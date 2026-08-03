// Команда seeddev — разовая наливка ДЕМОНСТРАЦИОННЫХ устройств в инсталляцию.
//
// Не для продакшена и не для парка: инструмент заводит устройства, за которыми нет машин.
// Нужен ровно для одного — чтобы скриншоты продукта показывали парк, а не пустой список.
//
// Почему через настоящий протокол, а не INSERT в базу: устройство в этой системе — это не
// строка, а следствие цепочки (заготовка → выданный сертификат → хартбит → инвентарь).
// Строка, вписанная мимо цепочки, разойдётся с ней в мелочах, которые видно как раз на
// скриншотах: пустой отпечаток серта, статус, не совпадающий с last_seen, инвентарь без
// устройства. Поэтому здесь пройден весь путь агента, только источник данных о «железе» —
// таблица ниже, а не реальная машина.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sort"
	"strings"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type spec struct {
	Hostname string
	OS       string
	OSVer    string
	CPU      string
	RAMMB    int64
	Disk     string
	DiskFree string
	IP       string
	MAC      string
	Serial   string
	Arch     string
	User     string
	Crypt    string // disk_encryption: enabled/disabled
	Patch    string // ISO-дата последнего обновления ОС
	Domain   string
	TPM      string
	Secure   string
	Group    string // имя группы устройств; пусто = не привязывать
	Owner    string // e-mail владельца из каталога; пусто = не привязывать
	Soft     []*pb.SoftwareItem
}

func main() {
	base := flag.String("base", "https://localhost:18443", "адрес REST API")
	grpcAddr := flag.String("grpc", "localhost:18051", "адрес gRPC-шлюза")
	email := flag.String("email", "", "оператор")
	pass := flag.String("pass", "", "пароль оператора")
	agentVer := flag.String("agent-version", "v2.5.9", "версия агента в карточке")
	dry := flag.Bool("dry", false, "показать план и выйти")
	certDir := flag.String("certs", "", "каталог для выданных пар ключ/сертификат (нужен для -events)")
	events := flag.Bool("events", false, "разослать события безопасности от уже заведённых устройств")
	reconnect := flag.Bool("reconnect", false, "переподключить устройства: хартбит + инвентарь (обновляет «последний раз на связи»)")
	flag.Parse()

	devices := append(fleet(), bulkFleet()...)
	if *dry {
		for _, d := range devices {
			fmt.Printf("  %-22s %-12s %-10s %s\n", d.Hostname, d.OS, d.Arch, d.Group)
		}
		fmt.Printf("итого %d устройств\n", len(devices))
		return
	}
	if *email == "" || *pass == "" {
		fmt.Fprintln(os.Stderr, "нужны -email и -pass")
		os.Exit(2)
	}
	c := &client{base: *base, agentVer: *agentVer, grpcAddr: *grpcAddr, certDir: *certDir}
	if err := c.init(*email, *pass); err != nil {
		fmt.Fprintf(os.Stderr, "вход: %v\n", err)
		os.Exit(1)
	}

	if *reconnect {
		if *certDir == "" {
			fmt.Fprintln(os.Stderr, "-reconnect требует -certs")
			os.Exit(2)
		}
		ok, failed := 0, 0
		for _, d := range devices {
			crt, err := os.ReadFile(certPath(*certDir, d.Hostname))
			if err != nil {
				continue // пары нет — устройство заводили не мы
			}
			key, err := os.ReadFile(keyPath(*certDir, d.Hostname))
			if err != nil {
				continue
			}
			pair, err := tls.X509KeyPair(crt, key)
			if err != nil {
				fmt.Printf("  ✗ %-22s пара: %v\n", d.Hostname, err)
				failed++
				continue
			}
			if err := c.report(d, pair); err != nil {
				fmt.Printf("  ✗ %-22s %v\n", d.Hostname, err)
				failed++
				continue
			}
			ok++
		}
		fmt.Printf("переподключено %d, ошибок %d\n", ok, failed)
		if failed > 0 {
			os.Exit(1)
		}
		return
	}
	if *events {
		if *certDir == "" {
			fmt.Fprintln(os.Stderr, "-events требует -certs: без ключа устройства событие отправить нельзя")
			os.Exit(2)
		}
		hosts := make([]string, 0, len(devices))
		for _, d := range devices {
			if _, err := os.Stat(certPath(*certDir, d.Hostname)); err == nil {
				hosts = append(hosts, d.Hostname)
			}
		}
		if len(hosts) == 0 {
			fmt.Fprintf(os.Stderr, "в %s нет ни одной сохранённой пары\n", *certDir)
			os.Exit(1)
		}
		sort.Strings(hosts)
		n, err := emitEvents(*grpcAddr, *certDir, hosts, eventPlan(hosts))
		if err != nil {
			fmt.Fprintf(os.Stderr, "отправлено %d, затем ошибка: %v\n", n, err)
			os.Exit(1)
		}
		fmt.Printf("отправлено событий: %d с %d устройств\n", n, len(hosts))
		return
	}

	if err := c.issueBulkToken(); err != nil {
		fmt.Fprintf(os.Stderr, "bulk-токен: %v\n", err)
		os.Exit(1)
	}
	groups, err := c.groupIndex()
	if err != nil {
		fmt.Fprintf(os.Stderr, "группы: %v\n", err)
		os.Exit(1)
	}
	owners, err := c.personIndex()
	if err != nil {
		fmt.Fprintf(os.Stderr, "каталог: %v\n", err)
		os.Exit(1)
	}
	// Идемпотентность по имени машины. Bulk-энролл на каждый вызов заводит НОВОЕ
	// устройство — без этой проверки повторный прогон удваивает парк, что и случилось
	// на первом же повторе.
	existing, err := c.hostnames()
	if err != nil {
		fmt.Fprintf(os.Stderr, "список парка: %v\n", err)
		os.Exit(1)
	}

	ok, failed, skipped := 0, 0, 0
	for _, d := range devices {
		if existing[d.Hostname] {
			fmt.Printf("  = %-22s уже есть, пропускаю\n", d.Hostname)
			skipped++
			continue
		}
		if err := c.seed(d, groups, owners); err != nil {
			fmt.Printf("  ✗ %-22s %v\n", d.Hostname, err)
			failed++
			continue
		}
		fmt.Printf("  ✓ %-22s %s %s\n", d.Hostname, d.OS, d.OSVer)
		ok++
	}
	fmt.Printf("\nзаведено %d, пропущено %d, ошибок %d\n", ok, skipped, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

type client struct {
	base      string
	grpcAddr  string
	agentVer  string
	certDir   string
	bulkToken string
	http      *http.Client
}

// issueBulkToken выпускает один многоразовый токен на весь прогон.
//
// require_approval=false намеренно: очередь одобрения — правильное умолчание для боевой
// раскатки, но здесь она означала бы, что все двенадцать машин повиснут в pending_approval
// и в парке их не будет. Для демо-наливки одобрять некого и нечего.
func (c *client) issueBulkToken() error {
	no := false
	var out struct {
		Token string `json:"enrollment_token"`
	}
	if err := c.do("POST", "/enrollment-tokens/bulk", map[string]any{
		"require_approval": &no,
		"ttl_hours":        2,
	}, &out); err != nil {
		return err
	}
	if out.Token == "" {
		return fmt.Errorf("сервер не вернул токен")
	}
	c.bulkToken = out.Token
	return nil
}

func (c *client) init(email, pass string) error {
	jar, _ := cookiejar.New(nil)
	c.http = &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		// Туннель отдаёт сертификат, выписанный на внутреннее имя сервера, а ходим мы
		// на localhost — проверка имени тут не значит ничего и только мешает. Канал и
		// так внутри ssh-туннеля.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	body, _ := json.Marshal(map[string]string{"email": email, "password": pass})
	resp, err := c.http.Post(c.base+"/api/v1/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *client) do(method, path string, in any, out any) error {
	return c.doRaw(method, "/api/v1"+path, in, out)
}

// doRaw — для роутов, зарегистрированных ПОЛНЫМ путём, а не внутри группы /api/v1
// (enroll, installer, agent/version): у них префикс уже в самом пути, и дописывать его
// второй раз значит получить 404 на ровном месте.
func (c *client) doRaw(method, path string, in any, out any) error {
	var rdr io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw))[:min(160, len(strings.TrimSpace(string(raw))))])
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// hostnames — имена машин, уже заведённых в этом тенанте.
//
// Обязательно СТРАНИЦАМИ. Список устройств отдаёт 50 записей, если не просить больше
// (storage.DefaultPageLimit), и запрос без параметров молча возвращает первую страницу —
// а выглядит как полный ответ. На этом я уже наступил живьём: сверил полный отчёт
// соответствия с усечённым списком, посчитал недостающее устройство «мусором» и удалил
// НАСТОЯЩУЮ машину. Здесь та же слепота стоила бы дублей всего, что не попало на первую
// страницу.
func (c *client) hostnames() (map[string]bool, error) {
	const page = 500 // storage.MaxPageLimit
	m := map[string]bool{}
	for offset := 0; ; offset += page {
		var list []struct {
			Hostname string `json:"hostname"`
		}
		if err := c.do("GET", fmt.Sprintf("/devices?limit=%d&offset=%d", page, offset), nil, &list); err != nil {
			return nil, err
		}
		for _, d := range list {
			m[d.Hostname] = true
		}
		if len(list) < page {
			return m, nil
		}
	}
}

func (c *client) groupIndex() (map[string]string, error) {
	var list []struct{ ID, Name string }
	if err := c.do("GET", "/device-groups", nil, &list); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, g := range list {
		m[g.Name] = g.ID
	}
	return m, nil
}

func (c *client) personIndex() (map[string]string, error) {
	var list []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := c.do("GET", "/directory/persons", nil, &list); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, p := range list {
		m[p.Email] = p.ID
	}
	return m, nil
}

// seed проводит одно устройство по всему пути: заготовка → сертификат → хартбит →
// инвентарь → группа и владелец.
func (c *client) seed(d spec, groups, owners map[string]string) error {
	// Идём bulk-токеном, а НЕ парой «заготовка + одноразовый токен».
	//
	// Не по вкусу: одноразовый путь на этой инсталляции отвечает 500. Причина видна в
	// коде — enroll по токену, привязанному к устройству, зовёт EnrollDevice с голым
	// r.Context(), без тенанта, тогда как bulk-ветка передаёт tok.TenantID явно. Под
	// ролью без BYPASSRLS запрос без привязанного тенанта не проходит по построению.
	// Bulk — это заодно и настоящий сценарий массовой раскатки.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: d.Hostname}}, key)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	var enrolled struct {
		DeviceID string `json:"device_id"`
		CertPem  string `json:"cert_pem"`
		CAPem    string `json:"ca_pem"`
	}
	if err := c.doRaw("POST", "/api/v1/enroll", map[string]string{
		"enrollment_token": c.bulkToken,
		"csr_pem":          string(csrPEM),
		"hostname":         d.Hostname,
		"os":               d.OS,
		"arch":             d.Arch,
	}, &enrolled); err != nil {
		return fmt.Errorf("энролл: %w", err)
	}
	deviceID := enrolled.DeviceID

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair([]byte(enrolled.CertPem), keyPEM)
	if err != nil {
		return fmt.Errorf("пара ключ/серт: %w", err)
	}
	// Пару сохраняем СРАЗУ: события безопасности опознаются только по сертификату
	// (ADR-1), и потерянный ключ означает устройство, которое больше ничего не расскажет.
	if err := saveCert(c.certDir, d.Hostname, []byte(enrolled.CertPem), keyPEM); err != nil {
		return fmt.Errorf("сохранение пары: %w", err)
	}

	if err := c.report(d, pair); err != nil {
		return fmt.Errorf("отчёт по gRPC: %w", err)
	}

	// Ошибки привязки НЕ глушим. Устройство без группы и владельца выглядит на скриншоте
	// ровно так же, как устройство, которое молча не привязалось, — и разницу видно
	// только глазами по всему списку.
	if d.Group != "" {
		id, ok := groups[d.Group]
		if !ok {
			return fmt.Errorf("группа %q не найдена в этой инсталляции", d.Group)
		}
		if err := c.do("POST", "/device-groups/"+id+"/members", map[string]string{"device_id": deviceID}, nil); err != nil {
			return fmt.Errorf("привязка к группе: %w", err)
		}
	}
	if d.Owner != "" {
		id, ok := owners[d.Owner]
		if !ok {
			return fmt.Errorf("карточка %q не найдена в каталоге", d.Owner)
		}
		if err := c.do("PUT", "/devices/"+deviceID+"/owner", map[string]string{"person_id": id}, nil); err != nil {
			return fmt.Errorf("привязка владельца: %w", err)
		}
	}
	return nil
}

// report открывает mTLS-соединение выданным сертификатом, шлёт один хартбит (он и
// переводит устройство из «зарегистрировано» в «на связи») и один инвентарь.
func (c *client) report(d spec, pair tls.Certificate) error {
	// Серверный сертификат выписан на внутреннее имя, а идём через туннель на localhost.
	// Проверять имя здесь нечем и незачем; клиентский серт — настоящий, его сервер
	// проверяет по-честному, и именно он определяет, чьё это устройство (ADR-1).
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, InsecureSkipVerify: true} //nolint:gosec
	conn, err := grpc.NewClient(c.grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return err
	}
	defer conn.Close()

	cl := pb.NewAgentServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	stream, err := cl.Connect(ctx)
	if err != nil {
		return fmt.Errorf("открытие стрима Connect: %w", err)
	}
	if err := stream.Send(&pb.HeartbeatRequest{IpAddress: d.IP, Timestamp: time.Now().Unix()}); err != nil {
		return fmt.Errorf("хартбит: %w", err)
	}
	// Сервер обрабатывает хартбит асинхронно; закрываем отправку и даём ему долететь.
	_ = stream.CloseSend()
	time.Sleep(700 * time.Millisecond)

	// Список ПО передаётся указателями: protobuf-сообщения содержат мьютекс во
	// внутреннем состоянии, и копирование их по значению — не стиль, а ошибка (govet
	// copylocks её и ловит).
	soft := d.Soft
	_, err = cl.ReportInventory(ctx, &pb.InventoryReport{
		DeviceInfo: &pb.DeviceInfo{
			Hostname: d.Hostname, Os: d.OS, OsVersion: d.OSVer,
			Cpu: d.CPU, Ram: d.RAMMB, Disk: d.Disk, IpAddress: d.IP,
			MacAddress: d.MAC, SerialNumber: d.Serial, AgentVersion: c.agentVer,
			Arch: d.Arch, ConsoleUser: d.User, DiskEncryption: d.Crypt,
			OsPatchDate: d.Patch, BootTime: time.Now().Add(-time.Duration(36) * time.Hour).Unix(),
			DiskFree: d.DiskFree, DomainJoined: d.Domain, Tpm: d.TPM, SecureBoot: d.Secure,
		},
		Software: soft,
	})
	if err != nil {
		return fmt.Errorf("ReportInventory: %w", err)
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
