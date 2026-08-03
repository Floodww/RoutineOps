package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testCA — самоподписанный CA, который «подписывает» CSR агента в фейк-сервере.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	return newTestCALasting(t, time.Hour)
}

// newTestCALasting — CA с заданным сроком жизни. Прод-CA живёт годами, и там, где
// проверка смотрит на момент выдачи leaf, часовой тестовый CA даёт ложное падение.
func newTestCALasting(t *testing.T, lifetime time.Duration) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		// БЕЗ бэкдейта — ровно как прод-CA от `openssl req -x509` (scripts/gen-certs.sh).
		// Раньше фикстура бэкдейтила CA на час, и потому не пересекала границу, на
		// которой ломается прод: сервер бэкдейтит leaf на минуту, и проверка цепочки,
		// привязанная ко времени, отвергала валидный энроллмент против свежего CA.
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(lifetime),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// signCSR подписывает публичный ключ из CSR, проставляя CN=device_id (как сервер).
func (ca *testCA) signCSR(t *testing.T, csrPEM string, deviceID string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("CSR не PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("подпись CSR невалидна: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: deviceID}, // сервер ставит CN сам (ADR-1)
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestEnrollHappyPath(t *testing.T) {
	ca := newTestCA(t)
	const wantToken = "tok-123"
	const wantDevID = "ed7433b7-aaaa"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p enrollPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if p.EnrollmentToken != wantToken {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		if p.Hostname == "" || p.OS == "" || p.Arch == "" {
			http.Error(w, "no meta", 400)
			return
		}
		certPEM := ca.signCSR(t, p.CSRPem, wantDevID)
		json.NewEncoder(w).Encode(enrollResponse{
			DeviceID: wantDevID,
			CertPem:  string(certPEM),
			CAPem:    string(ca.pem),
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	req := Request{
		EnrollURL:  srv.URL,
		Token:      wantToken,
		CertOut:    filepath.Join(dir, "agent.crt"),
		KeyOut:     filepath.Join(dir, "agent.key"),
		CAOut:      filepath.Join(dir, "ca.crt"),
		Hostname:   "mac.local",
		OS:         "macOS",
		Arch:       "arm64",
		HTTPClient: srv.Client(),
	}
	devID, err := Run(context.Background(), req, discardLog())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if devID != wantDevID {
		t.Fatalf("device_id=%q, want %q", devID, wantDevID)
	}

	// Файлы разложены, ключ парный к серту → tls.LoadX509KeyPair проходит.
	if _, err := os.Stat(req.CertOut); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(req.KeyOut)
	if err != nil {
		t.Fatal(err)
	}
	// Режим файла проверяем только там, где он что-то значит. На Windows Go
	// отображает в Mode() лишь флаг read-only, а реальный доступ определяет ACL,
	// унаследованный от каталога, — 0600 там не выполняется и выполниться не
	// может. Красный тест на этом месте сообщал бы не о дефекте раскладки, а о
	// том, что unix-права проверяют на не-unix.
	//
	// Чем ключ защищён на Windows — вопрос НЕ этого теста и на сегодня открытый:
	// при cert-source=file (значение по умолчанию) ключ остаётся файлом в
	// каталоге установки, а прав на него не ставит ни .wxs, ни агент (admin-only
	// DACL от EnsureDataDir накрывает только ProgramData\RoutineOps\state).
	// Проверять это надо на живой машине, а не режимом файла в юнит-тесте.
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != 0o600 {
			t.Errorf("права ключа = %v, want 0600", info.Mode().Perm())
		}
	}
	if _, err := tls.LoadX509KeyPair(req.CertOut, req.KeyOut); err != nil {
		t.Fatalf("серт и ключ не парные: %v", err)
	}
}

func TestEnrollRejectsServerError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "токен использован", http.StatusUnauthorized)
	}))
	defer srv.Close()

	dir := t.TempDir()
	_, err := Run(context.Background(), Request{
		EnrollURL:  srv.URL,
		Token:      "x",
		CertOut:    filepath.Join(dir, "agent.crt"),
		KeyOut:     filepath.Join(dir, "agent.key"),
		CAOut:      filepath.Join(dir, "ca.crt"),
		HTTPClient: srv.Client(),
	}, discardLog())
	if err == nil {
		t.Fatal("ожидали ошибку на 401")
	}
	// При ошибке файлы НЕ должны появиться (ключ не утёк на диск).
	if _, statErr := os.Stat(filepath.Join(dir, "agent.key")); statErr == nil {
		t.Fatal("ключ не должен записываться при неуспешном энроллменте")
	}
}

func TestEnrollRejectsForeignCert(t *testing.T) {
	ca := newTestCA(t)
	// Сервер возвращает серт под ЧУЖОЙ ключ (не наш CSR) — должно отвергнуться.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "dev"},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &other.PublicKey, ca.key)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		json.NewEncoder(w).Encode(enrollResponse{DeviceID: "dev", CertPem: string(certPEM), CAPem: string(ca.pem)})
	}))
	defer srv.Close()

	dir := t.TempDir()
	_, err := Run(context.Background(), Request{
		EnrollURL:  srv.URL,
		Token:      "x",
		CertOut:    filepath.Join(dir, "agent.crt"),
		KeyOut:     filepath.Join(dir, "agent.key"),
		CAOut:      filepath.Join(dir, "ca.crt"),
		HTTPClient: srv.Client(),
	}, discardLog())
	if err == nil {
		t.Fatal("ожидали отказ: серт не соответствует нашему ключу")
	}
}

func TestLoadCABundleRequiresSource(t *testing.T) {
	// Ни файла, ни URL — отказ: нечем пинить enroll-эндпоинт.
	if _, err := loadCABundle("", "", ""); err == nil {
		t.Fatal("ожидали ошибку без -ca и -ca-url")
	}
	// Несуществующий файл без URL — тоже отказ.
	if _, err := loadCABundle(filepath.Join(t.TempDir(), "нет.crt"), "", ""); err == nil {
		t.Fatal("ожидали ошибку: файла нет и URL не задан")
	}
}

func TestPinnedClientRejectsGarbage(t *testing.T) {
	if _, err := pinnedClient([]byte("не PEM")); err == nil {
		t.Fatal("ожидали ошибку: в бандле нет валидных сертификатов")
	}
}

// TestLoadCABundleFromURL: если файла -ca нет, бандл скачивается с -ca-url —
// но только с пин-хешем (SEC-1: TOFU-скачивание без пина небезопасно, см. ниже).
func TestLoadCABundleFromURL(t *testing.T) {
	ca := newTestCA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ca.pem)
	}))
	defer srv.Close()

	sum := sha256.Sum256(ca.pem)
	pin := hex.EncodeToString(sum[:])

	got, err := loadCABundle(filepath.Join(t.TempDir(), "нет.crt"), srv.URL, pin)
	if err != nil {
		t.Fatalf("loadCABundle по URL: %v", err)
	}
	if string(got) != string(ca.pem) {
		t.Fatal("скачанный CA-бандл не совпал с отданным сервером")
	}
	if _, err := pinnedClient(got); err != nil {
		t.Fatalf("pinnedClient на скачанном бандле: %v", err)
	}
}

// TestLoadCABundleFromURLRequiresPin — регрессия SEC-1 (аудит 2026-07-01): TOFU-
// скачивание CA по -ca-url БЕЗ -ca-sha256 должно отказывать, а не молча доверять
// первому ответившему серверу (MITM в момент установки иначе подсунул бы свой CA).
func TestLoadCABundleFromURLRequiresPin(t *testing.T) {
	ca := newTestCA(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ca.pem)
	}))
	defer srv.Close()

	if _, err := loadCABundle(filepath.Join(t.TempDir(), "нет.crt"), srv.URL, ""); err == nil {
		t.Fatal("ожидали отказ: -ca-url без -ca-sha256 небезопасен (TOFU)")
	}
}

// TestLoadCABundlePrefersFile: если файл -ca есть, по сети не ходим (URL игнорируется).
func TestLoadCABundlePrefersFile(t *testing.T) {
	ca := newTestCA(t)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, ca.pem, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadCABundle(caFile, "http://127.0.0.1:0/недоступно", "")
	if err != nil {
		t.Fatalf("loadCABundle из файла: %v", err)
	}
	if string(got) != string(ca.pem) {
		t.Fatal("прочитанный из файла CA-бандл не совпал")
	}
}

// TestEnrollValidatesArgs: пустые url/token отклоняются до любого сетевого вызова.
func TestEnrollValidatesArgs(t *testing.T) {
	if _, err := Run(context.Background(), Request{Token: "x"}, discardLog()); err == nil {
		t.Fatal("ожидали ошибку без enroll-url")
	}
	if _, err := Run(context.Background(), Request{EnrollURL: "https://h/enroll"}, discardLog()); err == nil {
		t.Fatal("ожидали ошибку без токена")
	}
}

// TestEnrollRejectsMalformedJSON: 200, но тело не JSON → ошибка разбора, ключ не пишется.
func TestEnrollRejectsMalformedJSON(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{не json")
	}))
	defer srv.Close()

	dir := t.TempDir()
	_, err := Run(context.Background(), Request{
		EnrollURL:  srv.URL,
		Token:      "x",
		CertOut:    filepath.Join(dir, "agent.crt"),
		KeyOut:     filepath.Join(dir, "agent.key"),
		CAOut:      filepath.Join(dir, "ca.crt"),
		HTTPClient: srv.Client(),
	}, discardLog())
	if err == nil {
		t.Fatal("ожидали ошибку разбора ответа")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "agent.key")); statErr == nil {
		t.Fatal("ключ не должен записываться при битом ответе")
	}
}

// TestEnrollRejectsIncompleteResponse: 200 с пропущенным ca_pem → ошибка, без раскладки.
func TestEnrollRejectsIncompleteResponse(t *testing.T) {
	ca := newTestCA(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p enrollPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		certPEM := ca.signCSR(t, p.CSRPem, "dev-1")
		// CAPem намеренно пуст.
		json.NewEncoder(w).Encode(enrollResponse{DeviceID: "dev-1", CertPem: string(certPEM)})
	}))
	defer srv.Close()

	dir := t.TempDir()
	_, err := Run(context.Background(), Request{
		EnrollURL:  srv.URL,
		Token:      "x",
		CertOut:    filepath.Join(dir, "agent.crt"),
		KeyOut:     filepath.Join(dir, "agent.key"),
		CAOut:      filepath.Join(dir, "ca.crt"),
		HTTPClient: srv.Client(),
	}, discardLog())
	if err == nil {
		t.Fatal("ожидали ошибку на неполный ответ (нет ca_pem)")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "agent.key")); statErr == nil {
		t.Fatal("ключ не должен записываться при неполном ответе")
	}
}

// TestEnrollRejectsLeafFromForeignCA — живой сценарий рассинхрона CA на сервере: leaf
// выписан СТАРЫМ CA, а ca_pem в ответе уже НОВЫЙ. По отдельности оба артефакта валидны
// (leaf под наш ключ, CA цел), поэтому раньше связка молча оседала на диске, enroll
// рапортовал успех, а служба потом вечно падала на mTLS-хендшейке. Прогоняем через
// полный Run с фейк-сервером — ровно ту границу, где баг и живёт.
func TestEnrollRejectsLeafFromForeignCA(t *testing.T) {
	signingCA := newTestCA(t)    // им подписан leaf
	advertisedCA := newTestCA(t) // а этот отдан агенту как корень доверия
	const wantToken = "tok-123"
	const wantDevID = "ed7433b7-bbbb"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p enrollPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		certPEM := signingCA.signCSR(t, p.CSRPem, wantDevID)
		json.NewEncoder(w).Encode(enrollResponse{
			DeviceID: wantDevID,
			CertPem:  string(certPEM),
			CAPem:    string(advertisedCA.pem), // рассинхрон
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	req := Request{
		EnrollURL:  srv.URL,
		Token:      wantToken,
		CertOut:    filepath.Join(dir, "agent.crt"),
		KeyOut:     filepath.Join(dir, "agent.key"),
		CAOut:      filepath.Join(dir, "ca.crt"),
		Hostname:   "mac.local",
		OS:         "macOS",
		Arch:       "arm64",
		HTTPClient: srv.Client(),
	}
	if _, err := Run(context.Background(), req, discardLog()); err == nil {
		t.Fatal("enroll принял leaf от чужого CA — mTLS не поднимется, а отказ будет молчаливым")
	}

	// Отказ обязан быть ДО записи: иначе на диске остаётся битая идентичность, и хуже —
	// CAOut == CAFile, т.е. чужой CA стал бы пином для следующего запуска.
	for _, p := range []string{req.CertOut, req.KeyOut, req.CAOut} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("после отказа на диске остался файл %q (err=%v)", filepath.Base(p), err)
		}
	}
}

// TestEnrollAcceptsBackwardClockSkew — контрольный к предыдущему: часы устройства съехали
// НАЗАД (севший CMOS, откат снапшота VM), поэтому свежий leaf выглядит «ещё не
// действительным». Проверка цепочки НЕ должна на этом валить валидный энроллмент —
// иначе повторим регресс идемпотентности v22 (форс полного enroll погашенным токеном
// → 401 → установка падает). Сервер здесь честный, разъезда CA нет.
func TestEnrollAcceptsBackwardClockSkew(t *testing.T) {
	ca := newTestCALasting(t, 10*365*24*time.Hour) // прод-CA живёт годами, не час
	const wantToken = "tok-123"
	const wantDevID = "ed7433b7-cccc"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p enrollPayload
		json.NewDecoder(r.Body).Decode(&p)
		block, _ := pem.Decode([]byte(p.CSRPem))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		// Серт «из будущего» с точки зрения устройства: его часы отстают на сутки.
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(7),
			Subject:      pkix.Name{CommonName: wantDevID},
			NotBefore:    time.Now().Add(24 * time.Hour),
			NotAfter:     time.Now().Add(48 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
		if err != nil {
			t.Fatal(err)
		}
		json.NewEncoder(w).Encode(enrollResponse{
			DeviceID: wantDevID,
			CertPem:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			CAPem:    string(ca.pem),
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	req := Request{
		EnrollURL:  srv.URL,
		Token:      wantToken,
		CertOut:    filepath.Join(dir, "agent.crt"),
		KeyOut:     filepath.Join(dir, "agent.key"),
		CAOut:      filepath.Join(dir, "ca.crt"),
		Hostname:   "mac.local",
		OS:         "macOS",
		Arch:       "arm64",
		HTTPClient: srv.Client(),
	}
	if _, err := Run(context.Background(), req, discardLog()); err != nil {
		t.Fatalf("валидный энроллмент завален из-за съехавших часов: %v", err)
	}
}

// TestEnrollAgainstFreshlyCreatedCA — CA родился только что (возраст ~0), как при
// `install.sh` (gen-certs.sh → сразу энроллмент), в e2e/демо-стендах и при ротации CA,
// когда флот переэнролливается немедленно. Сервер при этом бэкдейтит leaf на минуту
// (internal/server/enroll/signer.go), так что leaf.NotBefore оказывается РАНЬШЕ
// CA.NotBefore. Проверка цепочки не должна принимать это за «рассинхрон CA»: серт
// подписан именно этим CA, и энроллмент обязан пройти.
func TestEnrollAgainstFreshlyCreatedCA(t *testing.T) {
	ca := newTestCA(t) // NotBefore = сейчас, без бэкдейта — как openssl
	const wantDevID = "ed7433b7-dddd"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p enrollPayload
		json.NewDecoder(r.Body).Decode(&p)
		block, _ := pem.Decode([]byte(p.CSRPem))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		// Бэкдейт leaf на минуту — 1-в-1 как signer.go.
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(9),
			Subject:      pkix.Name{CommonName: wantDevID},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
		if err != nil {
			t.Fatal(err)
		}
		json.NewEncoder(w).Encode(enrollResponse{
			DeviceID: wantDevID,
			CertPem:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			CAPem:    string(ca.pem),
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	req := Request{
		EnrollURL: srv.URL, Token: "tok-123",
		CertOut:  filepath.Join(dir, "agent.crt"),
		KeyOut:   filepath.Join(dir, "agent.key"),
		CAOut:    filepath.Join(dir, "ca.crt"),
		Hostname: "mac.local", OS: "macOS", Arch: "arm64",
		HTTPClient: srv.Client(),
	}
	if _, err := Run(context.Background(), req, discardLog()); err != nil {
		t.Fatalf("энроллмент против свежесозданного CA завален: %v", err)
	}
}
