package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Лента событий безопасности.
//
// События приходят от агента по mTLS и опознаются исключительно по сертификату (ADR-1),
// поэтому наполнить ленту «снаружи» нельзя: нужен ключ конкретного устройства. Отсюда
// требование хранить выданные пары — без них демо-устройство умеет ровно то, что успело
// сделать в момент заведения, и лента остаётся пустой.

// eventTemplate — заготовка события. occurredAgo задаёт, насколько давно оно случилось:
// лента, где всё произошло в одну минуту, читается как сбой, а не как история.
type eventTemplate struct {
	Type        pb.AlertType
	Details     string
	OccurredAgo time.Duration
}

// eventScript — что «происходило» на устройствах.
//
// Набор подобран так, чтобы лента показывала разные типы и разную давность, а не десять
// одинаковых строк. Тексты — из словаря, которым пользуется сам агент: запрещённое ПО
// называется именем из политики, изменение настроек — конкретным параметром.
func eventScript() []eventTemplate {
	return []eventTemplate{
		{pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE, "uTorrent 3.6.0", 35 * time.Minute},
		{pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE, "TeamViewer 15.58.4", 3 * time.Hour},
		{pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE, "AnyDesk 8.1.0", 9 * time.Hour},
		{pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE, "BitTorrent 7.11.0", 26 * time.Hour},
		{pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE, "Tor Browser 14.0.1", 50 * time.Hour},

		{pb.AlertType_ALERT_TYPE_UNAUTHORIZED_INSTALL, "Установлено вне политики: Notepad++ 8.7.1", 90 * time.Minute},
		{pb.AlertType_ALERT_TYPE_UNAUTHORIZED_INSTALL, "Установлено вне политики: WinRAR 7.01", 6 * time.Hour},
		{pb.AlertType_ALERT_TYPE_UNAUTHORIZED_INSTALL, "Установлено вне политики: Advanced IP Scanner 2.5", 20 * time.Hour},
		{pb.AlertType_ALERT_TYPE_UNAUTHORIZED_INSTALL, "Установлено вне политики: PuTTY 0.81", 44 * time.Hour},

		{pb.AlertType_ALERT_TYPE_UNAUTHORIZED_SETTINGS_CHANGE, "Отключён брандмауэр Windows (профиль «Домен»)", 55 * time.Minute},
		{pb.AlertType_ALERT_TYPE_UNAUTHORIZED_SETTINGS_CHANGE, "Отключено шифрование системного тома", 4 * time.Hour},
		{pb.AlertType_ALERT_TYPE_UNAUTHORIZED_SETTINGS_CHANGE, "Изменены настройки автозапуска служб", 14 * time.Hour},
		{pb.AlertType_ALERT_TYPE_UNAUTHORIZED_SETTINGS_CHANGE, "Отключено автоматическое обновление ОС", 32 * time.Hour},
		{pb.AlertType_ALERT_TYPE_UNAUTHORIZED_SETTINGS_CHANGE, "Отключена защита в реальном времени", 70 * time.Hour},
	}
}

// certPath/keyPath — где лежит пара устройства.
func certPath(dir, host string) string { return filepath.Join(dir, host+".crt") }
func keyPath(dir, host string) string  { return filepath.Join(dir, host+".key") }

func saveCert(dir, host string, certPEM, keyPEM []byte) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(certPath(dir, host), certPEM, 0o600); err != nil {
		return err
	}
	// Ключ устройства — секрет: 0600 и никакого мира. Каталог тоже 0700.
	return os.WriteFile(keyPath(dir, host), keyPEM, 0o600)
}

// emitEvents рассылает события от имени устройств, чьи пары сохранены в dir.
//
// perDevice задаёт, сколько событий приходится на одно устройство; 0 — устройство
// пропускается. Ровная раскладка «по одному на каждого» дала бы ленту, в которой ни одна
// машина не выделяется, — а смысл ленты как раз в том, чтобы проблемные были видны.
func emitEvents(grpcAddr, dir string, hosts []string, plan map[string]int) (int, error) {
	script := eventScript()
	sent := 0
	// Обход по СПИСКУ, а не по map: порядок обхода map в Go случаен, и повторный прогон
	// разложил бы события иначе — воспроизводимость важнее одной строчки кода.
	for hi, host := range hosts {
		n := plan[host]
		if n <= 0 {
			continue
		}
		crt, err := os.ReadFile(certPath(dir, host))
		if err != nil {
			return sent, fmt.Errorf("сертификат %s: %w", host, err)
		}
		key, err := os.ReadFile(keyPath(dir, host))
		if err != nil {
			return sent, fmt.Errorf("ключ %s: %w", host, err)
		}
		pair, err := tls.X509KeyPair(crt, key)
		if err != nil {
			return sent, fmt.Errorf("пара %s: %w", host, err)
		}

		cfg := &tls.Config{Certificates: []tls.Certificate{pair}, InsecureSkipVerify: true} //nolint:gosec
		conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
		if err != nil {
			return sent, err
		}
		cl := pb.NewAgentServiceClient(conn)

		for i := 0; i < n; i++ {
			// Шаги 5 и 3 взаимно просты с длиной сценария (14), поэтому события
			// расходятся по всем типам. Первая версия брала смещением len(host) — и
			// провалилась ровно потому, что имена машин длиной 9–13 символов легли в
			// один и тот же хвост сценария: в ленте не оказалось ни одной установки
			// вне политики. Формула, которая «выглядит разбросанной», разбросанной быть
			// не обязана.
			t := script[(hi*5+i*3)%len(script)]
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			_, err := cl.ReportSecurityEvent(ctx, &pb.SecurityEvent{
				AlertType:  t.Type,
				Details:    t.Details,
				OccurredAt: time.Now().Add(-t.OccurredAgo).Unix(),
			})
			cancel()
			if err != nil {
				_ = conn.Close()
				return sent, fmt.Errorf("%s: %w", host, err)
			}
			sent++
		}
		_ = conn.Close()
	}
	return sent, nil
}

// eventPlan решает, сколько событий получит каждое устройство.
//
// Раскладка неровная намеренно: пара «проблемных» машин, у которых событий много, длинный
// хвост с одним-двумя и заметная часть парка вообще без событий. Так лента отвечает на
// вопрос «куда смотреть», ради которого её и открывают.
func eventPlan(hosts []string) map[string]int {
	plan := map[string]int{}
	for i, h := range hosts {
		switch {
		case strings.HasPrefix(h, "NB-SALES-07"):
			plan[h] = 5 // машина-нарушитель из демо-набора
		case strings.HasPrefix(h, "SRV-"):
			plan[h] = 0 // на серверах пользователь ничего не ставит
		case i%3 == 0:
			plan[h] = 2
		case i%3 == 1:
			plan[h] = 1
		default:
			plan[h] = 0
		}
	}
	return plan
}
