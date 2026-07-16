package notifier

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

const telegramHost = "api.telegram.org"

// telegramFallbackIPs — известные IP, обслуживающие api.telegram.org, ПОМИМО того,
// что отдаёт DNS. В РФ и подобных сетях «официальный» IP из DNS (напр. 149.154.166.110)
// заблокирован, причём это отдаёт и системный DNS, и DoH-резолверы (1.1.1.1/8.8.8.8) —
// то есть это не DNS-подмена, а блок по IP; а ДРУГОЙ IP того же api.telegram.org
// (149.154.167.220) открыт, но в DNS его нет. Поэтому дозваниваемся ещё и по этому
// списку. Все кандидаты проходят полное TLS-рукопожатие с проверкой сертификата
// api.telegram.org, так что устаревший/чужой IP просто НЕ пройдёт проверку и будет
// отброшен — вредным список быть не может, максимум бесполезным. При ПОЛНОЙ блокировке
// (закрыты все IP) спасает только HTTPS_PROXY (см. telegramHTTPClient).
var telegramFallbackIPs = []string{
	"149.154.167.220",
	"149.154.167.221",
	"149.154.167.222",
	"149.154.175.50",
	"149.154.175.100",
	"149.154.171.5",
	"91.108.56.130",
}

// telegramHTTPClient — HTTP-клиент Bot API, устойчивый к блокировке api.telegram.org
// по IP (актуально для РФ). Через DialTLSContext дозванивается по всем кандидат-IP
// параллельно и берёт первое соединение с успешным TLS-рукопожатием — так бот находит
// живой IP Telegram «из коробки», без ручной настройки у нового пользователя.
//
// DialTLSContext работает только для ПРЯМЫХ https-запросов. Если задан HTTPS_PROXY,
// транспорт идёт через прокси (наш дозвон не применяется) — прокси остаётся аварийным
// путём при полной блокировке. Базовый http.ProxyFromEnvironment сохранён (клон
// DefaultTransport).
func telegramHTTPClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialTLSContext = dialTLSFastest
	return &http.Client{Timeout: timeout, Transport: tr}
}

// dialTLSFastest собирает кандидат-IP хоста (DNS ∪ запасные для Telegram) и
// дозванивается TLS-ом по всем сразу, возвращая первое соединение с прошедшим
// рукопожатием. Гонка именно по TLS, а не по TCP: часть заблокированных IP принимает
// SYN, но глушит данные — TCP-only дозвон выбрал бы такой «живой на TCP, мёртвый на
// TLS» IP и завис бы в ожидании ответа.
func dialTLSFastest(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var ips []string
	add := func(ip string) {
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			ips = append(ips, ip)
		}
	}
	if resolved, e := net.DefaultResolver.LookupIPAddr(ctx, host); e == nil {
		for _, r := range resolved {
			add(r.IP.String())
		}
	}
	if host == telegramHost {
		for _, ip := range telegramFallbackIPs {
			add(ip)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("telegram dial: не удалось получить ни одного IP для %s", host)
	}

	cfg := &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}}
	return dialTLSParallel(ctx, network, cfg, ips, port)
}

// dialTLSParallel дозванивается TLS-ом по всем ips:port параллельно; побеждает первое
// соединение с завершённым рукопожатием, остальные дозвоны отменяются, их поздние
// успехи закрываются в фоне (иначе утекли бы сокеты). Если живых нет — первая ошибка.
func dialTLSParallel(ctx context.Context, network string, cfg *tls.Config, ips []string, port string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, len(ips)) // буфер = гоурутины не блокируются на отправке
	for _, ip := range ips {
		go func(target string) {
			var d net.Dialer
			raw, e := d.DialContext(ctx, network, target)
			if e != nil {
				ch <- result{nil, e}
				return
			}
			tconn := tls.Client(raw, cfg) // cfg только читается — безопасно шарить
			if e := tconn.HandshakeContext(ctx); e != nil {
				raw.Close()
				ch <- result{nil, e}
				return
			}
			ch <- result{tconn, nil}
		}(net.JoinHostPort(ip, port))
	}

	var firstErr error
	for i := 0; i < len(ips); i++ {
		r := <-ch
		if r.err == nil {
			cancel()
			if rest := len(ips) - i - 1; rest > 0 {
				go func() {
					for j := 0; j < rest; j++ {
						if rr := <-ch; rr.conn != nil {
							rr.conn.Close()
						}
					}
				}()
			}
			return r.conn, nil
		}
		if firstErr == nil {
			firstErr = r.err
		}
	}
	cancel()
	return nil, firstErr
}
