package notifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDialTLSParallel_PicksLiveAmongDead: среди «мёртвых» (не маршрутизируемых) адресов
// dialTLSParallel находит IP с рабочим TLS — эмуляция блокировки Telegram по IP, где
// открыт лишь один адрес.
func TestDialTLSParallel_PicksLiveAmongDead(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String()) // 127.0.0.1:PORT
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	cfg := &tls.Config{ServerName: host, RootCAs: pool}

	// 192.0.2.0/24 (TEST-NET-1, RFC 5737) не маршрутизируется → эмулирует заблокированный IP.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialTLSParallel(ctx, "tcp", cfg, []string{"192.0.2.1", "192.0.2.2", host}, port)
	if err != nil {
		t.Fatalf("ждали живое TLS-соединение, получили ошибку: %v", err)
	}
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok || !tc.ConnectionState().HandshakeComplete {
		t.Fatalf("ждали завершённое TLS-соединение, получили %T", conn)
	}
}

// TestDialTLSParallel_AllDeadReturnsError: если живых нет — ошибка, а не зависание.
func TestDialTLSParallel_AllDeadReturnsError(t *testing.T) {
	cfg := &tls.Config{ServerName: telegramHost}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialTLSParallel(ctx, "tcp", cfg, []string{"192.0.2.1", "192.0.2.2"}, "443")
	if err == nil {
		conn.Close()
		t.Fatal("ждали ошибку при всех мёртвых адресах, получили соединение")
	}
}
