package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	pb "github.com/Floodww/RoutineOps/proto"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

// Эти тесты гоняют gateway через НАСТОЯЩИЙ mTLS-хендшейк (bufconn + grpc TLS),
// в отличие от gateway_test.go, где peer-cert подкладывается прямо в контекст.
// Конфиг сервера зеркалит прод (cmd/server/main.go): RequireAndVerifyClientCert
// + ClientCAs. Поэтому «без серта» и «серт от чужого CA» отбиваются на уровне
// TLS (RPC падает, до хендлера не доходит) — барьер держится на транспорте.

const serverSNI = "routineops-server"

// mtlsEnv — поднятый по bufconn gRPC-сервер с mTLS как в проде.
type mtlsEnv struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPool *x509.CertPool
	lis    *bufconn.Listener
}

// newCA генерирует самоподписанный ECDSA CA.
func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

// issueCert выписывает лист-сертификат, подписанный caCert/caKey. Возвращает
// готовый tls.Certificate и сырой DER (для вычисления fingerprint = sha256(Raw),
// ровно как это делает сервер в extractCertInfo).
func issueCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, server bool) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{serverSNI}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, der
}

func fingerprintOf(der []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(der))
}

// startMTLSServer поднимает gateway по bufconn с прод-конфигом mTLS.
func startMTLSServer(t *testing.T, gw pb.AgentServiceServer) *mtlsEnv {
	t.Helper()
	caCert, caKey, caPool := newCA(t)
	serverCert, _ := issueCert(t, caCert, caKey, serverSNI, true)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	})
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterAgentServiceServer(srv, gw)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return &mtlsEnv{caCert: caCert, caKey: caKey, caPool: caPool, lis: lis}
}

// dial подключается клиентом с указанным сертификатом (nil = без клиентского
// серта). Сервер верифицирует SNI против своего листа, клиент — против CA.
func (e *mtlsEnv) dial(t *testing.T, clientCert *tls.Certificate) pb.AgentServiceClient {
	t.Helper()
	var certs []tls.Certificate
	if clientCert != nil {
		certs = []tls.Certificate{*clientCert}
	}
	tlsCfg := &tls.Config{
		RootCAs:      e.caPool,
		ServerName:   serverSNI,
		Certificates: certs,
	}
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return e.lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewAgentServiceClient(conn)
}

// unaryCallers — все four unary-метода под покрытие, одинаковой сигнатурой
// (вызов с пустым запросом), чтобы прогнать mTLS-барьер табличной проверкой.
func unaryCallers() map[string]func(context.Context, pb.AgentServiceClient) error {
	return map[string]func(context.Context, pb.AgentServiceClient) error{
		"FetchPolicy": func(ctx context.Context, c pb.AgentServiceClient) error {
			_, err := c.FetchPolicy(ctx, &pb.FetchPolicyRequest{})
			return err
		},
		"FetchScriptPolicies": func(ctx context.Context, c pb.AgentServiceClient) error {
			_, err := c.FetchScriptPolicies(ctx, &pb.FetchScriptPoliciesRequest{})
			return err
		},
		"ReportSecurityEvent": func(ctx context.Context, c pb.AgentServiceClient) error {
			_, err := c.ReportSecurityEvent(ctx, &pb.SecurityEvent{})
			return err
		},
		"ReportScriptResult": func(ctx context.Context, c pb.AgentServiceClient) error {
			_, err := c.ReportScriptResult(ctx, &pb.ScriptResult{})
			return err
		},
	}
}

func callCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ── mTLS-барьер: без клиентского серта ────────────────────────────────────────

func TestMTLS_NoClientCert_Rejected(t *testing.T) {
	env := startMTLSServer(t, newGW(t, newDB(t)))
	client := env.dial(t, nil)

	for name, call := range unaryCallers() {
		t.Run(name, func(t *testing.T) {
			if err := call(callCtx(t), client); err == nil {
				t.Errorf("%s: ожидали отказ TLS-хендшейка без клиентского серта, получили nil", name)
			}
		})
	}
}

// ── mTLS-барьер: серт от чужого CA ────────────────────────────────────────────

func TestMTLS_WrongCA_Rejected(t *testing.T) {
	env := startMTLSServer(t, newGW(t, newDB(t)))

	// серт подписан ДРУГИМ, неизвестным серверу CA
	foreignCA, foreignKey, _ := newCA(t)
	foreignCert, _ := issueCert(t, foreignCA, foreignKey, "evil-device", false)
	client := env.dial(t, &foreignCert)

	for name, call := range unaryCallers() {
		t.Run(name, func(t *testing.T) {
			if err := call(callCtx(t), client); err == nil {
				t.Errorf("%s: ожидали отказ для серта от чужого CA, получили nil", name)
			}
		})
	}
}

// ── валидный серт нашего CA: хендшейк проходит, метод доступен (ADR-1) ─────────

// validClient выписывает клиентский серт от CA окружения, регистрирует устройство
// с его реальным fingerprint и возвращает клиента + cn + device UUID.
func (e *mtlsEnv) validClient(t *testing.T, db *storage.DB, cn string) (pb.AgentServiceClient, string) {
	t.Helper()
	cert, der := issueCert(t, e.caCert, e.caKey, cn, false)
	fp := fingerprintOf(der)
	registerDevice(t, db, cn, fp)
	deviceID, err := db.GetDeviceIDByFingerprint(context.Background(), fp)
	if err != nil || deviceID == "" {
		t.Fatalf("GetDeviceIDByFingerprint: id=%q err=%v", deviceID, err)
	}
	return e.dial(t, &cert), deviceID
}

func TestMTLS_FetchPolicy_HappyPath(t *testing.T) {
	db := newDB(t)
	env := startMTLSServer(t, newGW(t, db))
	client, deviceID := env.validClient(t, db, "device-mtls-policy")

	// device-specific правило (не глобальное — чтобы не задеть другие тесты на общей БД)
	if _, err := db.CreatePolicyRule(context.Background(), tenancy.DefaultTenantID, "BitTorrent", "forbidden", &deviceID, nil); err != nil {
		t.Fatalf("CreatePolicyRule: %v", err)
	}

	resp, err := client.FetchPolicy(callCtx(t), &pb.FetchPolicyRequest{})
	if err != nil {
		t.Fatalf("FetchPolicy через mTLS: %v", err)
	}
	var found bool
	for _, r := range resp.Rules {
		if r.SoftwareName == "BitTorrent" && r.RuleType == pb.PolicyRuleType_POLICY_RULE_TYPE_FORBIDDEN {
			found = true
		}
	}
	if !found {
		t.Fatalf("ожидали forbidden-правило BitTorrent, получили %+v", resp.Rules)
	}
	if resp.Version == 0 {
		t.Fatal("ожидали ненулевую version")
	}

	// повтор с той же version → Unchanged, без перечисления правил
	resp2, err := client.FetchPolicy(callCtx(t), &pb.FetchPolicyRequest{KnownVersion: resp.Version})
	if err != nil {
		t.Fatalf("FetchPolicy (known version): %v", err)
	}
	if !resp2.Unchanged {
		t.Errorf("ожидали Unchanged=true при совпадении version, получили %+v", resp2)
	}
}

func TestMTLS_FetchScriptPolicies_HappyPath(t *testing.T) {
	db := newDB(t)
	env := startMTLSServer(t, newGW(t, db))
	client, deviceID := env.validClient(t, db, "device-mtls-scripts")
	ctx := context.Background()

	// скрипт → политика(schedule) → группа → устройство в группе → политика группе
	script, err := db.CreateScript(ctx, tenancy.DefaultTenantID, "win-script", "Windows", "Write-Host hi")
	if err != nil {
		t.Fatalf("CreateScript: %v", err)
	}
	policy, err := db.CreateScriptPolicy(ctx, tenancy.DefaultTenantID, "win-policy", script.ID, "schedule",
		[]byte(`{"cron":"*/5 * * * *"}`), nil)
	if err != nil {
		t.Fatalf("CreateScriptPolicy: %v", err)
	}
	group, err := db.CreateDeviceGroup(ctx, tenancy.DefaultTenantID, "mtls-group", "", "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}
	if err := db.AddDeviceToGroup(ctx, tenancy.DefaultTenantID, deviceID, group.ID); err != nil {
		t.Fatalf("AddDeviceToGroup: %v", err)
	}
	if err := db.AssignPolicyToGroup(ctx, tenancy.DefaultTenantID, policy.ID, group.ID); err != nil {
		t.Fatalf("AssignPolicyToGroup: %v", err)
	}

	resp, err := client.FetchScriptPolicies(callCtx(t), &pb.FetchScriptPoliciesRequest{})
	if err != nil {
		t.Fatalf("FetchScriptPolicies через mTLS: %v", err)
	}
	if len(resp.Policies) != 1 {
		t.Fatalf("ожидали 1 политику, получили %d (%+v)", len(resp.Policies), resp.Policies)
	}
	p := resp.Policies[0]
	if p.PolicyId != policy.ID {
		t.Errorf("PolicyId = %q, want %q", p.PolicyId, policy.ID)
	}
	if p.Interpreter != "powershell" {
		t.Errorf("Interpreter = %q, want powershell (платформа Windows)", p.Interpreter)
	}
	if p.Trigger != pb.ScriptTrigger_SCRIPT_TRIGGER_SCHEDULE {
		t.Errorf("Trigger = %v, want SCHEDULE", p.Trigger)
	}
	if p.Cron != "*/5 * * * *" {
		t.Errorf("Cron = %q, want '*/5 * * * *'", p.Cron)
	}

	// повтор с той же version → Unchanged
	resp2, err := client.FetchScriptPolicies(callCtx(t), &pb.FetchScriptPoliciesRequest{KnownVersion: resp.Version})
	if err != nil {
		t.Fatalf("FetchScriptPolicies (known version): %v", err)
	}
	if !resp2.Unchanged {
		t.Errorf("ожидали Unchanged=true при совпадении version, получили %+v", resp2)
	}
}

func TestMTLS_ReportScriptResult_HappyPathAndDedup(t *testing.T) {
	db := newDB(t)
	env := startMTLSServer(t, newGW(t, db))
	client, deviceID := env.validClient(t, db, "device-mtls-result")
	ctx := context.Background()

	// нужен валидный policy_id (script_results.policy_id NOT NULL REFERENCES policies)
	script, err := db.CreateScript(ctx, tenancy.DefaultTenantID, "res-script", "linux", "echo hi")
	if err != nil {
		t.Fatalf("CreateScript: %v", err)
	}
	policy, err := db.CreateScriptPolicy(ctx, tenancy.DefaultTenantID, "res-policy", script.ID, "on_connect", nil, nil)
	if err != nil {
		t.Fatalf("CreateScriptPolicy: %v", err)
	}

	runID := "run-mtls-dedup-001"
	req := &pb.ScriptResult{
		PolicyId:   policy.ID,
		RunId:      runID,
		ExitCode:   0,
		Stdout:     "ok",
		Trigger:    pb.ScriptTrigger_SCRIPT_TRIGGER_ON_CONNECT,
		StartedAt:  time.Now().Unix(),
		FinishedAt: time.Now().Unix(),
	}

	// первый вызов → сохранение
	ack, err := client.ReportScriptResult(callCtx(t), req)
	if err != nil {
		t.Fatalf("ReportScriptResult #1: %v", err)
	}
	if !ack.Received {
		t.Fatal("первый вызов: ожидали Received=true")
	}

	// второй вызов с тем же run_id → дедуп (ON CONFLICT DO NOTHING, без ошибки)
	ack2, err := client.ReportScriptResult(callCtx(t), req)
	if err != nil {
		t.Fatalf("ReportScriptResult #2 (dedup): %v", err)
	}
	if !ack2.Received {
		t.Fatal("второй вызов: ожидали Received=true (дедуп без ошибки)")
	}

	if n := countScriptResults(t, runID); n != 1 {
		t.Errorf("ожидали ровно 1 строку для run_id=%s после дедупа, получили %d", runID, n)
	}
	_ = deviceID
}

func TestMTLS_ReportSecurityEvent_HappyPath(t *testing.T) {
	db := newDB(t)
	env := startMTLSServer(t, newGW(t, db))
	client, _ := env.validClient(t, db, "device-mtls-sec")

	ack, err := client.ReportSecurityEvent(callCtx(t), &pb.SecurityEvent{
		AlertType: pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE,
		Details:   "BitTorrent 7.10",
	})
	if err != nil {
		t.Fatalf("ReportSecurityEvent через mTLS: %v", err)
	}
	if !ack.Received {
		t.Error("ожидали Received=true для зарегистрированного устройства")
	}
}

// countScriptResults считает строки script_results по run_id (прямой SQL,
// публичного API для этого нет).
func countScriptResults(t *testing.T, runID string) int {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), sharedDSN)
	if err != nil {
		t.Fatalf("countScriptResults pool: %v", err)
	}
	defer pool.Close()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM script_results WHERE run_id = $1`, runID).Scan(&n); err != nil {
		t.Fatalf("countScriptResults: %v", err)
	}
	return n
}
