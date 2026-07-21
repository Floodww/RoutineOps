package main

// Интеграционный тест: поднимает in-process gRPC-сервер с mTLS и прогоняет
// реальные компоненты агента (transport + heartbeat + command + inventory)
// против него — без сети и внешнего сервера. Эфемерные сертификаты генерируются
// в самом тесте.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/command"
	"github.com/Floodww/RoutineOps/internal/agent/heartbeat"
	"github.com/Floodww/RoutineOps/internal/agent/inventory"
	"github.com/Floodww/RoutineOps/internal/agent/outbox"
	"github.com/Floodww/RoutineOps/internal/agent/policy"
	"github.com/Floodww/RoutineOps/internal/agent/transport"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// --- тест-сервер ---

type capture struct {
	hbCh    chan *pb.HeartbeatRequest
	ackCh   chan string
	resCh   chan *pb.TaskResult
	invCh   chan *pb.InventoryReport
	secCh   chan *pb.SecurityEvent
	admCh   chan *pb.ReportAdminAccessRequest
	polCh   chan *pb.FetchPolicyRequest // захват FetchPolicy-запросов
	task    *pb.Task                    // отправляется агенту после первого heartbeat
	blocked bool                        // если true — Connect сразу отдаёт PermissionDenied

	secNotReceived bool  // если true — ReportSecurityEvent отвечает received=false (без gRPC-ошибки)
	secErr         error // если задан — ReportSecurityEvent отвечает этой gRPC-ошибкой (после захвата события)
	admErr         error // если задан — ReportAdminAccess отвечает этой gRPC-ошибкой (после захвата запроса)
}

type testServer struct {
	pb.UnimplementedAgentServiceServer
	c *capture
}

func send[T any](ch chan T, v T) {
	select {
	case ch <- v:
	default:
	}
}

func (s *testServer) Connect(stream grpc.BidiStreamingServer[pb.HeartbeatRequest, pb.Task]) error {
	if s.c.blocked {
		return status.Error(codes.PermissionDenied, "device is blocked")
	}
	sent := false
	for {
		hb, err := stream.Recv()
		if err != nil {
			return nil
		}
		send(s.c.hbCh, hb)
		if !sent && s.c.task != nil {
			sent = true
			_ = stream.Send(s.c.task)
		}
	}
}

func (s *testServer) AckTaskReceived(_ context.Context, in *pb.TaskReceivedAck) (*pb.TaskReceivedAckResponse, error) {
	send(s.c.ackCh, in.GetTaskId())
	return &pb.TaskReceivedAckResponse{Acknowledged: true}, nil
}

func (s *testServer) ReportTaskResult(_ context.Context, in *pb.TaskResult) (*pb.TaskResultAck, error) {
	send(s.c.resCh, in)
	return &pb.TaskResultAck{Received: true}, nil
}

func (s *testServer) ReportInventory(_ context.Context, in *pb.InventoryReport) (*pb.InventoryAck, error) {
	send(s.c.invCh, in)
	return &pb.InventoryAck{Received: true}, nil
}

func (s *testServer) ReportSecurityEvent(_ context.Context, in *pb.SecurityEvent) (*pb.SecurityEventAck, error) {
	send(s.c.secCh, in)
	if s.c.secErr != nil {
		return nil, s.c.secErr
	}
	return &pb.SecurityEventAck{Received: !s.c.secNotReceived}, nil
}

func (s *testServer) ReportAdminAccess(_ context.Context, in *pb.ReportAdminAccessRequest) (*pb.ReportAdminAccessResponse, error) {
	send(s.c.admCh, in)
	if s.c.admErr != nil {
		return nil, s.c.admErr
	}
	return &pb.ReportAdminAccessResponse{Received: true}, nil
}

func (s *testServer) FetchPolicy(_ context.Context, in *pb.FetchPolicyRequest) (*pb.FetchPolicyResponse, error) {
	send(s.c.polCh, in)
	return &pb.FetchPolicyResponse{
		Version: 1,
		Rules: []*pb.SoftwarePolicyRule{
			{RuleType: pb.PolicyRuleType_POLICY_RULE_TYPE_FORBIDDEN, SoftwareName: "evil.exe"},
			{RuleType: pb.PolicyRuleType_POLICY_RULE_TYPE_ALLOWED, SoftwareName: "ok.app"},
		},
	}, nil
}

// --- генерация эфемерных mTLS-сертификатов ---

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

func genCerts(t *testing.T, dir string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER)

	mk := func(name, cn string, serial int64, eku x509.ExtKeyUsage, dns []string, ips []net.IP) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
			DNSNames:     dns,
			IPAddresses:  ips,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		writePEM(t, filepath.Join(dir, name+".crt"), "CERTIFICATE", der)
		kder, _ := x509.MarshalPKCS8PrivateKey(k)
		writePEM(t, filepath.Join(dir, name+".key"), "PRIVATE KEY", kder)
	}
	mk("server", "localhost", 2, x509.ExtKeyUsageServerAuth, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	mk("agent", "test-device-001", 3, x509.ExtKeyUsageClientAuth, nil, nil)
}

func serverTLS(t *testing.T, dir string) credentials.TransportCredentials {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	})
}

// --- сам тест ---

func TestAgentEndToEnd(t *testing.T) {
	dir := t.TempDir()
	genCerts(t, dir)

	c := &capture{
		hbCh:  make(chan *pb.HeartbeatRequest, 8),
		ackCh: make(chan string, 4),
		resCh: make(chan *pb.TaskResult, 4),
		invCh: make(chan *pb.InventoryReport, 4),
		task:  &pb.Task{TaskId: "itest-1", ScriptContent: "echo integration-ok", Platform: "macOS"},
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(serverTLS(t, dir)))
	pb.RegisterAgentServiceServer(gs, &testServer{c: c})
	go gs.Serve(lis)
	defer gs.Stop()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := transport.FileCertProvider{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
	dialer, err := transport.NewDialer(lis.Addr().String(), "localhost", certs)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Боевая проводка результата задачи: executor → outbox (KindTask) →
	// dispatchReport → ReportTaskResult (как в runAgent), а не прямой unary.
	ob, err := outbox.New(filepath.Join(dir, "outbox"), 0, 200*time.Millisecond, log,
		func(ctx context.Context, kind string, data []byte) error {
			return dispatchReport(ctx, dialer, kind, data, log)
		})
	if err != nil {
		t.Fatal(err)
	}
	wg.Add(1)
	go func() { defer wg.Done(); ob.Run(ctx) }()

	executor := command.NewExecutor(dialer, log, "", ob.Enqueue)
	hb := &heartbeat.Heartbeater{
		Interval: 200 * time.Millisecond,
		IPFunc:   func() string { return "9.9.9.9" },
		OnTask:   executor.Submit,
		Log:      log,
	}
	client := transport.New(dialer, log)
	wg.Add(1)
	go func() { defer wg.Done(); _ = client.Run(ctx, hb.Session) }()

	reporter := &inventory.Reporter{Interval: time.Hour, Dialer: dialer, Log: log}
	wg.Add(1)
	go func() { defer wg.Done(); reporter.Run(ctx) }()

	// 1. heartbeat дошёл с правильным IP
	select {
	case got := <-c.hbCh:
		if got.GetIpAddress() != "9.9.9.9" {
			t.Errorf("heartbeat ip=%q want 9.9.9.9", got.GetIpAddress())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat не получен")
	}

	// 2. задача: сервер отправил Task → агент подтвердил доставку
	select {
	case id := <-c.ackCh:
		if id != "itest-1" {
			t.Errorf("ack task_id=%q want itest-1", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AckTaskReceived не получен")
	}

	// 3. задача выполнена → результат SUCCESS с выводом скрипта
	select {
	case res := <-c.resCh:
		if res.GetStatus() != pb.TaskStatus_TASK_STATUS_SUCCESS {
			t.Errorf("status=%v want SUCCESS, error_log=%q", res.GetStatus(), res.GetErrorLog())
		}
		if !strings.Contains(res.GetOutput(), "integration-ok") {
			t.Errorf("output=%q (ожидали 'integration-ok')", res.GetOutput())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReportTaskResult не получен")
	}

	// 4. инвентаризация дошла (после initialDelay ~3с)
	select {
	case inv := <-c.invCh:
		if inv.GetDeviceInfo().GetHostname() == "" {
			t.Error("inventory без hostname")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("ReportInventory не получен")
	}

	cancel()
	executor.Shutdown()
	wg.Wait()
}

// TestAgentPolicySyncEndToEnd прогоняет policy.Syncer против реального mTLS-сервера:
// FetchPolicy round-trip + запись локального кэша запрещённого ПО. Покрывает
// dialAndFetch (реальный dial+RPC), который не виден в юнит-тестах с подменой fetch.
func TestAgentPolicySyncEndToEnd(t *testing.T) {
	dir := t.TempDir()
	genCerts(t, dir)

	c := &capture{polCh: make(chan *pb.FetchPolicyRequest, 4)}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(serverTLS(t, dir)))
	pb.RegisterAgentServiceServer(gs, &testServer{c: c})
	go gs.Serve(lis)
	defer gs.Stop()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := transport.FileCertProvider{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
	dialer, err := transport.NewDialer(lis.Addr().String(), "localhost", certs)
	if err != nil {
		t.Fatal(err)
	}

	listFile := filepath.Join(dir, "forbidden.txt")
	syncer := &policy.Syncer{Interval: time.Hour, File: listFile, Dialer: dialer, Log: log}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { syncer.Run(ctx); close(done) }()

	// 1. FetchPolicy дошёл; known_version=0, т.к. локального кэша ещё нет.
	select {
	case req := <-c.polCh:
		if req.GetKnownVersion() != 0 {
			t.Errorf("known_version=%d, ожидалось 0 (нет кэша)", req.GetKnownVersion())
		}
	case <-time.After(6 * time.Second):
		t.Fatal("FetchPolicy не получен")
	}

	// 2. Кэш записан: только запрещённое ПО (evil.exe), без разрешённого (ok.app).
	deadline := time.After(4 * time.Second)
	for {
		data, _ := os.ReadFile(listFile)
		if strings.Contains(string(data), "evil.exe") {
			if strings.Contains(string(data), "ok.app") {
				t.Error("разрешённое ПО ok.app не должно попадать в список запрещённого")
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("кэш политики не записан в срок")
		case <-time.After(20 * time.Millisecond):
		}
	}

	cancel()
	<-done
}

// safeBuf — потокобезопасный буфер для логов (несколько горутин агента пишут).
type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestAgentBlockedBackoff: сервер отдаёт PermissionDenied (устройство заблокировано) —
// агент НЕ падает, логирует блокировку отдельно и уходит в (прерываемую) паузу.
func TestAgentBlockedBackoff(t *testing.T) {
	dir := t.TempDir()
	genCerts(t, dir)

	c := &capture{blocked: true}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(serverTLS(t, dir)))
	pb.RegisterAgentServiceServer(gs, &testServer{c: c})
	go gs.Serve(lis)
	defer gs.Stop()

	buf := &safeBuf{}
	log := slog.New(slog.NewTextHandler(buf, nil))
	certs := transport.FileCertProvider{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
	dialer, err := transport.NewDialer(lis.Addr().String(), "localhost", certs)
	if err != nil {
		t.Fatal(err)
	}

	hb := &heartbeat.Heartbeater{Interval: 100 * time.Millisecond, IPFunc: func() string { return "1.1.1.1" }, Log: log}
	client := transport.New(dialer, log)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx, hb.Session) }()

	// Ждём, пока агент распознает блокировку и залогирует её.
	deadline := time.After(8 * time.Second)
	for !strings.Contains(buf.String(), "заблокировано") {
		select {
		case <-deadline:
			cancel()
			t.Fatalf("агент не залогировал блокировку; лог:\n%s", buf.String())
		case <-time.After(100 * time.Millisecond):
		}
	}

	// Агент жив (в blockedRetry-паузе) — отмена должна корректно его завершить.
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("client.Run не завершился после cancel")
	}
}

// TestOutboxDeliversAfterOutage проверяет сквозной путь устойчивой очереди:
// отчёты, поставленные при недоступном сервере, не теряются и до-сылаются
// нужными RPC (ReportSecurityEvent / ReportAdminAccess) после восстановления связи.
func TestOutboxDeliversAfterOutage(t *testing.T) {
	dir := t.TempDir()
	genCerts(t, dir)

	// Резервируем адрес и сразу освобождаем — на этой фазе сервера нет.
	tmpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := tmpLis.Addr().String()
	tmpLis.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := transport.FileCertProvider{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
	dialer, err := transport.NewDialer(addr, "localhost", certs)
	if err != nil {
		t.Fatal(err)
	}

	ob, err := outbox.New(filepath.Join(dir, "outbox"), 0, time.Hour, log,
		func(ctx context.Context, kind string, data []byte) error {
			return dispatchReport(ctx, dialer, kind, data, log)
		})
	if err != nil {
		t.Fatal(err)
	}

	// Фаза 1: сервер недоступен — ставим алерт ИБ и админ-отчёт в очередь.
	secData, _ := proto.Marshal(&pb.SecurityEvent{
		AlertType: pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE, Details: "qbittorrent", OccurredAt: 1,
	})
	admData, _ := proto.Marshal(&pb.ReportAdminAccessRequest{
		RequestId: "req-1", Status: pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED, OccurredAt: 2,
	})
	if err := ob.Enqueue(outbox.KindSecurity, secData); err != nil {
		t.Fatal(err)
	}
	if err := ob.Enqueue(outbox.KindAdmin, admData); err != nil {
		t.Fatal(err)
	}

	ob.FlushOnce(context.Background()) // сервера нет — доставка должна провалиться
	if ob.Len() != 2 {
		t.Fatalf("при недоступном сервере записи должны остаться, got Len=%d", ob.Len())
	}

	// Фаза 2: поднимаем сервер на том же адресе и сливаем очередь.
	c := &capture{
		secCh: make(chan *pb.SecurityEvent, 2),
		admCh: make(chan *pb.ReportAdminAccessRequest, 2),
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("повторный listen на %s: %v", addr, err)
	}
	gs := grpc.NewServer(grpc.Creds(serverTLS(t, dir)))
	pb.RegisterAgentServiceServer(gs, &testServer{c: c})
	go gs.Serve(lis)
	defer gs.Stop()

	ob.FlushOnce(context.Background())

	select {
	case ev := <-c.secCh:
		if ev.GetDetails() != "qbittorrent" {
			t.Fatalf("неверный SecurityEvent: %q", ev.GetDetails())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SecurityEvent не доставлен после восстановления связи")
	}
	select {
	case r := <-c.admCh:
		if r.GetRequestId() != "req-1" || r.GetStatus() != pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED {
			t.Fatalf("неверный ReportAdminAccess: %+v", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReportAdminAccess не доставлен после восстановления связи")
	}

	if ob.Len() != 0 {
		t.Fatalf("очередь не очищена после доставки: Len=%d", ob.Len())
	}
}

// TestOutboxDeliversTaskResultAfterOutage: результат ad-hoc задачи, поставленный
// в очередь при недоступном сервере, не теряется и до-сылается ReportTaskResult
// после восстановления связи (агентская половина фикса «результат задачи не
// durable»; серверная — sweep зависших acked-задач).
func TestOutboxDeliversTaskResultAfterOutage(t *testing.T) {
	dir := t.TempDir()
	genCerts(t, dir)

	// Резервируем адрес и сразу освобождаем — на этой фазе сервера нет.
	tmpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := tmpLis.Addr().String()
	tmpLis.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := transport.FileCertProvider{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
	dialer, err := transport.NewDialer(addr, "localhost", certs)
	if err != nil {
		t.Fatal(err)
	}

	ob, err := outbox.New(filepath.Join(dir, "outbox"), 0, time.Hour, log,
		func(ctx context.Context, kind string, data []byte) error {
			return dispatchReport(ctx, dialer, kind, data, log)
		})
	if err != nil {
		t.Fatal(err)
	}

	resData, _ := proto.Marshal(&pb.TaskResult{
		TaskId: "task-42", Status: pb.TaskStatus_TASK_STATUS_SUCCESS, Output: "done",
	})
	if err := ob.Enqueue(outbox.KindTask, resData); err != nil {
		t.Fatal(err)
	}

	ob.FlushOnce(context.Background()) // сервера нет — доставка должна провалиться
	if ob.Len() != 1 {
		t.Fatalf("при недоступном сервере запись должна остаться, got Len=%d", ob.Len())
	}

	c := &capture{resCh: make(chan *pb.TaskResult, 1)}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("повторный listen на %s: %v", addr, err)
	}
	gs := grpc.NewServer(grpc.Creds(serverTLS(t, dir)))
	pb.RegisterAgentServiceServer(gs, &testServer{c: c})
	go gs.Serve(lis)
	defer gs.Stop()

	ob.FlushOnce(context.Background())

	select {
	case res := <-c.resCh:
		if res.GetTaskId() != "task-42" || res.GetStatus() != pb.TaskStatus_TASK_STATUS_SUCCESS {
			t.Fatalf("неверный TaskResult: %+v", res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TaskResult не доставлен после восстановления связи")
	}
	if ob.Len() != 0 {
		t.Fatalf("очередь не очищена после доставки: Len=%d", ob.Len())
	}
}

// TestOutboxKeepsEventOnNotReceived: сервер доступен, но отвечает received=false
// (напр. временная ошибка БД в gateway.ReportSecurityEvent) — событие НЕ должно
// считаться доставленным и удаляться из очереди. Регресс на silent-drop: раньше
// dispatchReport отбрасывал ack и возвращал nil → security-событие терялось молча.
func TestOutboxKeepsEventOnNotReceived(t *testing.T) {
	dir := t.TempDir()
	genCerts(t, dir)

	c := &capture{secCh: make(chan *pb.SecurityEvent, 4), secNotReceived: true}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(serverTLS(t, dir)))
	pb.RegisterAgentServiceServer(gs, &testServer{c: c})
	go gs.Serve(lis)
	defer gs.Stop()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := transport.FileCertProvider{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
	dialer, err := transport.NewDialer(lis.Addr().String(), "localhost", certs)
	if err != nil {
		t.Fatal(err)
	}
	ob, err := outbox.New(filepath.Join(dir, "outbox"), 0, time.Hour, log,
		func(ctx context.Context, kind string, data []byte) error {
			return dispatchReport(ctx, dialer, kind, data, log)
		})
	if err != nil {
		t.Fatal(err)
	}

	secData, _ := proto.Marshal(&pb.SecurityEvent{
		AlertType: pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE, Details: "qbittorrent", OccurredAt: 1,
	})
	if err := ob.Enqueue(outbox.KindSecurity, secData); err != nil {
		t.Fatal(err)
	}

	// Сервер ответил received=false — запись обязана остаться в очереди.
	ob.FlushOnce(context.Background())
	<-c.secCh // RPC реально дошёл до сервера
	if ob.Len() != 1 {
		t.Fatalf("событие потеряно при received=false (silent-drop): Len=%d, хотим 1", ob.Len())
	}

	// Сервер «выздоровел» (received=true) — запись доставлена и удалена.
	c.secNotReceived = false
	ob.FlushOnce(context.Background())
	<-c.secCh
	if ob.Len() != 0 {
		t.Fatalf("после received=true очередь должна очиститься: Len=%d", ob.Len())
	}
}

// TestOutboxDropsRecordOnTerminalServerError: сервер ответил терминальным
// gRPC-кодом на ReportAdminAccess. Транзиентный код (Unavailable) обязан
// сохранить запись для повтора, а терминальный (NotFound — заявки уже нет) —
// дропнуть: повтор бессмыслен, иначе запись навсегда заблокирует FIFO-очередь
// outbox (poison pill). Регресс на класс poison pill: раньше dispatchReport
// возвращал любую gRPC-ошибку как временный сбой и зацикливал доставку.
func TestOutboxDropsRecordOnTerminalServerError(t *testing.T) {
	dir := t.TempDir()
	genCerts(t, dir)

	c := &capture{admCh: make(chan *pb.ReportAdminAccessRequest, 4)}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(serverTLS(t, dir)))
	pb.RegisterAgentServiceServer(gs, &testServer{c: c})
	go gs.Serve(lis)
	defer gs.Stop()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := transport.FileCertProvider{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
	dialer, err := transport.NewDialer(lis.Addr().String(), "localhost", certs)
	if err != nil {
		t.Fatal(err)
	}
	ob, err := outbox.New(filepath.Join(dir, "outbox"), 0, time.Hour, log,
		func(ctx context.Context, kind string, data []byte) error {
			return dispatchReport(ctx, dialer, kind, data, log)
		})
	if err != nil {
		t.Fatal(err)
	}

	admData, _ := proto.Marshal(&pb.ReportAdminAccessRequest{
		RequestId: "req-gone", Status: pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED, OccurredAt: 1,
	})
	if err := ob.Enqueue(outbox.KindAdmin, admData); err != nil {
		t.Fatal(err)
	}

	// Транзиентный код → запись остаётся в очереди (повторим позже).
	c.admErr = status.Error(codes.Unavailable, "БД временно недоступна")
	ob.FlushOnce(context.Background())
	<-c.admCh // RPC реально дошёл до сервера
	if ob.Len() != 1 {
		t.Fatalf("транзиентный код (Unavailable) не должен дропать запись: Len=%d, хотим 1", ob.Len())
	}

	// Терминальный код → запись дропается, poison pill не блокирует очередь.
	c.admErr = status.Error(codes.NotFound, "заявка не найдена")
	ob.FlushOnce(context.Background())
	<-c.admCh
	if ob.Len() != 0 {
		t.Fatalf("терминальный код (NotFound) обязан дропнуть запись: Len=%d, хотим 0", ob.Len())
	}
}

// TestReportErrClassifiesCodes фиксирует полную таблицу классификации reportErr:
// терминальные коды (NotFound/InvalidArgument/FailedPrecondition) → дроп (nil),
// всё остальное (транзиенты, отмена, не-status ошибка) → повтор (исходная
// ошибка). Чистый unit-тест без gRPC: ловит любое сужение/расширение switch,
// в т.ч. коды, не покрытые интеграционными тестами.
func TestReportErrClassifiesCodes(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tests := []struct {
		name string
		err  error
		drop bool // true → ждём nil (дроп); false → ждём ту же ошибку (повтор)
	}{
		{"NotFound", status.Error(codes.NotFound, "gone"), true},
		{"InvalidArgument", status.Error(codes.InvalidArgument, "bad"), true},
		{"FailedPrecondition", status.Error(codes.FailedPrecondition, "precond"), true},
		{"Unavailable", status.Error(codes.Unavailable, "db down"), false},
		{"DeadlineExceeded", status.Error(codes.DeadlineExceeded, "slow"), false},
		{"Canceled", status.Error(codes.Canceled, "ctx cancel"), false},
		{"Unknown/plain", errors.New("plain transport drop"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reportErr(tt.err, outbox.KindSecurity, log)
			if tt.drop && got != nil {
				t.Fatalf("%s: ждали дроп (nil), получили %v", tt.name, got)
			}
			if !tt.drop && got == nil {
				t.Fatalf("%s: ждали повтор (ошибка), получили nil — молчаливый дроп!", tt.name)
			}
		})
	}
}

// TestOutboxDropsSecurityEventOnTerminalCode: KindSecurity — самый loss-sensitive
// вид записи, ради него outbox и существует, но его терминальный путь не был
// покрыт. Проверяем сквозь полный gRPC-стек: транзиентный код сохраняет
// ИБ-событие, а терминальный — дропает. Во второй фазе в очереди две записи и
// один flush: обе обязаны уйти на сервер — это прямо доказывает, что дроп
// poison-pill НЕ блокирует следующую запись в FIFO-очереди.
func TestOutboxDropsSecurityEventOnTerminalCode(t *testing.T) {
	dir := t.TempDir()
	genCerts(t, dir)

	c := &capture{secCh: make(chan *pb.SecurityEvent, 8)}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(serverTLS(t, dir)))
	pb.RegisterAgentServiceServer(gs, &testServer{c: c})
	go gs.Serve(lis)
	defer gs.Stop()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := transport.FileCertProvider{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
	dialer, err := transport.NewDialer(lis.Addr().String(), "localhost", certs)
	if err != nil {
		t.Fatal(err)
	}
	ob, err := outbox.New(filepath.Join(dir, "outbox"), 0, time.Hour, log,
		func(ctx context.Context, kind string, data []byte) error {
			return dispatchReport(ctx, dialer, kind, data, log)
		})
	if err != nil {
		t.Fatal(err)
	}

	mk := func(details string) []byte {
		b, _ := proto.Marshal(&pb.SecurityEvent{
			AlertType: pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE, Details: details, OccurredAt: 1,
		})
		return b
	}

	// Фаза 1: транзиентный код — ИБ-событие обязано остаться в очереди.
	c.secErr = status.Error(codes.Unavailable, "БД временно недоступна")
	if err := ob.Enqueue(outbox.KindSecurity, mk("evt-keep")); err != nil {
		t.Fatal(err)
	}
	ob.FlushOnce(context.Background())
	<-c.secCh // RPC реально дошёл до сервера
	if ob.Len() != 1 {
		t.Fatalf("транзиентный код не должен дропать ИБ-событие: Len=%d, хотим 1", ob.Len())
	}

	// Фаза 2: терминальный код для очереди из ДВУХ записей (удержанная +
	// новая). Один flush обязан обработать обе — дроп первой не должен
	// застопорить вторую (иначе poison pill блокирует FIFO-очередь).
	c.secErr = status.Error(codes.InvalidArgument, "невалидное событие")
	if err := ob.Enqueue(outbox.KindSecurity, mk("evt-poison")); err != nil {
		t.Fatal(err)
	}
	ob.FlushOnce(context.Background())
	for got := 0; got < 2; got++ {
		select {
		case <-c.secCh:
		case <-time.After(3 * time.Second):
			t.Fatalf("ждали 2 доставки на сервер за один flush, получили %d (очередь застопорилась на poison pill)", got)
		}
	}
	if ob.Len() != 0 {
		t.Fatalf("терминальный код обязан дропнуть обе записи: Len=%d, хотим 0", ob.Len())
	}
}

// TestAgentReconnectsAfterServerRestart: сервер перезапускается (редеплой/блип),
// пока агент работает — heartbeat-стрим должен сам переподключиться к серверу на
// том же адресе, без рестарта агента. Это ключевой полевой сценарий: перезапуск
// сервера не должен требовать ручного вмешательства на каждом устройстве.
func TestAgentReconnectsAfterServerRestart(t *testing.T) {
	dir := t.TempDir()
	genCerts(t, dir)

	lis1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis1.Addr().String()

	c1 := &capture{hbCh: make(chan *pb.HeartbeatRequest, 8)}
	gs1 := grpc.NewServer(grpc.Creds(serverTLS(t, dir)))
	pb.RegisterAgentServiceServer(gs1, &testServer{c: c1})
	go gs1.Serve(lis1)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	certs := transport.FileCertProvider{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	}
	dialer, err := transport.NewDialer(addr, "localhost", certs)
	if err != nil {
		t.Fatal(err)
	}

	hb := &heartbeat.Heartbeater{
		Interval: 200 * time.Millisecond,
		IPFunc:   func() string { return "1.1.1.1" },
		OnTask:   func(*pb.Task) {},
		Log:      log,
	}
	client := transport.New(dialer, log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = client.Run(ctx, hb.Session); close(done) }()

	// 1. Агент подключился к первому серверу.
	select {
	case <-c1.hbCh:
	case <-time.After(5 * time.Second):
		t.Fatal("первый heartbeat не получен")
	}

	// 2. Сервер падает.
	gs1.Stop()

	// 3. Поднимаем новый сервер на том же адресе (порт освобождён после Stop).
	var lis2 net.Listener
	for i := 0; i < 50; i++ {
		lis2, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lis2 == nil {
		t.Fatalf("повторный listen на %s: %v", addr, err)
	}
	c2 := &capture{hbCh: make(chan *pb.HeartbeatRequest, 8)}
	gs2 := grpc.NewServer(grpc.Creds(serverTLS(t, dir)))
	pb.RegisterAgentServiceServer(gs2, &testServer{c: c2})
	go gs2.Serve(lis2)
	defer gs2.Stop()

	// 4. Агент сам переподключился к перезапущенному серверу (backoff base=1s).
	select {
	case <-c2.hbCh:
	case <-time.After(15 * time.Second):
		t.Fatal("агент не переподключился к перезапущенному серверу")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("client.Run не завершился после cancel")
	}
}
