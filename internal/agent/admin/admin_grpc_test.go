package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/transport"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// adminStub — минимальный AgentService для проверки клиентских вызовов admin.
type adminStub struct {
	pb.UnimplementedAgentServiceServer
	reqResp   *pb.RequestAdminAccessResponse
	reqErr    error
	fetchResp *pb.FetchAdminStatusResponse
}

func (s *adminStub) RequestAdminAccess(context.Context, *pb.RequestAdminAccessRequest) (*pb.RequestAdminAccessResponse, error) {
	return s.reqResp, s.reqErr
}

func (s *adminStub) FetchAdminStatus(context.Context, *pb.FetchAdminStatusRequest) (*pb.FetchAdminStatusResponse, error) {
	if s.fetchResp == nil {
		return &pb.FetchAdminStatusResponse{}, nil
	}
	return s.fetchResp, nil
}

func (s *adminStub) ReportAdminAccess(context.Context, *pb.ReportAdminAccessRequest) (*pb.ReportAdminAccessResponse, error) {
	return &pb.ReportAdminAccessResponse{}, nil
}

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

// genCerts создаёт CA + серверный (SAN localhost) и клиентский серты в dir.
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

// startServer поднимает mTLS gRPC-сервер со stub и возвращает Dialer к нему.
func startServer(t *testing.T, stub pb.AgentServiceServer) *transport.Dialer {
	t.Helper()
	dir := t.TempDir()
	genCerts(t, dir)

	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterAgentServiceServer(gs, stub)
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)

	dialer, err := transport.NewDialer(lis.Addr().String(), "localhost", transport.FileCertProvider{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return dialer
}

// RequestAdmin успешно отправляет заявку через настоящий mTLS-стрим.
func TestRequestAdminOverGRPC(t *testing.T) {
	dialer := startServer(t, &adminStub{
		reqResp: &pb.RequestAdminAccessResponse{
			RequestId: "req-1",
			Status:    pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_PENDING,
		},
	})
	if err := RequestAdmin(context.Background(), dialer, "нужны права для установки ПО", quietLog()); err != nil {
		t.Fatalf("RequestAdmin вернул ошибку: %v", err)
	}
}

// RequestAdmin пробрасывает ошибку сервера.
func TestRequestAdminServerError(t *testing.T) {
	dialer := startServer(t, &adminStub{reqErr: status.Error(codes.Internal, "сервер сломался")})
	if err := RequestAdmin(context.Background(), dialer, "повод", quietLog()); err == nil {
		t.Fatal("ожидали ошибку при отказе сервера")
	}
}

// NewManager.poll через настоящий dialer тянет FetchAdminStatus и выдаёт права
// (dry-run, без мутации системы) на одобренную заявку.
func TestManagerPollOverGRPC(t *testing.T) {
	dialer := startServer(t, &adminStub{
		fetchResp: &pb.FetchAdminStatusResponse{
			RequestId: "approved-1",
			Status:    pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	})
	enqueued := 0
	m := NewManager(dialer, func(string, []byte) error { enqueued++; return nil }, time.Minute, quietLog(), true, nil)
	m.consoleUser = func() (string, bool) { return "alice", true } // детерминированный пользователь

	m.poll(context.Background())

	if m.grantedUser != "alice" || m.lastReqID != "approved-1" {
		t.Fatalf("ожидали выдачу alice по approved-1, got user=%q req=%q", m.grantedUser, m.lastReqID)
	}
	if enqueued == 0 {
		t.Fatal("ожидали отчёт о выдаче в outbox")
	}
}
