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
	"io"
	"log/slog"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/gateway"
	"github.com/Floodww/RoutineOps/internal/server/registry"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/testutil"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

var sharedDSN string

func TestMain(m *testing.M) {
	dsn, cleanup := testutil.NewDSNWithCleanup()
	sharedDSN = dsn
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func newDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Connect(context.Background(), sharedDSN)
	if err != nil {
		t.Fatalf("storage.Connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

type MockNotifier struct {
	mu       sync.Mutex
	Messages []string
	notified chan struct{}
}

func (m *MockNotifier) NotifyITAdmins(ctx context.Context, text string) {
	m.mu.Lock()
	m.Messages = append(m.Messages, text)
	m.mu.Unlock()
	if m.notified != nil {
		m.notified <- struct{}{}
	}
}

func newMockNotifier() *MockNotifier {
	return &MockNotifier{notified: make(chan struct{}, 4)}
}

func newGWWithBot(t *testing.T, db *storage.DB, bot gateway.Notifier) *gateway.Gateway {
	t.Helper()
	reg := registry.New()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return gateway.New(db, reg, nil, logger, bot)
}

func newGW(t *testing.T, db *storage.DB) *gateway.Gateway {
	t.Helper()
	return newGWWithBot(t, db, &MockNotifier{})
}

// makeCertCtx generates a self-signed ECDSA cert with the given CN and returns a
// gRPC peer-injected context plus the certificate fingerprint.
// ADR-1: this is the only valid path for device_id to enter the system.
func makeCertCtx(t *testing.T, cn string) (context.Context, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(certDER))
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		},
	}
	return peer.NewContext(context.Background(), p), fingerprint
}

// uniqEmail возвращает уникальный email, чтобы тесты были идемпотентны под
// -count>1 (общая БД переживает прогоны, а users.email — UNIQUE).
func uniqEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@test.com", prefix, time.Now().UnixNano())
}

// registerDevice inserts a device via heartbeat upsert (simulates post-enrollment state).
func registerDevice(t *testing.T, db *storage.DB, cn, fingerprint string) {
	t.Helper()
	err := db.UpsertDeviceHeartbeat(context.Background(), storage.HeartbeatData{
		CertFingerprint: fingerprint,
		DeviceID:        cn,
		CertCN:          cn,
		IPAddress:       "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("registerDevice: %v", err)
	}
}

// mockStream implements grpc.BidiStreamingServer[pb.HeartbeatRequest, pb.Task].
type mockStream struct {
	ctx       context.Context
	msgs      []*pb.HeartbeatRequest
	pos       int
	Sent      []*pb.Task
	RecvErr   error
	SendErr   error
	BlockRecv chan struct{}
	RecvHook  func()
}

func (m *mockStream) Context() context.Context { return m.ctx }

func (m *mockStream) Recv() (*pb.HeartbeatRequest, error) {
	if m.RecvHook != nil {
		m.RecvHook()
	}
	if m.pos >= len(m.msgs) {
		if m.RecvErr != nil {
			return nil, m.RecvErr
		}
		if m.BlockRecv != nil {
			<-m.BlockRecv
		}
		return nil, io.EOF
	}
	msg := m.msgs[m.pos]
	m.pos++
	return msg, nil
}

func (m *mockStream) Send(t *pb.Task) error {
	if m.SendErr != nil {
		return m.SendErr
	}
	m.Sent = append(m.Sent, t)
	return nil
}
func (m *mockStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockStream) SendHeader(metadata.MD) error { return nil }
func (m *mockStream) SetTrailer(metadata.MD)       {}
func (m *mockStream) SendMsg(any) error            { return nil }
func (m *mockStream) RecvMsg(any) error            { return nil }
