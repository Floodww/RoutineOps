package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/outbox"
	"github.com/Floodww/RoutineOps/internal/agent/transport"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// evidenceRig — очередь агента, подключённая к живому mTLS-серверу через тот же
// dispatchReport, которым пользуется боевой агент.
func evidenceRig(t *testing.T, c *capture) (*outbox.Queue, func()) {
	t.Helper()
	dir := t.TempDir()
	genCerts(t, dir)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(serverTLS(t, dir)))
	pb.RegisterAgentServiceServer(gs, &testServer{c: c})
	go gs.Serve(lis)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dialer, err := transport.NewDialer(lis.Addr().String(), "localhost", transport.FileCertProvider{
		CertFile: filepath.Join(dir, "agent.crt"),
		KeyFile:  filepath.Join(dir, "agent.key"),
		CAFile:   filepath.Join(dir, "ca.crt"),
	})
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
	return ob, gs.Stop
}

// Окно улик из очереди доезжает до своего RPC, а не до чужого и не в никуда.
//
// Вид записи — единственное, что связывает содержимое с вызовом: диспетчер
// выбирает RPC по нему. Незнакомый вид отбрасывается молча (иначе FIFO встаёт
// навсегда), поэтому пропущенная ветка выглядела бы как «улики собираются, но
// на сервере их нет» — без единой ошибки в логе.
func TestOutboxDeliversAdminSessionWindow(t *testing.T) {
	c := &capture{evdCh: make(chan *pb.ReportAdminSessionChangesRequest, 4)}
	ob, stop := evidenceRig(t, c)
	defer stop()

	data, err := proto.Marshal(&pb.ReportAdminSessionChangesRequest{
		RequestId:    "req-7",
		WindowSeq:    3,
		Final:        true,
		TotalChanges: 1,
		Completeness: pb.EvidenceCompleteness_EVIDENCE_COMPLETENESS_COMPLETE,
		Changes: []*pb.AdminSessionChange{{
			Kind:        pb.AdminChangeKind_ADMIN_CHANGE_KIND_SOFTWARE_INSTALLED,
			Subject:     "Some App",
			Attribution: pb.ChangeAttribution_CHANGE_ATTRIBUTION_HUMAN_LIKELY,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ob.Enqueue(outbox.KindAdminChanges, data); err != nil {
		t.Fatal(err)
	}

	ob.FlushOnce(context.Background())

	select {
	case got := <-c.evdCh:
		if got.GetRequestId() != "req-7" || got.GetWindowSeq() != 3 || !got.GetFinal() {
			t.Fatalf("сервер получил искажённое окно: %+v", got)
		}
		if len(got.GetChanges()) != 1 || got.GetChanges()[0].GetSubject() != "Some App" {
			t.Fatalf("дельта не доехала: %+v", got.GetChanges())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("окно улик не доставлено")
	}
	if ob.Len() != 0 {
		t.Fatalf("доставленное окно осталось в очереди: Len=%d", ob.Len())
	}
}

// Битое окно отбрасывается и не запирает очередь.
//
// Очередь FIFO и общая: запись, которую нельзя разобрать, при возврате ошибки
// осталась бы первой навсегда и заблокировала бы за собой ИБ-алерты и статусы
// лока (класс poison pill).
func TestOutboxDropsCorruptedAdminSessionWindow(t *testing.T) {
	c := &capture{evdCh: make(chan *pb.ReportAdminSessionChangesRequest, 4)}
	ob, stop := evidenceRig(t, c)
	defer stop()

	if err := ob.Enqueue(outbox.KindAdminChanges, []byte{0xff, 0xff, 0xff}); err != nil {
		t.Fatal(err)
	}
	ob.FlushOnce(context.Background())

	if ob.Len() != 0 {
		t.Fatalf("битое окно осталось в очереди и держит FIFO: Len=%d", ob.Len())
	}
	select {
	case got := <-c.evdCh:
		t.Fatalf("битые данные ушли на сервер: %+v", got)
	default:
	}
}

// Сервер, не знающий этого RPC, окно НЕ уничтожает.
//
// Unimplemented — не терминальный код: он означает «сервер ещё не обновлён», и
// дропать улики по нему нельзя. Сбор гейтится флагом самого сервера, поэтому
// реально запись появляется только там, где принимать её уже умеют; этот тест
// держит границу на случай отката сервера назад.
func TestOutboxKeepsWindowWhenServerTooOld(t *testing.T) {
	c := &capture{
		evdCh:  make(chan *pb.ReportAdminSessionChangesRequest, 4),
		evdErr: status.Error(codes.Unimplemented, "method not implemented"),
	}
	ob, stop := evidenceRig(t, c)
	defer stop()

	data, _ := proto.Marshal(&pb.ReportAdminSessionChangesRequest{RequestId: "req-8", Final: true})
	if err := ob.Enqueue(outbox.KindAdminChanges, data); err != nil {
		t.Fatal(err)
	}
	ob.FlushOnce(context.Background())
	<-c.evdCh // вызов реально дошёл до сервера

	if ob.Len() != 1 {
		t.Fatalf("окно потеряно на старом сервере: Len=%d, хотим 1", ob.Len())
	}

	// Сервер обновился — та же запись доезжает без вмешательства.
	c.evdErr = nil
	ob.FlushOnce(context.Background())
	<-c.evdCh
	if ob.Len() != 0 {
		t.Fatalf("после апгрейда сервера очередь должна очиститься: Len=%d", ob.Len())
	}
}
