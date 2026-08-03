package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/outbox"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/protobuf/proto"
)

// windowStub — сервер, считающий приёмы окон улик.
type windowStub struct {
	adminStub
	got      []*pb.ReportAdminSessionChangesRequest
	received bool
	err      error
}

func (s *windowStub) ReportAdminSessionChanges(_ context.Context, req *pb.ReportAdminSessionChangesRequest) (*pb.ReportAdminSessionChangesResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.got = append(s.got, req)
	return &pb.ReportAdminSessionChangesResponse{Received: s.received}, nil
}

// Штатный путь: окно уходит в устойчивую очередь под своим видом, а не мимо неё.
//
// Вид записи несёт КЛАСС ВЫТЕСНЕНИЯ (admin_changes — вытесняемый): ошибка здесь
// означала бы, что улики конкурируют с ИБ-алертами за место в очереди наравне.
func TestSendWindowEnqueuesUnderOwnKind(t *testing.T) {
	stub := &windowStub{received: true}
	dialer := startServer(t, stub)

	var kinds []string
	var payload []byte
	send := windowSender(dialer, func(kind string, data []byte) error {
		kinds = append(kinds, kind)
		payload = data
		return nil
	})

	w := fullWindow()
	if err := send(context.Background(), w); err != nil {
		t.Fatalf("отправка окна: %v", err)
	}
	if len(kinds) != 1 || kinds[0] != outbox.KindAdminChanges {
		t.Fatalf("ожидали одну запись вида %q, got %v", outbox.KindAdminChanges, kinds)
	}
	var req pb.ReportAdminSessionChangesRequest
	if err := proto.Unmarshal(payload, &req); err != nil {
		t.Fatalf("в очередь легло не окно улик: %v", err)
	}
	if req.GetRequestId() != w.RequestID || req.GetWindowSeq() != w.Seq || !req.GetFinal() {
		t.Fatalf("окно доехало искажённым: %+v", &req)
	}
	if len(stub.got) != 0 {
		t.Fatalf("очередь приняла запись, но окно ушло ещё и напрямую (%d вызовов)", len(stub.got))
	}
}

// Промежуточное окно, не принятое очередью, НЕ идёт напрямую.
//
// Очередь отказывает ровно тогда, когда забита защищёнными видами, то есть
// когда с доставкой и так плохо. Промежуточное окно в этот момент не несёт
// ничего срочного: окна кумулятивны от t0, и следующее содержит всё, что было в
// непринятом. Сетевой вызов здесь только добавил бы нагрузки на живом обрыве.
func TestSendWindowIntermediateDoesNotFallBack(t *testing.T) {
	stub := &windowStub{received: true}
	dialer := startServer(t, stub)

	full := errors.New("очередь забита")
	send := windowSender(dialer, func(string, []byte) error { return full })

	w := fullWindow()
	w.Final = false
	err := send(context.Background(), w)

	if !errors.Is(err, full) {
		t.Fatalf("ожидали ошибку очереди, got %v", err)
	}
	if len(stub.got) != 0 {
		t.Fatalf("промежуточное окно ушло прямым вызовом (%d)", len(stub.got))
	}
}

// Финальное окно, не принятое очередью, доезжает прямым вызовом.
//
// Второго шанса у финала нет: сразу после него состояние сессии стирается
// вместе с базовой линией. Потеря финала оставляет заявку без улик — то есть
// дыру, которую сервер потом покажет алертом. Дыры быть не должно.
func TestSendWindowFinalFallsBackToDirectCall(t *testing.T) {
	stub := &windowStub{received: true}
	dialer := startServer(t, stub)

	send := windowSender(dialer, func(string, []byte) error { return errors.New("очередь забита") })

	w := fullWindow() // Final: true
	if err := send(context.Background(), w); err != nil {
		t.Fatalf("финальное окно не доехало: %v", err)
	}
	if len(stub.got) != 1 {
		t.Fatalf("ожидали один прямой вызов, got %d", len(stub.got))
	}
	if got := stub.got[0]; got.GetRequestId() != w.RequestID || !got.GetFinal() {
		t.Fatalf("сервер получил не то окно: %+v", got)
	}
}

// Сервер ответил без подтверждения приёма — это ошибка, а не тихий успех.
//
// Ack=false на прямом пути означает, что улики не сохранены. Вернуть nil здесь
// значило бы записать сессию как отчитавшуюся и не оставить в логе ни следа.
func TestSendWindowFinalUnacknowledgedIsError(t *testing.T) {
	stub := &windowStub{received: false}
	dialer := startServer(t, stub)

	send := windowSender(dialer, func(string, []byte) error { return errors.New("очередь забита") })

	if err := send(context.Background(), fullWindow()); err == nil {
		t.Fatal("неподтверждённый приём финального окна принят за успех")
	}
}

// Флаги сбора читаются из ответа сервера — и в обе стороны.
//
// Ноль (сервер старше агента, поля отсутствуют) обязан означать «не собирать»:
// иначе агент копил бы в общей FIFO-очереди записи, которые некому принять, и
// блокировал бы ИБ-алерты и статусы лока.
func TestSessionCollectFlagsReadsServerAnswer(t *testing.T) {
	on, interval := sessionCollectFlags(&pb.FetchAdminStatusResponse{
		CollectSessionChanges: true, SnapshotIntervalSec: 900,
	})
	if !on || interval != 900 {
		t.Fatalf("флаги сервера прочитаны как collect=%v interval=%d", on, interval)
	}

	off, zero := sessionCollectFlags(&pb.FetchAdminStatusResponse{})
	if off || zero != 0 {
		t.Fatalf("пустой ответ прочитан как collect=%v interval=%d", off, zero)
	}
}

// baseline_captured в отчёте о выдаче отражает ФАКТ снятия базовой линии.
//
// По этому полю сервер отличает «улик не ждём» от «улики пропали». Ошибка в
// любую сторону ломает подотчётность: false при снятой линии прячет настоящую
// дыру, true без линии заказывает алерт на пустом месте.
func TestReportBaselineCapturedBothWays(t *testing.T) {
	cases := []struct {
		name    string
		collect bool
		durable bool
		want    bool
	}{
		{"сбор включён и состояние на диске", true, true, true},
		{"сбор включён, но устойчивого состояния нет", true, false, false},
		{"сбор выключен", false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []*pb.ReportAdminAccessRequest
			m := &Manager{
				log:            quietLog(),
				priv:           dryRunPriv{log: quietLog()},
				consoleUser:    func() (string, bool) { return "alice", true },
				windowInterval: DefaultWindowInterval,
				collectChanges: tc.collect,
				collectFlags:   func(*pb.FetchAdminStatusResponse) (bool, int32) { return tc.collect, 0 },
				snapshot: func() ([]SoftFP, string, []SvcFP, string) {
					return []SoftFP{{Name: "App", Version: "1"}}, "ok", []SvcFP{{Key: "svc"}}, "ok"
				},
				bootTime: func() int64 { return 1 },
				report: func(_ context.Context, req *pb.ReportAdminAccessRequest) error {
					got = append(got, req)
					return nil
				},
			}
			if tc.durable {
				dir := t.TempDir()
				m.store = NewSessionStore(dir, dir)
			}

			m.grant(context.Background(), "req-1", time.Now().Add(time.Hour))

			if len(got) != 1 {
				t.Fatalf("ожидали один отчёт о выдаче, got %d", len(got))
			}
			if got[0].GetBaselineCaptured() != tc.want {
				t.Fatalf("baseline_captured=%v, ожидали %v", got[0].GetBaselineCaptured(), tc.want)
			}
		})
	}
}
