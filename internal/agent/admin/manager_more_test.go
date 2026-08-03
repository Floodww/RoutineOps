package admin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
)

// errPriv — PrivilegeManager с настраиваемыми ошибками Grant/Revoke для проверки
// веток обработки ошибок ОС-слоя.
type errPriv struct {
	grantErr, revokeErr error
	granted, revoked    []string
}

func (e *errPriv) Grant(u string) error         { e.granted = append(e.granted, u); return e.grantErr }
func (e *errPriv) Revoke(u string) error        { e.revoked = append(e.revoked, u); return e.revokeErr }
func (e *errPriv) IsAdmin(string) (bool, error) { return false, nil }

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// dryRunPriv не трогает систему — обе операции всегда успешны и лишь логируются.
func TestDryRunPriv(t *testing.T) {
	d := dryRunPriv{log: quietLog()}
	if err := d.Grant("alice"); err != nil {
		t.Fatalf("dry-run Grant вернул ошибку: %v", err)
	}
	if err := d.Revoke("alice"); err != nil {
		t.Fatalf("dry-run Revoke вернул ошибку: %v", err)
	}
}

// Нет вошедшего пользователя → права не выдаются, состояние не меняется,
// отчёт APPROVED не отправляется.
func TestGrantNoConsoleUser(t *testing.T) {
	h := newHarness()
	h.user = "" // никто не залогинен
	h.resp = approved("r1", time.Now().Add(time.Hour))
	h.m.poll(context.Background())

	if len(h.priv.granted) != 0 {
		t.Fatalf("без пользователя не должно быть выдачи: %v", h.priv.granted)
	}
	if h.m.grantedUser != "" || h.m.lastReqID != "" {
		t.Fatalf("состояние не должно меняться: user=%q req=%q", h.m.grantedUser, h.m.lastReqID)
	}
	if lastReport(h) != nil {
		t.Fatalf("не ожидали отчёт, got %+v", lastReport(h))
	}
}

// ОС вернула ошибку при выдаче → состояние не фиксируется, заявка не считается
// обработанной (можно повторить на следующем тике), отчёт APPROVED не уходит.
func TestGrantPrivError(t *testing.T) {
	ep := &errPriv{grantErr: errors.New("dseditgroup failed")}
	var reports []*pb.ReportAdminAccessRequest
	m := &Manager{
		log:         quietLog(),
		priv:        ep,
		consoleUser: func() (string, bool) { return "bob", true },
		fetch: func(context.Context) (*pb.FetchAdminStatusResponse, error) {
			return approved("r1", time.Now().Add(time.Hour)), nil
		},
		report: func(_ context.Context, r *pb.ReportAdminAccessRequest) error {
			reports = append(reports, r)
			return nil
		},
	}
	m.poll(context.Background())

	if len(ep.granted) != 1 {
		t.Fatalf("ожидали попытку выдачи, got %v", ep.granted)
	}
	if m.grantedUser != "" || m.lastReqID != "" {
		t.Fatalf("при ошибке ОС состояние не должно фиксироваться: user=%q req=%q", m.grantedUser, m.lastReqID)
	}
	if len(reports) != 0 {
		t.Fatalf("при ошибке выдачи отчёт не должен уходить, got %+v", reports)
	}
}

// ОС вернула ошибку при снятии → состояние всё равно очищается (не зацикливаемся),
// отчёт REVOKED всё равно отправляется.
func TestRevokePrivError(t *testing.T) {
	ep := &errPriv{revokeErr: errors.New("dseditgroup failed")}
	var reports []*pb.ReportAdminAccessRequest
	user := "carol"
	m := &Manager{
		log:         quietLog(),
		priv:        ep,
		consoleUser: func() (string, bool) { return user, true },
		fetch: func(context.Context) (*pb.FetchAdminStatusResponse, error) {
			return approved("r1", time.Now().Add(time.Hour)), nil
		},
		report: func(_ context.Context, r *pb.ReportAdminAccessRequest) error {
			reports = append(reports, r)
			return nil
		},
	}
	m.poll(context.Background()) // выдали carol

	user = "" // логаут → revoke с ошибкой ОС
	m.poll(context.Background())

	if len(ep.revoked) != 1 {
		t.Fatalf("ожидали попытку снятия, got %v", ep.revoked)
	}
	if m.grantedUser != "" || !m.grantedExpires.IsZero() {
		t.Fatalf("состояние должно очищаться даже при ошибке снятия: user=%q exp=%v", m.grantedUser, m.grantedExpires)
	}
	if r := reports[len(reports)-1]; r.GetStatus() != pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED {
		t.Fatalf("ожидали отчёт REVOKED, got %+v", r)
	}
}

// Ошибка отправки отчёта не должна ломать выдачу прав (отчёт лишь логируется).
func TestReportStatusError(t *testing.T) {
	h := newHarness()
	h.m.report = func(context.Context, *pb.ReportAdminAccessRequest) error {
		return errors.New("outbox full")
	}
	h.resp = approved("r1", time.Now().Add(time.Hour))
	h.m.poll(context.Background())

	if len(h.priv.granted) != 1 || h.m.grantedUser != "alice" {
		t.Fatalf("права должны быть выданы несмотря на ошибку отчёта: granted=%v user=%q", h.priv.granted, h.m.grantedUser)
	}
}

// Run должен периодически вызывать poll и завершаться по отмене контекста.
func TestRunPollsAndStops(t *testing.T) {
	var polls int32
	m := &Manager{
		interval:    time.Millisecond,
		log:         quietLog(),
		priv:        &fakePriv{},
		consoleUser: func() (string, bool) { return "alice", true },
		fetch: func(context.Context) (*pb.FetchAdminStatusResponse, error) {
			atomic.AddInt32(&polls, 1)
			return &pb.FetchAdminStatusResponse{}, nil
		},
		report: func(context.Context, *pb.ReportAdminAccessRequest) error { return nil },
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()

	// Дать нескольким тикам отработать, затем отменить.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run не завершился после отмены контекста")
	}
	if atomic.LoadInt32(&polls) == 0 {
		t.Fatal("Run ни разу не вызвал poll")
	}
}

// Бессрочная заявка (ExpiresAt=0) — права выдаются и держатся до логаута,
// проверяет ветку approvedNow при expires_at==0.
func TestGrantPermanentNoExpiry(t *testing.T) {
	h := newHarness()
	h.resp = &pb.FetchAdminStatusResponse{
		RequestId: "perm1",
		Status:    pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED,
		ExpiresAt: 0, // без срока
	}
	h.m.poll(context.Background())

	if len(h.priv.granted) != 1 || h.priv.granted[0] != "alice" {
		t.Fatalf("ожидали выдачу по бессрочной заявке, got %v", h.priv.granted)
	}
	// Повторный poll — без повторной выдачи и без снятия (заявка та же, бессрочная).
	h.m.poll(context.Background())
	if len(h.priv.granted) != 1 || len(h.priv.revoked) != 0 {
		t.Fatalf("бессрочная заявка не должна пере-выдаваться/сниматься: granted=%v revoked=%v", h.priv.granted, h.priv.revoked)
	}
}

// osConsoleUser лишь читает владельца /dev/console — безопасно вызвать в тесте;
// проверяем, что не паникует и возвращает строку (root → "").
func TestOSConsoleUserSmoke(t *testing.T) {
	_ = osConsoleUser()
}

// NewManager с dryRun=true собирает Manager с dryRunPriv и рабочим report-замыканием
// (durable enqueue в outbox). Боевой dialer при конструировании не используется.
func TestNewManagerDryRun(t *testing.T) {
	var enqKind string
	var enqCalls int32
	enqueue := func(kind string, data []byte) error {
		enqKind = kind
		atomic.AddInt32(&enqCalls, 1)
		return nil
	}
	m := NewManager(nil, enqueue, 42*time.Second, quietLog(), true, nil)

	if _, ok := m.priv.(dryRunPriv); !ok {
		t.Fatalf("при dryRun ожидали dryRunPriv, got %T", m.priv)
	}
	if m.interval != 42*time.Second {
		t.Fatalf("interval не проброшен: %v", m.interval)
	}
	if m.consoleUser == nil {
		t.Fatal("consoleUser не установлен")
	}
	// report-замыкание должно сериализовать запрос и положить его в outbox.
	if err := m.report(context.Background(), &pb.ReportAdminAccessRequest{RequestId: "r1"}); err != nil {
		t.Fatalf("report вернул ошибку: %v", err)
	}
	if atomic.LoadInt32(&enqCalls) != 1 || enqKind == "" {
		t.Fatalf("report не поставил отчёт в очередь: calls=%d kind=%q", enqCalls, enqKind)
	}
}
