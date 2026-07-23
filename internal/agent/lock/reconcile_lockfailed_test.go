package lock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/Floodww/RoutineOps/proto"
)

// mgr с гарантированно падающим persist (родитель пути состояния — обычный ФАЙЛ,
// поэтому MkdirAll в writeStateAtomic валится): Lock с ВАЛИДНЫМ hash всё равно
// отказывает на записи, то есть request_id непустой (в отличие от empty-hash из #1.1).
func failingPersistReconciler(t *testing.T, hash string, report func(context.Context, *pb.ReportLockStatusRequest) error) *Reconciler {
	t.Helper()
	fileAsParent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileAsParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mgr := New(filepath.Join(fileAsParent, "lock.json"), &fakeLocker{}, quietLog())
	return &Reconciler{
		mgr: mgr, interval: 0, log: quietLog(),
		fetch: func(context.Context) (*pb.FetchLockStatusResponse, error) {
			return &pb.FetchLockStatusResponse{Locked: true, PasswordHash: hash}, nil
		},
		report: report,
	}
}

// Провал применения desired=locked отчитывается durably: LOCK_FAILED с request_id
// этой блокировки и текстом реальной ошибки (сервер кладёт в аудит/алерт/карточку,
// коррелирует поздний отчёт из outbox по request_id). Дедуп: один отчёт на request_id,
// сколько бы тиков ни ретраило (гейт часа).
func TestReconcile_LockFailed_ReportsRequestIdAndDedup(t *testing.T) {
	hash := bcryptHash(t, "pw")
	var reports []*pb.ReportLockStatusRequest
	r := failingPersistReconciler(t, hash, func(_ context.Context, req *pb.ReportLockStatusRequest) error {
		reports = append(reports, req)
		return nil
	})

	r.tick(context.Background())
	r.tick(context.Background())
	r.tick(context.Background()) // много ретраев — отчёт всё равно один (гейт часа)

	if len(reports) != 1 {
		t.Fatalf("ожидали ровно один LOCK_FAILED (дедуп по request_id), получили %d", len(reports))
	}
	rep := reports[0]
	if rep.GetState() != pb.LockState_LOCK_STATE_LOCK_FAILED {
		t.Fatalf("state=%v, want LOCK_STATE_LOCK_FAILED", rep.GetState())
	}
	if rep.GetRequestId() != hash {
		t.Fatalf("request_id=%q, want %q (сервер коррелирует отказ с конкретным локом)", rep.GetRequestId(), hash)
	}
	if !strings.Contains(rep.GetDetails(), "apply failed") {
		t.Fatalf("details без текста реальной ошибки: %q", rep.GetDetails())
	}
	if rep.GetOccurredAt() == 0 {
		t.Error("occurred_at не проставлен")
	}
}

// Бесконечные ретраи по одному request_id: повторный LOCK_FAILED — не чаще часа.
// Гейт проверяем, отматывая applyFailReportedAt назад больше чем на интервал.
func TestReconcile_LockFailed_HourlyRepeat(t *testing.T) {
	hash := bcryptHash(t, "pw")
	var reports []*pb.ReportLockStatusRequest
	r := failingPersistReconciler(t, hash, func(_ context.Context, req *pb.ReportLockStatusRequest) error {
		reports = append(reports, req)
		return nil
	})

	r.tick(context.Background()) // 1-й отчёт
	if len(reports) != 1 {
		t.Fatalf("после первого тика ожидали 1 отчёт, получили %d", len(reports))
	}
	// Ещё тик сразу — в пределах часа, отчёта быть не должно.
	r.tick(context.Background())
	if len(reports) != 1 {
		t.Fatalf("повтор в пределах часа не должен слать отчёт, получили %d", len(reports))
	}
	// Имитируем, что прошёл час с последнего отчёта.
	r.mu.Lock()
	r.applyFailReportedAt = r.applyFailReportedAt.Add(-2 * lockFailedReportInterval)
	r.mu.Unlock()
	r.tick(context.Background())
	if len(reports) != 2 {
		t.Fatalf("спустя час ретрай обязан повторить LOCK_FAILED, отчётов %d (want 2)", len(reports))
	}
	if reports[1].GetState() != pb.LockState_LOCK_STATE_LOCK_FAILED || reports[1].GetRequestId() != hash {
		t.Fatalf("повторный отчёт неверен: %+v", reports[1])
	}
}

// Отчёт не встал даже в очередь outbox → applyFailReportedAt сбрасывается, следующий
// тик повторяет попытку (durability: «лок не применился» терять нельзя).
func TestReconcile_LockFailed_RetriesWhenEnqueueFails(t *testing.T) {
	hash := bcryptHash(t, "pw")
	var attempts int
	r := failingPersistReconciler(t, hash, func(_ context.Context, _ *pb.ReportLockStatusRequest) error {
		attempts++
		if attempts == 1 {
			return errEnqueue // первый enqueue не удался
		}
		return nil
	})

	r.tick(context.Background()) // enqueue упал
	r.tick(context.Background()) // должен повторить, несмотря на дедуп по hash
	if attempts < 2 {
		t.Fatalf("после провала enqueue отчёт обязан повториться на следующем тике, попыток %d", attempts)
	}
}

var errEnqueue = errors.New("outbox недоступен")
