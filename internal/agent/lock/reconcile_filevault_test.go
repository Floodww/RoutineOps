package lock

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
)

// fakeFileVaultRevoker записывает вызовы RevokeAndShutdown (pull-путь).
type fakeFileVaultRevoker struct {
	calls []string
	state pb.LockState
	err   error
}

func (f *fakeFileVaultRevoker) RevokeAndShutdown(_ context.Context, requestID string) (pb.LockState, error) {
	f.calls = append(f.calls, requestID)
	return f.state, f.err
}

func newTestReconciler(mgr *Manager, fetchResp *pb.FetchLockStatusResponse, fetchErr error) *Reconciler {
	return &Reconciler{
		mgr:      mgr,
		interval: 0,
		log:      quietLog(),
		fetch: func(context.Context) (*pb.FetchLockStatusResponse, error) {
			return fetchResp, fetchErr
		},
		report: func(context.Context, *pb.ReportLockStatusRequest) error { return nil },
	}
}

// desired lock_mode=FILEVAULT → реконсиляция дёргает revoker, НЕ mgr.Lock
// (overlay lock.json/оверлей не должны трогаться для FileVault-режима).
func TestReconcile_FileVaultMode_CallsRevoker_NotOverlay(t *testing.T) {
	fl := &fakeLocker{}
	mgr := newMgr(t, fl)
	fr := &fakeFileVaultRevoker{state: pb.LockState_LOCK_STATE_FILEVAULT_REVOKED}

	r := newTestReconciler(mgr, &pb.FetchLockStatusResponse{
		Locked: true, PasswordHash: "hash-fv", LockMode: pb.LockMode_LOCK_MODE_FILEVAULT,
	}, nil)
	r.SetFileVaultRevoker(fr)

	r.tick(context.Background())
	r.fvWG.Wait() // M4: revoke уходит в фоновый воркер — дождаться перед ассертами

	if len(fr.calls) != 1 || fr.calls[0] != "hash-fv" {
		t.Fatalf("expected RevokeAndShutdown called once with hash-fv, got %v", fr.calls)
	}
	if fl.shows != 0 {
		t.Fatalf("overlay locker must not be shown for lock_mode=FILEVAULT, got shows=%d", fl.shows)
	}
	if mgr.Locked() {
		t.Fatalf("lock.Manager (overlay state) must remain untouched for FILEVAULT mode")
	}
}

// #4: после «ребута» in-memory lastUnlockedHash реконсилятора пуст, но Manager
// хранит hash последнего локального снятия durably — реконсиляция НЕ должна
// пере-запереть устройство по устаревшему desired=locked (сервер ещё не догнал
// UNLOCKED-отчёт из outbox).
func TestReconcile_DurableLastUnlocked_NoRelockAfterRestart(t *testing.T) {
	fl := &fakeLocker{}
	mgr := newMgr(t, fl)
	hash := bcryptHash(t, "pw")
	if err := mgr.Lock("r1", hash, "увольнение"); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := mgr.Unlock(); err != nil { // локальное снятие → durable LastUnlockedHash
		t.Fatalf("Unlock: %v", err)
	}

	// Свежий реконсилятор (lastUnlockedHash в памяти пуст), сервер ещё
	// показывает desired=locked с тем же hash.
	r := newTestReconciler(mgr, &pb.FetchLockStatusResponse{Locked: true, PasswordHash: hash}, nil)
	r.tick(context.Background())

	if mgr.Locked() {
		t.Fatal("устройство пере-заблокировано по устаревшему desired после ребута (#4)")
	}
	if fl.shows != 1 {
		t.Fatalf("замок поднят повторно (re-lock), shows=%d, want 1 (только исходный Lock)", fl.shows)
	}
}

// desired lock_mode=OVERLAY (или unspecified) → обычный путь через mgr.Lock,
// revoker не трогается, даже если сконфигурирован.
func TestReconcile_OverlayMode_DoesNotCallRevoker(t *testing.T) {
	fl := &fakeLocker{}
	mgr := newMgr(t, fl)
	fr := &fakeFileVaultRevoker{state: pb.LockState_LOCK_STATE_FILEVAULT_REVOKED}

	// Реальный bcrypt-хеш: overlay-путь зовёт mgr.Lock, который #13-валидацией
	// отвергает невалидный хеш (fake-строка "hash-overlay" им и была).
	r := newTestReconciler(mgr, &pb.FetchLockStatusResponse{
		Locked: true, PasswordHash: bcryptHash(t, "overlay-pw"),
	}, nil)
	r.SetFileVaultRevoker(fr)

	r.tick(context.Background())

	if len(fr.calls) != 0 {
		t.Fatalf("revoker must not be called for overlay/unspecified lock_mode, got %v", fr.calls)
	}
	if !mgr.Locked() {
		t.Fatalf("expected overlay lock to be applied")
	}
}

// Без revoker lock_mode=FILEVAULT логируется как ошибка, mgr.Lock НЕ
// вызывается (нет тихой деградации в overlay).
func TestReconcile_FileVaultMode_NoRevoker_DoesNotFallBackToOverlay(t *testing.T) {
	fl := &fakeLocker{}
	mgr := newMgr(t, fl)

	r := newTestReconciler(mgr, &pb.FetchLockStatusResponse{
		Locked: true, PasswordHash: "hash-fv", LockMode: pb.LockMode_LOCK_MODE_FILEVAULT,
	}, nil) // SetFileVaultRevoker не вызывали

	r.tick(context.Background())

	if mgr.Locked() {
		t.Fatalf("must not silently degrade to overlay lock when revoker is unconfigured")
	}
}

// Ошибка RevokeAndShutdown (ABORT одного из гардов) логируется, оверлей не трогается.
func TestReconcile_FileVaultMode_RevokeError_DoesNotTouchOverlay(t *testing.T) {
	fl := &fakeLocker{}
	mgr := newMgr(t, fl)
	fr := &fakeFileVaultRevoker{err: errors.New("revoke ABORT — residual owner")}

	r := newTestReconciler(mgr, &pb.FetchLockStatusResponse{
		Locked: true, PasswordHash: "hash-fv", LockMode: pb.LockMode_LOCK_MODE_FILEVAULT,
	}, nil)
	r.SetFileVaultRevoker(fr)

	r.tick(context.Background())
	r.fvWG.Wait()

	if mgr.Locked() {
		t.Fatalf("overlay must remain untouched even when FileVault revoke fails")
	}
	if len(fr.calls) != 1 {
		t.Fatalf("expected exactly one RevokeAndShutdown attempt, got %v", fr.calls)
	}
}

// blockingRevoker имитирует RevokeAndShutdown, надолго повисший в durable
// ReportState (сервер недоступен): вход сигналится в started, выход — по release.
type blockingRevoker struct {
	started chan struct{}
	release chan struct{}
	calls   int32
}

func (b *blockingRevoker) RevokeAndShutdown(context.Context, string) (pb.LockState, error) {
	atomic.AddInt32(&b.calls, 1)
	b.started <- struct{}{}
	<-b.release
	return pb.LockState_LOCK_STATE_FILEVAULT_REVOKED, nil
}

// RevokeAndShutdown может блокироваться до agent-lifetime
// ctx (durable ReportState с backoff 1с→2мин) — tick не должен замерзать на
// нём, а повторные тики при живом воркере не должны плодить параллельные
// revoke-цепочки (и копить горутины на Chain.mu).
func TestReconcile_FileVaultMode_TickNotBlocked_SingleWorker(t *testing.T) {
	mgr := newMgr(t, &fakeLocker{})
	br := &blockingRevoker{started: make(chan struct{}, 1), release: make(chan struct{})}
	r := newTestReconciler(mgr, &pb.FetchLockStatusResponse{
		Locked: true, PasswordHash: "hash-fv", LockMode: pb.LockMode_LOCK_MODE_FILEVAULT,
	}, nil)
	r.SetFileVaultRevoker(br)

	tickDone := make(chan struct{})
	go func() {
		r.tick(context.Background())
		close(tickDone)
	}()
	select {
	case <-tickDone:
	case <-time.After(2 * time.Second):
		t.Fatal("tick завис на блокирующем RevokeAndShutdown — M4-регрессия")
	}
	<-br.started // воркер реально запущен и висит внутри revoke

	r.tick(context.Background()) // повторный тик при живом воркере — no-op
	if got := atomic.LoadInt32(&br.calls); got != 1 {
		t.Fatalf("повторный тик запустил параллельный revoke: calls=%d, want 1", got)
	}

	close(br.release)
	r.fvWG.Wait()

	r.tick(context.Background()) // воркер завершён — следующий тик снова применяет desired
	r.fvWG.Wait()
	if got := atomic.LoadInt32(&br.calls); got != 2 {
		t.Fatalf("после завершения воркера тик обязан повторить revoke: calls=%d, want 2", got)
	}
}
