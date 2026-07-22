package lock

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/Floodww/RoutineOps/proto"
)

// #1.1: сервер прислал desired=locked с ПУСТЫМ password_hash (или Lock отказал
// транзиентно). Реконсиляция НЕ должна слать серверу состояние, стирающее
// desired: overlay-UNLOCKED на сервере идёт в SetDeviceLockState('unlocked',”)
// и уничтожает desired=locked — транзиентный сбой навсегда разоружил бы
// kill-switch (adversarial-ревью: critical). Держим desired нетронутым (ни
// одного отчёта), логируем, и полагаемся на ретрай следующего тика.
func TestReconcile_LockApplyFailure_DoesNotEraseDesired(t *testing.T) {
	fl := &fakeLocker{}
	mgr := newMgr(t, fl)

	var reports []*pb.ReportLockStatusRequest
	r := &Reconciler{
		mgr: mgr, interval: 0, log: quietLog(),
		fetch: func(context.Context) (*pb.FetchLockStatusResponse, error) {
			return &pb.FetchLockStatusResponse{Locked: true, PasswordHash: ""}, nil
		},
		report: func(_ context.Context, req *pb.ReportLockStatusRequest) error {
			reports = append(reports, req)
			return nil
		},
	}

	r.tick(context.Background())
	r.tick(context.Background()) // ретрай — тоже без отчёта

	if len(reports) != 0 {
		t.Fatalf("реконсиляция отправила %d отчёт(ов) при провале Lock — desired на сервере мог быть стёрт (kill-switch разоружён)", len(reports))
	}
	if mgr.Locked() || fl.shows != 0 {
		t.Fatalf("оверлей НЕ должен подниматься при пустом хеше: locked=%v shows=%d", mgr.Locked(), fl.shows)
	}
}

// Manager.Lock атомарен: при отказе persist состояние ОТКАТЫВАЕТСЯ, mgr.Locked()
// остаётся false. Иначе in-memory Locked=true маскировал бы провал (оверлей не
// поднят, диск не записан), и реконсиляция по mgr.Locked() считала бы лок
// применённым, не повторяя попытку — транзиентный сбой persist подавлял бы
// kill-switch бессрочно.
func TestManagerLock_RollsBackOnPersistFailure(t *testing.T) {
	// Путь, куда persist гарантированно не запишет: родитель — обычный ФАЙЛ,
	// поэтому MkdirAll в writeStateAtomic падает.
	fileAsParent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileAsParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fl := &fakeLocker{}
	m := New(filepath.Join(fileAsParent, "lock.json"), fl, quietLog())

	err := m.Lock("r1", bcryptHash(t, "pw"), "увольнение")
	if err == nil {
		t.Fatal("ожидали ошибку Lock при отказе persist")
	}
	if m.Locked() {
		t.Fatal("после отказа persist mgr.Locked()==true — состояние не откатилось, провал замаскирован")
	}
	if fl.shows != 0 {
		t.Fatalf("оверлей поднят при не записанном на диск локе: shows=%d", fl.shows)
	}
}
