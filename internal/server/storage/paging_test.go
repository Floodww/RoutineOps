package storage_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Страницы устройств не должны терять и дублировать строки, а total обязан считать
// ВСЮ выдачу под фильтром, а не размер страницы. База в тестах общая, поэтому
// считаем внутри своей группы — иначе устройства соседних тестов ломают арифметику.
func TestListEnrolledDevices_Pagination(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)

	group, err := db.CreateDeviceGroup(ctx, "grp-page-"+suffix, "")
	if err != nil {
		t.Fatalf("CreateDeviceGroup: %v", err)
	}
	const want = 5
	ids := map[string]bool{}
	for i := 0; i < want; i++ {
		id := activeDevice(t, db, fmt.Sprintf("page-%d-%s", i, suffix), "Windows 11")
		if err := db.AddDeviceToGroup(ctx, id, group.ID); err != nil {
			t.Fatalf("AddDeviceToGroup: %v", err)
		}
		ids[id] = true
	}

	seen := map[string]bool{}
	for offset := 0; offset < want; offset += 2 {
		page, total, err := db.ListEnrolledDevices(ctx, "", group.ID, 2, offset)
		if err != nil {
			t.Fatalf("ListEnrolledDevices(offset=%d): %v", offset, err)
		}
		if total != want {
			t.Errorf("offset=%d: total = %d, want %d (счётчик считает всю выдачу, не страницу)", offset, total, want)
		}
		for _, d := range page {
			if seen[d.ID] {
				t.Errorf("устройство %s встретилось на двух страницах", d.ID)
			}
			seen[d.ID] = true
		}
	}
	if len(seen) != want {
		t.Errorf("листанием собрали %d устройств из %d — страницы теряют строки", len(seen), want)
	}

	// Хвост за пределами выдачи: страница пуста, и total тоже 0 — счётчик едет окном
	// вместе со строками (см. paging.go). Это осознанный контракт, а не потеря данных:
	// признак «промахнулись offset'ом, а не пусто по фильтру» — сам offset > 0, по нему
	// интерфейс возвращается на первую страницу.
	page, total, err := db.ListEnrolledDevices(ctx, "", group.ID, 2, 999)
	if err != nil {
		t.Fatalf("ListEnrolledDevices(offset=999): %v", err)
	}
	if len(page) != 0 || total != 0 {
		t.Errorf("offset за концом: страница=%d total=%d, want 0 и 0", len(page), total)
	}

	// Потолок limit'а: запрос «отдай всё» не должен материализовать таблицу.
	if _, _, err := db.ListEnrolledDevices(ctx, "", group.ID, 1_000_000, 0); err != nil {
		t.Fatalf("ListEnrolledDevices(limit=1e6): %v", err)
	}
}

// Фильтры журнала уехали на сервер вместе с пагинацией: считая их на клиенте поверх
// страницы, интерфейс показывал бы совпадения только в пределах последних N записей.
func TestListAuditLog_ServerSideFilters(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	suffix := uniq(t)
	action := "PAGE_ACTION_" + suffix
	alice := fmt.Sprintf("alice-%s@test.com", suffix)
	bob := fmt.Sprintf("bob-%s@test.com", suffix)

	before := time.Now().Add(-time.Minute)
	for i := 0; i < 3; i++ {
		if err := db.WriteAuditLog(ctx, "", alice, action, "device", fmt.Sprintf("a%d", i), nil); err != nil {
			t.Fatalf("WriteAuditLog alice: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := db.WriteAuditLog(ctx, "", bob, action, "device", fmt.Sprintf("b%d", i), nil); err != nil {
			t.Fatalf("WriteAuditLog bob: %v", err)
		}
	}

	// Пагинация внутри действия.
	seen := map[string]bool{}
	for offset := 0; offset < 5; offset += 2 {
		page, total, err := db.ListAuditLog(ctx, storage.AuditFilter{Action: action}, 2, offset)
		if err != nil {
			t.Fatalf("ListAuditLog(offset=%d): %v", offset, err)
		}
		if total != 5 {
			t.Errorf("offset=%d: total = %d, want 5", offset, total)
		}
		for _, e := range page {
			if seen[e.ID] {
				t.Errorf("запись %s встретилась на двух страницах", e.ID)
			}
			seen[e.ID] = true
		}
	}
	if len(seen) != 5 {
		t.Errorf("листанием собрали %d записей из 5", len(seen))
	}

	// Кто: подстрока по email, а не точное совпадение — оператор ищет по имени.
	if _, total, err := db.ListAuditLog(ctx, storage.AuditFilter{Action: action, Who: "alice-" + suffix}, 50, 0); err != nil {
		t.Fatalf("ListAuditLog(who): %v", err)
	} else if total != 3 {
		t.Errorf("who=alice: total = %d, want 3", total)
	}

	// Период: нижняя граница до записей — все, после записей — ни одной.
	after := time.Now().Add(time.Minute)
	if _, total, err := db.ListAuditLog(ctx, storage.AuditFilter{Action: action, From: &before, To: &after}, 50, 0); err != nil {
		t.Fatalf("ListAuditLog(period): %v", err)
	} else if total != 5 {
		t.Errorf("период вокруг записей: total = %d, want 5", total)
	}
	if _, total, err := db.ListAuditLog(ctx, storage.AuditFilter{Action: action, From: &after}, 50, 0); err != nil {
		t.Fatalf("ListAuditLog(from=future): %v", err)
	} else if total != 0 {
		t.Errorf("период в будущем: total = %d, want 0", total)
	}
}
