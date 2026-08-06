package api_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/api"
	"github.com/Floodww/RoutineOps/internal/server/mailer"
	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Записи экрана удаляются ФАЙЛАМИ, а строки — каскадом схемы. Значит проверять надо не
// «функция purge работает» (это делает пакет screen), а что ручка её ЗОВЁТ и что делает
// с её отказом. До этой правки PurgeDevice не вызывалась ниоткуда: код был написан,
// покрыт тестом и мёртв, а записи оставались на томе после списания устройства (§6).

// fakePurger — считает вызовы и умеет отказывать.
type fakePurger struct {
	devices []string
	tenants []string
	err     error
}

func (f *fakePurger) PurgeDevice(_ context.Context, tenantID, deviceID string) error {
	f.devices = append(f.devices, tenantID+"/"+deviceID)
	return f.err
}

func (f *fakePurger) PurgeTenant(_ context.Context, tenantID string) error {
	f.tenants = append(f.tenants, tenantID)
	return f.err
}

func routerWithPurger(t *testing.T, db *storage.DB, p api.ScreenPurger) http.Handler {
	t.Helper()
	return api.NewRouter(db, nil, []byte("test-secret"), nil, "https://test.local", t.TempDir(),
		mailer.New("", "", "", "", "", false), false, api.WithScreenPurger(p))
}

func TestDeleteDevicePurgesScreenRecordings(t *testing.T) {
	db := newTestDB(t)
	purger := &fakePurger{}
	rtr := routerWithPurger(t, db, purger)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-purge", "linux")
	w := authedDo(t, rtr, http.MethodDelete, "/api/v1/devices/"+deviceID, nil, tok)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("удаление устройства: %d %s", w.Code, w.Body)
	}
	if len(purger.devices) != 1 {
		t.Fatalf("purge вызван %d раз, want 1 — записи экрана остались бы на диске", len(purger.devices))
	}
}

// 🔴 Отказ удаления записей обязан ОТМЕНЯТЬ удаление устройства. Иначе получается
// худший исход: оператору сказали «удалено», строки уехали каскадом, а файлы остались
// на томе — и теперь о них не знает никто, включая нас.
func TestDeleteDeviceAbortedWhenPurgeFails(t *testing.T) {
	db := newTestDB(t)
	purger := &fakePurger{err: errors.New("том недоступен")}
	rtr := routerWithPurger(t, db, purger)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-purge-fail", "linux")
	w := authedDo(t, rtr, http.MethodDelete, "/api/v1/devices/"+deviceID, nil, tok)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("отказ purge дал %d, want 500", w.Code)
	}
	// Устройство обязано остаться: удалять его, не убрав записи, нельзя.
	got := authedDo(t, rtr, http.MethodGet, "/api/v1/devices/"+deviceID, nil, tok)
	if got.Code == http.StatusNotFound {
		t.Fatal("устройство удалено, хотя записи экрана удалить не удалось")
	}
}

// Открытая сборка живёт без реализации шва: записей экрана в ней не бывает вовсе, и
// удаление устройства обязано работать как раньше. Проверяем именно nil-путь.
func TestDeleteDeviceWorksWithoutPurgerInOpenCore(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db)
	tok := authToken(t, rtr, db)

	deviceID, _ := createDevice(t, rtr, tok, "host-no-purger", "linux")
	w := authedDo(t, rtr, http.MethodDelete, "/api/v1/devices/"+deviceID, nil, tok)
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("удаление без покрытия шва: %d %s", w.Code, w.Body)
	}
}
