package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/api"
	"github.com/Floodww/RoutineOps/internal/server/mailer"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// fvEnabledPolicy — тест-политика, разрешающая filevault (зеркалит enterprise
// escrow.Policy{Enabled:true} без импорта enterprise-пакета). Тестит api-шов
// WithLockModePolicy: filevault → разрешён, мусор → 400.
type fvEnabledPolicy struct{}

func (fvEnabledPolicy) ValidateMode(m string) error {
	switch m {
	case "", storage.LockModeOverlay, storage.LockModeFileVault:
		return nil
	default:
		return api.ErrLockModeInvalid
	}
}

func newRouterEscrowOn(t *testing.T, db *storage.DB) http.Handler {
	t.Helper()
	return api.NewRouter(db, nil, []byte("test-secret"), nil, "https://test.local", t.TempDir(),
		mailer.New("", "", "", "", "", false), false,
		api.WithLockModePolicy(fvEnabledPolicy{}))
}

// filevault-лок ОТКЛОНЯЕТСЯ (409) когда escrow выключен — fail-safe: агенту некуда
// эскроить recovery-ключ ДО revoke Secure Token = кирпич. Явный код, не тихая
// деградация в overlay: админ должен знать, что деструктив недоступен.
func TestLockDevice_FileVault_RequiresEscrow(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db) // escrow disabled
	tok := authToken(t, rtr, db)
	deviceID, _ := createDevice(t, rtr, tok, "host-fv-noescrow", "macos")
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+deviceID+"/lock",
		[]byte(`{"reason":"x","mode":"filevault"}`), tok)
	if w.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409; body: %s", w.Code, w.Body)
	}
}

// filevault-лок с включённым escrow → 200 и task несёт lock_mode=filevault (доедет
// до агента через worker.LockModeToProto).
func TestLockDevice_FileVault_WithEscrow(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterEscrowOn(t, db)
	tok := authToken(t, rtr, db)
	deviceID, _ := createDevice(t, rtr, tok, "host-fv-escrow", "macos")
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+deviceID+"/lock",
		[]byte(`{"reason":"утеря","mode":"filevault"}`), tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	task, err := db.GetTask(storage.WithTenantID(t.Context(), tenancy.DefaultTenantID), resp["task_id"])
	if err != nil || task == nil {
		t.Fatalf("GetTask: %v", err)
	}
	if task.LockMode != storage.LockModeFileVault {
		t.Fatalf("task.LockMode = %q, want %q", task.LockMode, storage.LockModeFileVault)
	}
}

func TestLockDevice_InvalidMode_Returns400(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterEscrowOn(t, db)
	tok := authToken(t, rtr, db)
	deviceID, _ := createDevice(t, rtr, tok, "host-badmode", "macos")
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+deviceID+"/lock",
		[]byte(`{"reason":"x","mode":"nuke"}`), tok)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400; body: %s", w.Code, w.Body)
	}
}

// дефолтный лок (без mode) — overlay, работает и без escrow.
func TestLockDevice_DefaultOverlay(t *testing.T) {
	db := newTestDB(t)
	rtr := newRouterFull(t, db) // escrow disabled
	tok := authToken(t, rtr, db)
	deviceID, _ := createDevice(t, rtr, tok, "host-overlay", "macos")
	w := authedDo(t, rtr, http.MethodPost, "/api/v1/devices/"+deviceID+"/lock",
		[]byte(`{"reason":"x"}`), tok)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", w.Code, w.Body)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	task, err := db.GetTask(storage.WithTenantID(t.Context(), tenancy.DefaultTenantID), resp["task_id"])
	if err != nil || task == nil {
		t.Fatalf("GetTask: %v", err)
	}
	if task.LockMode != storage.LockModeOverlay {
		t.Fatalf("task.LockMode = %q, want %q", task.LockMode, storage.LockModeOverlay)
	}
}
