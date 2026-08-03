package storage_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// deviceWithAgentVersion заводит устройство и проставляет ему версию агента так же,
// как это делает живой инвентарь.
func deviceWithAgentVersion(t *testing.T, db *storage.DB, name, agentVersion string) string {
	t.Helper()
	ctx := context.Background()
	fp := fmt.Sprintf("fp-%s-%s", name, uniq(t))
	if err := db.UpsertDeviceHeartbeat(ctx, storageHeartbeatData(fp, name, name, "192.0.2.11")); err != nil {
		t.Fatalf("UpsertDeviceHeartbeat: %v", err)
	}
	if agentVersion != "" {
		if err := db.UpsertInventory(ctx, storageInventoryDataV(fp, name, "macos", "14.0", agentVersion, nil)); err != nil {
			t.Fatalf("UpsertInventory: %v", err)
		}
	}
	id, err := db.GetDeviceIDByFingerprint(ctx, fp)
	if err != nil || id == "" {
		t.Fatalf("GetDeviceIDByFingerprint: %v (id=%q)", err, id)
	}
	return id
}

// Задача типа, которого агент устройства не умеет, не должна создаваться вовсе.
// Раньше она создавалась, доезжала и агент до 2.5.8 отчитывался по ней успехом,
// не сделав ничего. Без гейта первый подтест зелёный — то есть задача создана.
func TestCreateTask_AgentCapabilityGate(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	old := deviceWithAgentVersion(t, db, "cap-old", "2.5.7")
	if _, err := db.CreateFileVaultProvisionTask(ctx, old, "нужен пароль"); !errors.Is(err, storage.ErrAgentTooOld) {
		t.Fatalf("агент 2.5.7 не умеет filevault_provision, ждали ErrAgentTooOld, получили %v", err)
	}

	// Версия неизвестна (устройство ещё не отдавало инвентарь) — тоже отказ: обещать
	// исполнение там, где мы не знаем исполнителя, и есть исходная болезнь.
	unknown := deviceWithAgentVersion(t, db, "cap-unknown", "")
	if _, err := db.CreateFileVaultProvisionTask(ctx, unknown, "нужен пароль"); !errors.Is(err, storage.ErrAgentTooOld) {
		t.Fatalf("неизвестная версия агента: ждали ErrAgentTooOld, получили %v", err)
	}

	fresh := deviceWithAgentVersion(t, db, "cap-fresh", "2.5.8")
	if _, err := db.CreateFileVaultProvisionTask(ctx, fresh, "нужен пароль"); err != nil {
		t.Fatalf("агент ровно минимальной версии обязан проходить: %v", err)
	}

	// У типов, которые парк умеет с незапамятных версий, минимума нет — гейт обязан
	// молчать, иначе он отказывал бы живым устройствам по выдуманному порогу.
	if _, err := db.CreateRebootTask(ctx, old, "плановая перезагрузка", 0); err != nil {
		t.Fatalf("reboot не гейтится по версии, но упал: %v", err)
	}
}
