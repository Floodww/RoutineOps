package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/tenancy"
)

// Граница отказа этого класса — «запрос ушёл в базу без привязанного тенанта». Раньше
// она проходила ВНУТРИ Postgres: соединение из пула, предикат RLS не совпал, ноль строк,
// ошибки нет. Проверить её тестом было почти невозможно — testutil ставит роли дефолтный
// routineops.tenant_id, и мимо-скоупный запрос в тестах «попадает» в дефолтный тенант,
// то есть выглядит рабочим ровно там, где в проде он молчит.
//
// Теперь граница проходит ДО базы, в Go: непривязанный контекст даёт нулевой TenantScope,
// и запроса не случается вовсе. Отсюда и тесты ниже — они красные на прежнем коде и не
// зависят от того, что настроено у роли.

// Нулевой хэндл обязан отказывать из каждого метода. Это не косметика: собрать
// TenantScope снаружи нельзя, но внутри пакета структура нулевая по умолчанию, и
// «забыли инициализировать» обязано быть отказом, а не паникой и не тихим успехом.
func TestTenantScopeZeroValueFailsClosed(t *testing.T) {
	var s storage.TenantScope
	ctx := context.Background()

	if _, err := s.Query(ctx, `SELECT 1`); !errors.Is(err, tenancy.ErrTenantScopeMissing) {
		t.Errorf("Query: err = %v, want ErrTenantScopeMissing", err)
	}
	if _, err := s.Exec(ctx, `SELECT 1`); !errors.Is(err, tenancy.ErrTenantScopeMissing) {
		t.Errorf("Exec: err = %v, want ErrTenantScopeMissing", err)
	}
	// QueryRow ошибку не возвращает — единственный путь наружу через Scan, и он обязан
	// работать: иначе отказ превратился бы в панику на nil-строке.
	var v int
	if err := s.QueryRow(ctx, `SELECT 1`).Scan(&v); !errors.Is(err, tenancy.ErrTenantScopeMissing) {
		t.Errorf("QueryRow(...).Scan: err = %v, want ErrTenantScopeMissing", err)
	}
	if _, err := s.Tx(); !errors.Is(err, tenancy.ErrTenantScopeMissing) {
		t.Errorf("Tx: err = %v, want ErrTenantScopeMissing", err)
	}
}

// 🔴 Главный регресс. Непривязанный контекст НЕ должен доезжать до пула — ни при каких
// настройках роли. На прежнем коде (Q(ctx) → db.pool) этот тест зелёный и на сломанном
// поведении: запрос уходил соседним соединением и в тестовой конфигурации возвращал
// строки дефолтного тенанта. Именно так класс и прожил незамеченным.
func TestScopedWithoutBindNeverReachesPool(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	// Строка в базе ЕСТЬ: если бы запрос ушёл в пул, он бы её увидел (роль в тестах
	// имеет дефолтный тенант) — и «ноль строк» было бы не отличить от «нет данных».
	fp := "scope-guard-" + uniq(t)
	if err := db.UpsertDeviceHeartbeat(ctx, storage.HeartbeatData{
		CertFingerprint: fp, CertCN: fp, DeviceID: fp, IPAddress: "192.0.2.10",
	}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	rows, err := db.Scoped(ctx).Query(ctx, `SELECT id FROM devices WHERE certificate_fingerprint = $1`, fp)
	if err == nil {
		// Закрыть обязательно: иначе на сломанном коде тест не падает, а вешает весь
		// пакет — соединение из пула остаётся занятым, и следующий тест ждёт его вечно.
		// Красный гейт должен быть красным, а не «висит».
		rows.Close()
	}
	if !errors.Is(err, tenancy.ErrTenantScopeMissing) {
		t.Fatalf("запрос без скоупа: err = %v, want ErrTenantScopeMissing (ушёл в пул?)", err)
	}

	// А под скоупом та же строка находится — иначе тест был бы зелёным просто оттого,
	// что запрос сломан целиком.
	tctx, finish, err := db.BindTenant(ctx, tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("BindTenant: %v", err)
	}
	defer finish(true)
	var id string
	if err := db.Scoped(tctx).QueryRow(tctx,
		`SELECT id FROM devices WHERE certificate_fingerprint = $1`, fp).Scan(&id); err != nil {
		t.Fatalf("под скоупом строка не найдена: %v", err)
	}
	if id == "" {
		t.Error("под скоупом вернулся пустой id")
	}
}

// Синк каталога — тот путь, на котором класс сработал вживую: все пять его обращений
// шли непривязанным контекстом. Проверяем не «сегодня работает», а что тенант доезжает
// до строки: персона обязана лечь в тенанта, который назвал вызывающий.
func TestDirectoryPersonLandsInNamedTenant(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	u := uniq(t)

	p := storage.DirectoryPerson{
		ObjectGUID: "guid-scope-" + u, ObjectSID: "S-1-5-21-scope-" + u,
		SAMAccount: "scoped" + u, DisplayName: "Скоуп Т.",
	}
	if err := db.UpsertDirectoryPerson(ctx, tenancy.DefaultTenantID, p); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := db.ListDirectoryPersons(ctx, tenancy.DefaultTenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, g := range got {
		if g.ObjectGUID == p.ObjectGUID {
			found = true
		}
	}
	if !found {
		t.Error("персона не найдена в тенанте, в который её писали")
	}

	// Пустой тенант — отказ, а не «все». Это то же правило, что у остальных ручек
	// панели (контракт §4), и оно обязано действовать и на путях каталога.
	if err := db.UpsertDirectoryPerson(ctx, "", p); !errors.Is(err, tenancy.ErrTenantScopeMissing) {
		t.Errorf("upsert с пустым тенантом: err = %v, want ErrTenantScopeMissing", err)
	}
	if _, err := db.ListDevicesForDirectoryMatch(ctx, ""); !errors.Is(err, tenancy.ErrTenantScopeMissing) {
		t.Errorf("список на матч с пустым тенантом: err = %v, want ErrTenantScopeMissing", err)
	}
}
