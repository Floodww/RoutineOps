package storage_test

import (
	"testing"
)

// После ADR-7 надзор — признак личности, а не роль в тенанте, и на чистой установке
// его стало неоткуда взять: сид-админ заводится обычным it_admin, а создание тенанта
// уже под requireProviderAdmin. Полевой e2e 30.07 упёрся в это на проде.
//
// Лечение — выдавать флаг бутстрап-личности. Тест держит именно ГРАНИЦУ: флаг даётся,
// только когда личность в инсталляции одна. Дефолт `true` для всех был бы эскалацией
// привилегий — любой приглашённый viewer стал бы надзорным над всей инсталляцией.
func TestPromoteBootstrapProviderAdmin_OnlyWhenSoleIdentity(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()

	// Предусловие создаём сами, а не полагаемся на состояние общей тестовой БД:
	// тест, который пропускается при «неудобных» данных, не доказывает ничего.
	other := "bootstrap-other-" + uniq(t) + "@test.local"
	if _, _, err := db.EnsureIdentity(ctx, other, "hash"); err != nil {
		t.Fatalf("EnsureIdentity (соседняя личность): %v", err)
	}
	email := "bootstrap-" + uniq(t) + "@test.local"
	if _, _, err := db.EnsureIdentity(ctx, email, "hash"); err != nil {
		t.Fatalf("EnsureIdentity: %v", err)
	}

	var count int
	if err := db.Pool().QueryRow(ctx, `SELECT count(*) FROM identities`).Scan(&count); err != nil {
		t.Fatalf("счёт личностей: %v", err)
	}
	if count < 2 {
		t.Fatalf("личностей %d — предусловие теста не выполнено", count)
	}

	granted, err := db.PromoteBootstrapProviderAdmin(ctx, email)
	if err != nil {
		t.Fatalf("PromoteBootstrapProviderAdmin: %v", err)
	}
	if granted {
		t.Fatal("надзор выдан личности на НЕпустой инсталляции — это эскалация привилегий")
	}

	var isProvider bool
	if err := db.Pool().QueryRow(ctx,
		`SELECT is_provider_admin FROM identities WHERE lower(email) = lower($1)`, email).Scan(&isProvider); err != nil {
		t.Fatalf("чтение флага: %v", err)
	}
	if isProvider {
		t.Fatal("is_provider_admin=true в БД, хотя выдача не подтверждена")
	}

	// Несуществующий e-mail — не ошибка, просто «не выдано».
	if granted, err := db.PromoteBootstrapProviderAdmin(ctx, "nobody-"+uniq(t)+"@test.local"); err != nil || granted {
		t.Fatalf("для несуществующей личности ждали (false, nil), получили (%v, %v)", granted, err)
	}
}
