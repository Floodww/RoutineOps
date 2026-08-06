package storage_test

import (
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Повторная публикация той же (os,arch,version) должна быть идемпотентной (UPSERT),
// а не падать на UNIQUE(os,arch,version): повтор update.sh / ретрай после сбоя сборки
// одной из платформ не должен ронять весь публиш. Артефакт/подписи при этом обновляются
// (пересобранный бинарь той же версии).
func TestRegisterAgentRelease_Idempotent(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	osName := "testos" + uniq(t) // уникальный os → GetLatest вернёт только нашу строку
	arch := "amd64"
	ver := "v1.0.0"

	if err := db.RegisterAgentRelease(ctx, osName, arch, ver, "agent_old", "sha_old", "sig_old", "msig_old", storage.ChannelStable); err != nil {
		t.Fatalf("первый register: %v", err)
	}
	// та же версия, новый артефакт — НЕ ошибка
	if err := db.RegisterAgentRelease(ctx, osName, arch, ver, "agent_new", "sha_new", "sig_new", "msig_new", storage.ChannelStable); err != nil {
		t.Fatalf("повторный register той же версии обязан быть идемпотентным, получили: %v", err)
	}

	rel, err := db.GetLatestAgentRelease(ctx, osName, arch)
	if err != nil {
		t.Fatalf("GetLatestAgentRelease: %v", err)
	}
	if rel == nil {
		t.Fatal("релиз не найден после register")
	}
	if rel.Version != ver {
		t.Fatalf("version = %q, ожидали %q", rel.Version, ver)
	}
	// UPSERT обновил артефакт/подпись, не создал дубль
	if rel.Filename != "agent_new" || rel.SHA256 != "sha_new" ||
		rel.Signature != "sig_new" || rel.ManifestSignature != "msig_new" {
		t.Fatalf("UPSERT не обновил артефакт: filename=%q sha=%q sig=%q msig=%q",
			rel.Filename, rel.SHA256, rel.Signature, rel.ManifestSignature)
	}
}
