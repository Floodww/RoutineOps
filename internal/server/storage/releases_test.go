package storage_test

import (
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Версия НЕИЗМЕНЯЕМА: под одним (os,arch,version) байты закрепляются первой публикацией.
// Три исхода повторной публикации:
//   - тот же sha256, другой канал → ПРОДВИЖЕНИЕ (меняется только канал, байты/подпись те же);
//   - тот же sha256, тот же канал → идемпотентно (ретрай update.sh после сбоя одной платформы
//     не роняет весь публиш; повтор того же коммита под -trimpath даёт тот же бинарь);
//   - другой sha256 → ОТКАЗ, а не тихая подмена содержимого под тем же номером.
func TestRegisterAgentRelease_VersionImmutable(t *testing.T) {
	db := newDB(t)
	ctx := tenantCtx()
	osName := "testos" + uniq(t) // уникальный os → GetLatest вернёт только нашу строку
	arch := "amd64"
	ver := "v1.0.0"

	// Первая публикация — в beta (канарейка).
	if err := db.RegisterAgentRelease(ctx, osName, arch, ver, "agent_v1", "sha_A", "sig_A", "msig_A", storage.ChannelBeta); err != nil {
		t.Fatalf("первая публикация: %v", err)
	}

	// Продвижение: та же версия, ТОТ ЖЕ sha256, канал stable. Законная мутация — только канал.
	if err := db.RegisterAgentRelease(ctx, osName, arch, ver, "agent_v1", "sha_A", "sig_A", "msig_A", storage.ChannelStable); err != nil {
		t.Fatalf("продвижение (тот же sha256, новый канал) обязано проходить, получили: %v", err)
	}
	rel, err := db.GetLatestAgentRelease(ctx, osName, arch) // GetLatest = канал stable
	if err != nil || rel == nil {
		t.Fatalf("после продвижения строка не видна в stable: rel=%v err=%v", rel, err)
	}
	if rel.Channel != storage.ChannelStable {
		t.Fatalf("канал = %q, ожидали stable — продвижение не сменило канал", rel.Channel)
	}
	if rel.SHA256 != "sha_A" || rel.Filename != "agent_v1" {
		t.Fatalf("продвижение тронуло байты: sha=%q filename=%q", rel.SHA256, rel.Filename)
	}

	// Перевыпуск с ДРУГИМ sha256 под той же версией — отказ, а не upsert.
	err = db.RegisterAgentRelease(ctx, osName, arch, ver, "agent_v1_relabel", "sha_B", "sig_B", "msig_B", storage.ChannelStable)
	if err == nil {
		t.Fatal("перевыпуск с другим sha256 под тем же номером обязан быть отказом, а не тихой подменой")
	}
	if !strings.Contains(err.Error(), "неизменяем") {
		t.Fatalf("отказ должен объяснять причину (неизменяемость версии), получили: %v", err)
	}

	// И содержимое осталось прежним — подмена не просочилась.
	rel, err = db.GetLatestAgentRelease(ctx, osName, arch)
	if err != nil || rel == nil {
		t.Fatalf("строка пропала после отклонённого перевыпуска: rel=%v err=%v", rel, err)
	}
	if rel.SHA256 != "sha_A" || rel.Filename != "agent_v1" {
		t.Fatalf("отклонённый перевыпуск всё же подменил байты: sha=%q filename=%q", rel.SHA256, rel.Filename)
	}
}
