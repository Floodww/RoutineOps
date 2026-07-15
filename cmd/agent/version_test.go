package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/agent/config"
)

func TestPrintVersion(t *testing.T) {
	old := version
	defer func() { version = old }()
	version = "v9.9.9"

	var buf bytes.Buffer
	printVersion(&buf, &config.Config{})
	out := buf.String()

	for _, want := range []string{"RoutineOps-agent v9.9.9", runtime.GOOS, runtime.GOARCH, runtime.Version()} {
		if !strings.Contains(out, want) {
			t.Errorf("вывод version не содержит %q:\n%s", want, out)
		}
	}
}

func TestPrintVersionSelfUpdateFlag(t *testing.T) {
	oldV, oldK, oldDir := version, releasePubKey, installedCertDir
	defer func() { version, releasePubKey, installedCertDir = oldV, oldK, oldDir }()
	// Без изоляции ветка releasePubKey="" случайно нашла бы ключ в реальном
	// /var/lib/RoutineOps-agent/certs на машине разработчика и тест бы флакал.
	installedCertDir = t.TempDir()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// «AAAA» здесь уже нельзя: updateKeyStatus проверяет, что это валидный
	// base64 ed25519 (32 байта), иначе рапортует ВЫКЛЮЧЕНО.
	releasePubKey = base64.StdEncoding.EncodeToString(pub)
	var buf bytes.Buffer
	printVersion(&buf, &config.Config{CAFile: filepath.Join(t.TempDir(), "ca.crt")})
	if !strings.Contains(buf.String(), "self-update: включено") {
		t.Errorf("при вшитом ключе ждали 'включено':\n%s", buf.String())
	}

	releasePubKey = ""
	buf.Reset()
	printVersion(&buf, &config.Config{CAFile: filepath.Join(t.TempDir(), "ca.crt")})
	if !strings.Contains(buf.String(), "ВЫКЛЮЧЕНО") {
		t.Errorf("без ключа ждали 'ВЫКЛЮЧЕНО':\n%s", buf.String())
	}
}

// Регрессия SEC-2 (аудит 2026-07-01): вшитый в релизную сборку ключ должен
// быть авторитетным и НЕ обходиться через -update-pubkey/ROUTINEOPS_UPDATE_PUBKEY —
// иначе локальный админ/поддельный env могли бы подсунуть свой ключ и принять
// произвольный "подписанный" бинарь как обновление.
func TestResolveUpdatePubKeyB64(t *testing.T) {
	old := releasePubKey
	defer func() { releasePubKey = old }()

	releasePubKey = "RELEASE_KEY"
	if got := resolveUpdatePubKeyB64("cfg-override", ""); got != "RELEASE_KEY" {
		t.Errorf("вшитый ключ должен быть авторитетным, got %q", got)
	}

	releasePubKey = ""
	if got := resolveUpdatePubKeyB64("dev-key", ""); got != "dev-key" {
		t.Errorf("без вшитого ключа cfg — валидный dev-override, got %q", got)
	}

	// Универсальный агент: сохранённый при enroll'е ключ приоритетнее cfgKey.
	stored := filepath.Join(t.TempDir(), "release_pubkey")
	if err := os.WriteFile(stored, []byte("STORED_KEY\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := resolveUpdatePubKeyB64("dev-key", stored); got != "STORED_KEY" {
		t.Errorf("сохранённый release-pubkey должен побеждать cfgKey, got %q", got)
	}
}

// TestUpdateKeyStatus — диагностика self-update: ok=false обязан быть ровно тогда,
// когда selfupdate не стартует. Это единственный сигнал о мёртвом обновлении.
func TestUpdateKeyStatus(t *testing.T) {
	oldK, oldDir := releasePubKey, installedCertDir
	defer func() { releasePubKey, installedCertDir = oldK, oldDir }()
	releasePubKey = ""
	installedCertDir = t.TempDir() // изоляция от реального /var/lib/RoutineOps-agent

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := base64.StdEncoding.EncodeToString(pub)

	certDir := t.TempDir()
	cfg := &config.Config{CAFile: filepath.Join(certDir, "ca.crt")}

	// 1. Ключа нет нигде → self-update мёртв, и это ВИДНО.
	if ok, detail := updateKeyStatus(cfg); ok {
		t.Errorf("без ключа ждали ok=false, got true (%s)", detail)
	}

	// 2. Ключ сохранён при enroll'е рядом с CA → включено, в detail есть путь.
	keyPath := filepath.Join(certDir, "release_pubkey")
	if err := os.WriteFile(keyPath, []byte(valid+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, detail := updateKeyStatus(cfg)
	if !ok || !strings.Contains(detail, keyPath) {
		t.Errorf("ключ рядом с CA: ok=%v detail=%q", ok, detail)
	}

	// 3. Битый ключ на диске — тоже мёртвый self-update, а не «включено».
	if err := os.WriteFile(keyPath, []byte("не-base64!!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, _ := updateKeyStatus(cfg); ok {
		t.Errorf("битый ключ должен давать ok=false")
	}

	// 4. Вшитый ключ авторитетнее всего (SEC-2) и виден как «вшит».
	releasePubKey = valid
	if ok, detail := updateKeyStatus(cfg); !ok || !strings.Contains(detail, "вшит") {
		t.Errorf("вшитый ключ: ok=%v detail=%q", ok, detail)
	}
}

// Фолбэк на CertDir службы: агент, заэнролленный ДО фикса раскладки, оставил ключ в
// enroll-каталоге; после переустановки бинаря он обязан подхватиться из CertDir.
func TestReleaseKeyCandidates_FallsBackToInstalledCertDir(t *testing.T) {
	oldDir := installedCertDir
	defer func() { installedCertDir = oldDir }()
	installedCertDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(installedCertDir, "release_pubkey"),
		[]byte("STORED"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{CAFile: filepath.Join(t.TempDir(), "ca.crt")} // рядом с CA ключа нет
	if got := resolveUpdatePubKeyB64("", releaseKeyCandidates(cfg)...); got != "STORED" {
		t.Errorf("фолбэк на CertDir не сработал: got %q", got)
	}
}
