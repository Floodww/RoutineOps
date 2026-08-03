package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// signedManifest строит корректный manifest для бинаря data, подписанный priv
// (manifest_signature покрывает канон version\nos\narch\nsha256, см. signedMessage;
// os/arch — текущей машины, т.к. verify() их тоже берёт из runtime.GOOS/GOARCH).
func signedManifest(version string, data []byte, priv ed25519.PrivateKey) *Manifest {
	sum := sha256.Sum256(data)
	m := &Manifest{
		Version: version,
		URL:     "https://example/agent",
		SHA256:  hex.EncodeToString(sum[:]),
	}
	m.ManifestSignature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(priv, signedMessage(m, runtime.GOOS, runtime.GOARCH)))
	return m
}

// harness собирает Updater с подменёнными сеймами и счётчиками применений.
type harness struct {
	u        *Updater
	applied  [][]byte
	restarts int
}

func newHarness(t *testing.T, current string, pub ed25519.PublicKey, m *Manifest, bin []byte) *harness {
	t.Helper()
	h := &harness{}
	h.u = &Updater{
		current:  current,
		pubKey:   pub,
		log:      discardLog(),
		check:    func(context.Context) (*Manifest, error) { return m, nil },
		download: func(context.Context, string) ([]byte, error) { return bin, nil },
		replace:  func(data []byte) error { h.applied = append(h.applied, data); return nil },
		restart:  func() { h.restarts++ },
	}
	return h
}

func TestApplyWhenNewerAndSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("НОВЫЙ-БИНАРЬ-АГЕНТА")
	m := signedManifest("v1.1.0", bin, priv)
	h := newHarness(t, "v1.0.0", pub, m, bin)

	if err := h.u.checkAndApply(context.Background()); err != nil {
		t.Fatalf("checkAndApply: %v", err)
	}
	if len(h.applied) != 1 || string(h.applied[0]) != string(bin) {
		t.Fatalf("бинарь не применён корректно: %v", h.applied)
	}
	if h.restarts != 1 {
		t.Fatalf("ожидали 1 рестарт, got %d", h.restarts)
	}
}

func TestSkipWhenNotNewer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("x")
	m := signedManifest("v1.0.0", bin, priv) // та же версия
	h := newHarness(t, "v1.0.0", pub, m, bin)

	if err := h.u.checkAndApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 0 || h.restarts != 0 {
		t.Fatalf("не должны были обновляться: applied=%d restarts=%d", len(h.applied), h.restarts)
	}
}

func TestRejectBadSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader) // НЕ тот ключ, что подписал
	bin := []byte("вредоносный-бинарь")
	m := signedManifest("v1.1.0", bin, priv)
	h := newHarness(t, "v1.0.0", otherPub, m, bin) // агент доверяет другому ключу

	if err := h.u.checkAndApply(context.Background()); err == nil {
		t.Fatal("ожидали отказ по подписи")
	}
	if len(h.applied) != 0 || h.restarts != 0 {
		t.Fatal("бинарь с невалидной подписью НЕ должен применяться")
	}
}

func TestRejectTamperedBinary(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("оригинал")
	m := signedManifest("v1.1.0", bin, priv)
	tampered := []byte("подменён-в-пути") // sha256 не совпадёт с manifest
	h := newHarness(t, "v1.0.0", pub, m, tampered)

	if err := h.u.checkAndApply(context.Background()); err == nil {
		t.Fatal("ожидали отказ по sha256")
	}
	if len(h.applied) != 0 {
		t.Fatal("повреждённый бинарь НЕ должен применяться")
	}
}

// TestRejectRelabeledVersion — регрессия SEC-3 (аудит 2026-07-01): подпись
// покрывает весь манифест (version+url+sha256), а не только sha256 бинаря.
// Если бы подписывался только sha256, злоумышленник/скомпрометированный сервер
// мог бы взять СТАРЫЙ валидно подписанный бинарь и подсунуть его под ЛЮБОЙ
// версией (в т.ч. выше текущей) — агент принял бы устаревший (потенциально
// уязвимый) бинарь как "новее". Проверяем, что одна лишь смена version в уже
// подписанном манифесте ломает подпись.
func TestRejectRelabeledVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("старый-но-валидно-подписанный-бинарь")
	m := signedManifest("v1.1.0", bin, priv)
	m.Version = "v9.9.9" // релейбл ПОСЛЕ подписи — подпись её не покрывала бы, будь она только над sha256

	h := newHarness(t, "v1.0.0", pub, m, bin)
	if err := h.u.checkAndApply(context.Background()); err == nil {
		t.Fatal("ожидали отказ: version изменена после подписи манифеста")
	}
	if len(h.applied) != 0 {
		t.Fatal("релейбленный манифест НЕ должен применяться")
	}
}

// TestAntiRollbackFloor — регрессия SEC-3: high-water mark не даёт применить
// манифест ниже уже когда-либо применённой версии, даже если он валидно подписан
// (сценарий: бинарь на диске откатили вручную до v1.0.0, но устройство уже когда-то
// успешно обновлялось до v2.0.0 — реплей состарившегося v1.5.0-манифеста не должен
// пройти, хотя v1.5.0 формально новее ТЕКУЩЕГО v1.0.0).
func TestAntiRollbackFloor(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	floorFile := filepath.Join(t.TempDir(), "floor.txt")
	if err := os.WriteFile(floorFile, []byte("v2.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}

	bin := []byte("состарившийся-бинарь")
	m := signedManifest("v1.5.0", bin, priv) // новее current, но НЕ новее floor

	var applied int
	u := &Updater{
		current:   "v1.0.0",
		pubKey:    pub,
		floorFile: floorFile,
		log:       discardLog(),
		check:     func(context.Context) (*Manifest, error) { return m, nil },
		download:  func(context.Context, string) ([]byte, error) { return bin, nil },
		replace:   func([]byte) error { applied++; return nil },
		restart:   func() {},
	}
	if err := u.checkAndApply(context.Background()); err != nil {
		t.Fatalf("checkAndApply: %v", err)
	}
	if applied != 0 {
		t.Fatal("манифест ниже high-water mark НЕ должен применяться")
	}
}

// TestFloorPersistsAfterApply: успешное применение обновления поднимает
// high-water mark на диске — следующая проверка сравнивается уже с ним.
func TestFloorPersistsAfterApply(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	floorFile := filepath.Join(t.TempDir(), "floor.txt")
	bin := []byte("новый-бинарь")
	m := signedManifest("v2.0.0", bin, priv)

	u := &Updater{
		current:   "v1.0.0",
		pubKey:    pub,
		floorFile: floorFile,
		log:       discardLog(),
		check:     func(context.Context) (*Manifest, error) { return m, nil },
		download:  func(context.Context, string) ([]byte, error) { return bin, nil },
		replace:   func([]byte) error { return nil },
		restart:   func() {},
	}
	if err := u.checkAndApply(context.Background()); err != nil {
		t.Fatalf("checkAndApply: %v", err)
	}
	got, err := os.ReadFile(floorFile)
	if err != nil {
		t.Fatalf("floor не персистнулся: %v", err)
	}
	if string(got) != "v2.0.0" {
		t.Fatalf("floor = %q, хотим v2.0.0", got)
	}
}

// TestRejectDowngrade: сервер предлагает ВЕРСИЮ СТАРШЕ текущей — агент не должен
// откатываться (защита от форс-даунгрейда скомпрометированным сервером).
func TestRejectDowngrade(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("старый-бинарь")
	m := signedManifest("v1.0.0", bin, priv) // подпись валидна, но версия старее
	h := newHarness(t, "v2.0.0", pub, m, bin)

	if err := h.u.checkAndApply(context.Background()); err != nil {
		t.Fatalf("checkAndApply: %v", err)
	}
	if len(h.applied) != 0 || h.restarts != 0 {
		t.Fatalf("даунгрейд не должен применяться: applied=%d restarts=%d", len(h.applied), h.restarts)
	}
}

// TestNoRestartWhenReplaceFails: если замена бинаря провалилась, агент НЕ
// перезапускается (остаётся работать на старом бинаре — atomic rename оставил его
// нетронутым) и возвращает ошибку.
func TestNoRestartWhenReplaceFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("новый-бинарь")
	m := signedManifest("v1.1.0", bin, priv)

	var restarts int
	u := &Updater{
		current:  "v1.0.0",
		pubKey:   pub,
		log:      discardLog(),
		check:    func(context.Context) (*Manifest, error) { return m, nil },
		download: func(context.Context, string) ([]byte, error) { return bin, nil },
		replace:  func([]byte) error { return errors.New("диск переполнен") },
		restart:  func() { restarts++ },
	}
	err := u.checkAndApply(context.Background())
	if err == nil {
		t.Fatal("ожидали ошибку при сбое замены")
	}
	if restarts != 0 {
		t.Fatalf("перезапуск не должен происходить при неудачной замене (restarts=%d)", restarts)
	}
}

// TestOnReplaceFailHook: сбой замены дёргает OnReplaceFail (Windows поднимает трей,
// убитый taskkill'ом ДО падения замены), успешная замена — НЕ дёргает.
func TestOnReplaceFailHook(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("новый-бинарь")
	m := signedManifest("v1.1.0", bin, priv)

	newU := func(replaceErr error, fired *int) *Updater {
		return &Updater{
			current:       "v1.0.0",
			pubKey:        pub,
			log:           discardLog(),
			check:         func(context.Context) (*Manifest, error) { return m, nil },
			download:      func(context.Context, string) ([]byte, error) { return bin, nil },
			replace:       func([]byte) error { return replaceErr },
			restart:       func() {},
			OnReplaceFail: func() { *fired++ },
		}
	}

	var fired int
	if err := newU(errors.New("AV держит файл"), &fired).checkAndApply(context.Background()); err == nil {
		t.Fatal("ожидали ошибку при сбое замены")
	}
	if fired != 1 {
		t.Fatalf("OnReplaceFail при сбое замены: вызовов=%d, хотим 1", fired)
	}

	fired = 0
	if err := newU(nil, &fired).checkAndApply(context.Background()); err != nil {
		t.Fatalf("checkAndApply: %v", err)
	}
	if fired != 0 {
		t.Fatalf("OnReplaceFail при успешной замене вызываться не должен (вызовов=%d)", fired)
	}
}

// TestInvalidManifestVersion: непарсибельная версия в manifest → ошибка сравнения,
// ничего не применяется.
func TestInvalidManifestVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := []byte("x")
	m := signedManifest("не-семвер", bin, priv)
	h := newHarness(t, "v1.0.0", pub, m, bin)

	if err := h.u.checkAndApply(context.Background()); err == nil {
		t.Fatal("ожидали ошибку на непарсибельной версии manifest")
	}
	if len(h.applied) != 0 || h.restarts != 0 {
		t.Fatalf("ничего не должно применяться: applied=%d restarts=%d", len(h.applied), h.restarts)
	}
}

func TestRunDisabledForDevAndNoKey(t *testing.T) {
	// dev-сборка — Run выходит сразу (не паникует, ничего не качает).
	u := New("dev", time.Hour, make(ed25519.PublicKey, ed25519.PublicKeySize), "http://x", "", "", func() {}, discardLog())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	u.Run(ctx) // должен мгновенно вернуться

	// Пустой ключ — тоже выключено.
	u2 := New("v1.0.0", time.Hour, nil, "http://x", "", "", func() {}, discardLog())
	u2.Run(ctx)
}
