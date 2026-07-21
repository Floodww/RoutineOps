package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/Floodww/RoutineOps/internal/agent/config"
	"github.com/Floodww/RoutineOps/internal/agent/service"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// applyStatePaths переводит в DataDir только пути, оставшиеся на дефолтах;
// явно заданный оператором путь не трогается.
func TestApplyStatePaths_RebasesDefaultsOnly(t *testing.T) {
	lay := service.Layout{DataDir: filepath.FromSlash("/data")}
	custom := filepath.FromSlash("/custom/forbidden.txt")
	cfg := &config.Config{
		OutboxDir:          config.DefaultOutboxDir,
		TaskStateFile:      config.DefaultTaskStateFile,
		ScriptDedupFile:    config.DefaultScriptDedupFile,
		ForbiddenListFile:  custom, // задан явно — уважаем
		UpdateFloorFile:    config.DefaultUpdateFloorFile,
		FilevaultEscrowDir: config.DefaultFilevaultEscrowDir,
	}
	applyStatePaths(cfg, lay)

	want := map[string]string{
		cfg.OutboxDir:          filepath.Join(lay.DataDir, "outbox"),
		cfg.TaskStateFile:      filepath.Join(lay.DataDir, "tasks.seen"),
		cfg.ScriptDedupFile:    filepath.Join(lay.DataDir, "scripts.seen"),
		cfg.UpdateFloorFile:    filepath.Join(lay.DataDir, "update_floor.txt"),
		cfg.FilevaultEscrowDir: filepath.Join(lay.DataDir, "filevault_escrow"),
	}
	for got, exp := range want {
		if got != exp {
			t.Errorf("путь = %q, ожидался %q", got, exp)
		}
	}
	if cfg.ForbiddenListFile != custom {
		t.Errorf("явно заданный путь перезаписан: %q", cfg.ForbiddenListFile)
	}
}

// migrateLegacyState переносит состояние прежней установки по маппингу имён,
// не затирает уже существующее на новом месте и идемпотентен.
func TestMigrateLegacyState_MovesRenamesAndKeepsNewer(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	writeFile := func(dir, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(src, config.DefaultTaskStateFile, "old-tasks")
	writeFile(src, config.DefaultUpdateFloorFile, "2.4.1")
	writeFile(src, config.DefaultForbiddenListFile, "evil.exe")
	writeFile(src, "security_alerted.seen", "episode-1")
	if err := os.MkdirAll(filepath.Join(src, config.DefaultOutboxDir), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(filepath.Join(src, config.DefaultOutboxDir), "0001-entry.json", "{}")

	cfg := &config.Config{
		OutboxDir:         filepath.Join(dst, "outbox"),
		TaskStateFile:     filepath.Join(dst, "tasks.seen"),
		ScriptDedupFile:   filepath.Join(dst, "scripts.seen"),
		UpdateFloorFile:   filepath.Join(dst, "update_floor.txt"),
		ForbiddenListFile: filepath.Join(dst, "forbidden_software.txt"),
	}
	// На новом месте уже есть свежий tasks.seen — перенос не должен его затереть.
	writeFile(dst, "tasks.seen", "new-tasks")

	migrateLegacyState(src, cfg, discardLog())

	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("чтение %s: %v", path, err)
		}
		return string(b)
	}
	if got := read(cfg.TaskStateFile); got != "new-tasks" {
		t.Errorf("tasks.seen затёрт переносом: %q (новое состояние главнее)", got)
	}
	if _, err := os.Stat(filepath.Join(src, config.DefaultTaskStateFile)); !os.IsNotExist(err) {
		t.Errorf("устаревший источник tasks.seen должен быть убран при занятом назначении (err=%v)", err)
	}
	if got := read(cfg.UpdateFloorFile); got != "2.4.1" {
		t.Errorf("update_floor = %q, ожидался перенос 2.4.1", got)
	}
	if got := read(cfg.ForbiddenListFile); got != "evil.exe" {
		t.Errorf("forbidden-list = %q, ожидался перенос", got)
	}
	if got := read(filepath.Join(dst, "security_alerted.seen")); got != "episode-1" {
		t.Errorf("security_alerted.seen = %q, ожидался перенос рядом со списком", got)
	}
	if got := read(filepath.Join(cfg.OutboxDir, "0001-entry.json")); got != "{}" {
		t.Errorf("запись outbox не переехала: %q", got)
	}
	for _, name := range []string{config.DefaultUpdateFloorFile, config.DefaultForbiddenListFile, config.DefaultOutboxDir} {
		if _, err := os.Stat(filepath.Join(src, name)); !os.IsNotExist(err) {
			t.Errorf("источник %s должен исчезнуть после переноса (err=%v)", name, err)
		}
	}

	// Повторный вызов — no-op: перенесённое не трогается, ошибок нет.
	writeFile(dst, "update_floor.txt", "2.4.2")
	migrateLegacyState(src, cfg, discardLog())
	if got := read(cfg.UpdateFloorFile); got != "2.4.2" {
		t.Errorf("повторная миграция перезаписала состояние: %q", got)
	}
}

// Отсутствующий источник (свежая установка) — тихий no-op.
func TestMigrateLegacyState_NoSource(t *testing.T) {
	dst := t.TempDir()
	cfg := &config.Config{TaskStateFile: filepath.Join(dst, "tasks.seen")}
	migrateLegacyState(filepath.Join(dst, "нет-такого"), cfg, discardLog())
	migrateLegacyState("", cfg, discardLog())
	if _, err := os.Stat(cfg.TaskStateFile); !os.IsNotExist(err) {
		t.Errorf("миграция без источника не должна создавать файлы (err=%v)", err)
	}
}
