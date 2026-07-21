// Перенос изменяемого состояния агента из каталогов прежних установок в
// машинный каталог данных (Windows). До появления DataDir в раскладке Windows
// (layout_windows.go) относительные дефолты путей резолвились от CWD службы —
// C:\Windows\System32, и туда уезжал весь mutable-state: outbox, seen-файлы,
// forbidden-list, floor самообновления.
package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Floodww/RoutineOps/internal/agent/config"
)

// legacyStateDir — каталог, от которого резолвились относительные дефолты у
// прежних установок Windows-службы: CWD службы под SCM, то есть
// %SystemRoot%\System32. Пусто = переносить неоткуда (не-Windows).
func legacyStateDir() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32")
}

// migrateLegacyState разово переносит состояние прежней установки из srcDir в
// новые пути cfg (уже переведённые applyStatePaths). Вызывается ТОЛЬКО после
// успешного service.EnsureDataDir, т.е. каталог назначения гарантированно
// защищён admin-only DACL.
//
// Перенос — КОПИРОВАНИЕ содержимого в СВЕЖИЙ файл под защищённым каталогом (не
// os.Rename): свежесозданный объект наследует admin-only OICI-DACL от state, а
// rename/MoveFileEx сохранил бы исходный ACL из System32 (где Users обычно имеют
// чтение) — тогда мигрированный forbidden-list/outbox остался бы читаемым
// сотрудником. Копирование заодно работает через границу тома (rename — нет) и
// идемпотентно per-file: сбой на одном файле не блокирует остальные и
// повторяется на следующем старте.
//
// Переносится ВЕСЬ loss-sensitive state, а не минимум:
//   - outbox — недоставленные алерты ИБ, аудит прав, результаты скриптов/задач;
//   - tasks.seen / scripts.seen — иначе редоставленная задача выполнится дважды,
//     а on_connect-политики перезапустятся;
//   - update_floor — иначе теряется anti-replay-пол самообновления (SEC-3);
//   - forbidden-list — иначе Security Monitor слепнет до ближайшего FetchPolicy;
//   - security_alerted.seen — дедуп эпизодов живёт ТОЛЬКО на агенте, без него
//     флот перевыстрелит уже отрапортованными алертами.
//
// Идемпотентно: источника нет — пропуск; на новом месте файл уже есть — новое
// главнее, а устаревший источник удаляется (не копим мусор в System32).
func migrateLegacyState(srcDir string, cfg *config.Config, log *slog.Logger) {
	if srcDir == "" {
		return
	}
	if _, err := os.Stat(srcDir); err != nil {
		return
	}
	files := []struct{ from, to string }{
		{config.DefaultTaskStateFile, cfg.TaskStateFile},
		{config.DefaultScriptDedupFile, cfg.ScriptDedupFile},
		{config.DefaultUpdateFloorFile, cfg.UpdateFloorFile},
		{config.DefaultForbiddenListFile, cfg.ForbiddenListFile},
		// Имя файла — контракт security.Monitor (метод stateFile): живёт рядом
		// с forbidden-list и следует за ним.
		{"security_alerted.seen", filepath.Join(filepath.Dir(cfg.ForbiddenListFile), "security_alerted.seen")},
	}
	for _, m := range files {
		migrateFile(filepath.Join(srcDir, m.from), m.to, log)
	}
	// outbox — каталог: переносим per-entry, чтобы единичный сбой (AV держит
	// хэндл, и т.п.) не «застрял» навсегда из-за того, что каталог назначения к
	// следующему старту уже создан пустым (его создаёт outbox.New).
	migrateDir(filepath.Join(srcDir, config.DefaultOutboxDir), cfg.OutboxDir, log)
}

// migrateFile переносит один файл из from в to копированием в свежий объект.
func migrateFile(from, to string, log *slog.Logger) {
	if to == "" || from == to {
		return
	}
	if _, err := os.Stat(from); err != nil {
		return // нечего переносить
	}
	if _, err := os.Stat(to); err == nil {
		// На новом месте уже есть состояние — оно главнее; устаревший источник
		// убираем, чтобы не проверять его на каждом старте и не оставлять в System32.
		if err := os.Remove(from); err != nil {
			log.Warn("state: не удалось убрать устаревший источник", slog.String("from", from), slog.Any("error", err))
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		log.Warn("state: не удалось создать каталог назначения", slog.String("to", to), slog.Any("error", err))
		return
	}
	if err := copyFresh(from, to); err != nil {
		log.Warn("state: не удалось перенести файл из прежнего каталога",
			slog.String("from", from), slog.String("to", to), slog.Any("error", err))
		return
	}
	if err := os.Remove(from); err != nil {
		log.Warn("state: файл перенесён, но источник не удалён", slog.String("from", from), slog.Any("error", err))
	}
	log.Info("state: перенесён файл из каталога прежней установки", slog.String("from", from), slog.String("to", to))
}

// migrateDir переносит содержимое каталога fromDir в toDir per-entry (outbox —
// плоский каталог файлов-записей). Каталог назначения создаётся заранее и
// наследует admin-only DACL; каждая запись копируется в свежий файл.
func migrateDir(fromDir, toDir string, log *slog.Logger) {
	if toDir == "" || fromDir == toDir {
		return
	}
	entries, err := os.ReadDir(fromDir)
	if err != nil {
		return // прежнего каталога нет — переносить нечего
	}
	if err := os.MkdirAll(toDir, 0o700); err != nil {
		log.Warn("state: не удалось создать каталог назначения outbox", slog.String("to", toDir), slog.Any("error", err))
		return
	}
	var moved, kept int
	for _, e := range entries {
		if e.IsDir() {
			continue // outbox плоский; вложенные каталоги не наши — не трогаем
		}
		from := filepath.Join(fromDir, e.Name())
		to := filepath.Join(toDir, e.Name())
		if _, err := os.Stat(to); err == nil {
			if err := os.Remove(from); err != nil {
				kept++
			}
			continue // запись с этим именем уже на новом месте
		}
		if err := copyFresh(from, to); err != nil {
			log.Warn("state: не удалось перенести запись outbox",
				slog.String("from", from), slog.String("to", to), slog.Any("error", err))
			kept++
			continue
		}
		if err := os.Remove(from); err != nil {
			kept++
		}
		moved++
	}
	// Каталог-источник убираем, только если он полностью опустошён (иначе
	// os.Remove на непустом откажет — оставим на следующий старт).
	if kept == 0 {
		_ = os.Remove(fromDir)
	}
	if moved > 0 {
		log.Info("state: перенесён outbox из каталога прежней установки",
			slog.String("from", fromDir), slog.String("to", toDir), slog.Int("entries", moved))
	}
}

// copyFresh копирует src в СВЕЖИЙ файл dst (через dst.tmp + rename в том же
// каталоге — атомарно, наследует ACL каталога назначения). Свежий объект под
// защищённым state получает admin-only DACL по наследованию; частичная копия при
// сбое остаётся как .tmp и не выдаёт себя за готовый dst.
func copyFresh(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".migrate.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
