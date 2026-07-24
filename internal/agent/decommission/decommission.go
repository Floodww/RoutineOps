// Package decommission выполняет полное самоудаление агента по авторизованной
// команде сервера (вывод устройства из эксплуатации): снимает службу и
// tamper-защиту, удаляет mTLS-материал, конфиг и всё изменяемое состояние, затем
// удаляет собственный бинарь (на Windows — отложенно, запущенный .exe удалить
// нельзя).
//
// Контракт вызова (см. executor.handleDecommission и cmd/agent):
//   - Run вызывается ТОЛЬКО после того, как агент подтвердил приём серверу
//     (ReportTaskResult) — иначе, сняв серт, отчитаться будет уже нечем;
//   - и ТОЛЬКО когда рабочий цикл агента остановлен (heartbeat/outbox/reporter
//     уже не пишут), чтобы не гонки с writer'ами состояния.
//
// Авторизованный серверный путь сознательно обходит модель tamper «снять можно
// только из Safe Mode»: та защищает от ЛОКАЛЬНОГО пользователя, а команда пришла
// по mTLS от доверенного сервера — легитимный владелец устройства.
package decommission

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// errUnsafeDir — removeDirSafe ОТКАЗАЛСЯ трогать каталог по соображениям
// безопасности (корневой/системный путь или reparse-точка/симлинк). Это
// ТЕРМИНАЛЬНЫЙ отказ, а НЕ транзиентный сбой удаления: такой путь НЕЛЬЗЯ
// добавлять в leftover, иначе отложенный делетер (rmdir /s /q // os.RemoveAll)
// снёс бы ровно то, от чего removeDirSafe защищал — обход собственной защиты.
var errUnsafeDir = errors.New("decommission: небезопасный каталог, удаление отклонено")

// Plan описывает, что удалить. Пути известны только cmd/agent (из config+layout),
// поэтому собираются там и передаются сюда — пакет их сам не выводит.
type Plan struct {
	// Files — конкретные файлы: серт, приватный ключ, CA, lock.json, status.json,
	// admin-request.json, *.seen, forbidden_software.txt, update_floor.txt.
	Files []string
	// Dirs — каталоги состояния целиком (outbox, машинный DataDir).
	Dirs []string
	// BinPath — стабильный путь к бинарю службы. Удаляется последним/отложенно.
	BinPath string
}

// Hooks — сервисные/tamper-операции, инъектируются из cmd/agent, чтобы пакет не
// тянул service/tamper и тестировался с фейками. nil-хук пропускается.
type Hooks struct {
	StopService  func() error // снять службу (service.Uninstall)
	DisarmTamper func()       // снять tamper (Windows Cleanup; macOS Disarm+Unlock)
	// PurgeKeystore удаляет идентичность (cert + приватный ключ) из хранилища ОС
	// (Keychain/Cert Store). Ставится только при cert-source=keystore: там
	// идентичность живёт вне файлов и файловый план её не достаёт. nil — режим file.
	PurgeKeystore func() error
}

// Run выполняет teardown. Возвращает ошибку только планирования отложенного
// удаления бинаря — остальные шаги best-effort (device всё равно списывается,
// частичный остаток добьёт отложенный делетер / переустановка ОС), их провалы
// логируются, но не прерывают снос: остановиться на полпути хуже, чем доснести.
func Run(plan Plan, hooks Hooks, log *slog.Logger) error {
	if hooks.DisarmTamper != nil {
		hooks.DisarmTamper()
	}
	// Снятие службы. На Windows/Linux безопасно ЗДЕСЬ, до удаления файлов: SCM-стоп
	// кооперативен, systemd шлёт SIGTERM с grace-периодом — процесс успевает
	// доснести. На macOS launchctl bootout шлёт SIGKILL самому процессу-демону,
	// который И выполняет снос: сделай снятие тут — teardown оборвётся на середине,
	// а сервер уже получил SUCCESS. Поэтому на darwin stopServiceEarly — no-op, а
	// службу снимает scheduleSelfDelete САМЫМ ПОСЛЕДНИМ шагом (см. selfdelete_darwin).
	stopServiceEarly(hooks.StopService, log)
	// Идентичность в хранилище ОС — пока процесс ещё привилегирован и до удаления
	// файлов/бинаря. Best-effort: остаточный ключевой материал на списанном железе —
	// вопрос гигиены, доступа он не даёт (сервер режет decommissioned на границе).
	if hooks.PurgeKeystore != nil {
		if err := hooks.PurgeKeystore(); err != nil {
			log.Warn("decommission: чистка идентичности в хранилище ОС не удалась — продолжаю снос", slog.Any("error", err))
		}
	}

	for _, f := range plan.Files {
		removeFile(f, log)
	}
	var leftover []string
	for _, d := range plan.Dirs {
		if err := removeDirSafe(d, log); err != nil {
			if errors.Is(err, errUnsafeDir) {
				// Отказ по безопасности терминален — НЕ передаём делетеру (иначе он
				// снёс бы небезопасный/подменённый путь в обход этой же защиты).
				continue
			}
			// Реальный сбой удаления (открытые хэндлы на Windows) — добьёт делетер.
			leftover = append(leftover, d)
		}
	}

	log.Warn("decommission: агент удаляет себя по команде сервера",
		slog.String("bin", plan.BinPath), slog.Int("leftover_dirs", len(leftover)))
	// hooks.StopService прокидываем в scheduleSelfDelete: на macOS он вызывается там
	// ПОСЛЕДНИМ (bootout убивает нас), на Windows/Linux уже отработал в
	// stopServiceEarly и здесь игнорируется.
	return scheduleSelfDelete(plan.BinPath, leftover, hooks.StopService, log)
}

// removeFile удаляет один файл. Отсутствие — не ошибка (агент мог не создать его).
func removeFile(path string, log *slog.Logger) {
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Warn("decommission: не удалить файл", slog.String("path", path), slog.Any("error", err))
	}
}

// removeDirSafe удаляет каталог целиком, отказываясь от опасных путей и
// reparse-точек/симлинков (иначе RemoveAll под привилегиями агента мог бы уехать
// по подложенному junction в чужой каталог — тот же вектор, что закрыт в
// service.RemoveLegacyArtifacts и EnsureDataDir).
func removeDirSafe(path string, log *slog.Logger) error {
	if path == "" {
		return nil
	}
	if isDangerousDir(path) {
		log.Error("decommission: ОТКАЗ удалять подозрительно-корневой каталог", slog.String("path", path))
		return fmt.Errorf("отказ удалять %q: %w", path, errUnsafeDir)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		log.Warn("decommission: пропускаю каталог — symlink/junction (возможная подмена)", slog.String("path", path))
		return fmt.Errorf("reparse-точка %q: %w", path, errUnsafeDir)
	}
	if err := os.RemoveAll(path); err != nil {
		log.Warn("decommission: не удалить каталог состояния", slog.String("path", path), slog.Any("error", err))
		return err
	}
	return nil
}

// safeLeftover — defense-in-depth перед отложенным удалением: даже если в
// leftover каким-то образом попал небезопасный путь (прямой вызов в обход Run
// или подмена каталога на reparse-точку уже ПОСЛЕ проверки removeDirSafe —
// TOCTOU), делетер его не тронет. Основную защиту даёт Run (errUnsafeDir не
// попадает в leftover); это второй барьер вплотную к rmdir/RemoveAll.
func safeLeftover(leftover []string, log *slog.Logger) []string {
	safe := make([]string, 0, len(leftover))
	for _, d := range leftover {
		if isDangerousDir(d) {
			log.Error("decommission: делетер ОТКАЗ — небезопасный каталог", slog.String("path", d))
			continue
		}
		if fi, err := os.Lstat(d); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			log.Warn("decommission: делетер пропускает reparse-точку (возможная подмена)", slog.String("path", d))
			continue
		}
		safe = append(safe, d)
	}
	return safe
}

// isDangerousDir — грубый предохранитель от катастрофического RemoveAll: корень
// ФС/тома и заведомо системные каталоги. Реальные пути состояния (ProgramData\
// RoutineOps, /var/lib/RoutineOps-agent, outbox) сюда не попадают.
func isDangerousDir(path string) bool {
	clean := filepath.Clean(path)
	if clean == "" || clean == "." {
		return true
	}
	if vol := filepath.VolumeName(clean); clean == vol+string(filepath.Separator) || clean == string(filepath.Separator) {
		return true // корень тома C:\ или /
	}
	if runtime.GOOS == "windows" {
		low := strings.ToLower(clean)
		for _, sys := range []string{`c:\windows`, `c:\program files`, `c:\program files (x86)`, `c:\users`} {
			if low == sys {
				return true
			}
		}
	} else {
		for _, sys := range []string{"/usr", "/etc", "/var", "/bin", "/sbin", "/lib", "/home", "/Library", "/System", "/Applications"} {
			if clean == sys {
				return true
			}
		}
	}
	return false
}
