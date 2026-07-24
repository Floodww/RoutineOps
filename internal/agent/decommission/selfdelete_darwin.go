//go:build darwin

package decommission

import (
	"log/slog"
	"os"
)

// stopServiceEarly на macOS — НАМЕРЕННО no-op. Снятие службы (service.Uninstall →
// launchctl bootout) шлёт SIGKILL самому процессу-демону, который выполняет снос.
// Сделай это до удаления файлов (как на Windows/Linux) — teardown оборвётся на
// середине (бинарь, серт, plist демона, receipt останутся), а сервер уже получил
// SUCCESS. Поэтому на darwin службу снимает scheduleSelfDelete ПОСЛЕДНИМ шагом.
func stopServiceEarly(_ func() error, _ *slog.Logger) {}

// scheduleSelfDelete на macOS: сначала синхронно (в ещё живом процессе) удаляет
// остаточные каталоги и собственный бинарь — unlink работающего исполняемого файла
// на unix легален. Снятие службы (stopService = service.Uninstall) — САМЫМ
// ПОСЛЕДНИМ: launchctl bootout внутри него убивает наш процесс, поэтому всё
// остальное (файлы/каталоги/бинарь + receipt/plist демона внутри Uninstall) обязано
// завершиться до него. service.Uninstall (darwin) переставлен так, что bootout там
// — тоже последняя операция (pkgutil --forget и удаление plist ПЕРЕД ним).
func scheduleSelfDelete(binPath string, leftover []string, stopService func() error, log *slog.Logger) error {
	for _, d := range safeLeftover(leftover, log) {
		if err := os.RemoveAll(d); err != nil {
			log.Warn("decommission: не удалить остаточный каталог", slog.String("path", d), slog.Any("error", err))
		}
	}
	var binErr error
	if binPath != "" {
		if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
			log.Warn("decommission: не удалить бинарь", slog.String("path", binPath), slog.Any("error", err))
			binErr = err
		} else {
			log.Warn("decommission: бинарь удалён — агент снят с устройства", slog.String("path", binPath))
		}
	}
	// ПОСЛЕДНИМ: bootout внутри Uninstall убивает этот процесс. Всё выше уже сделано.
	if stopService != nil {
		if err := stopService(); err != nil {
			log.Warn("decommission: снятие службы не удалось", slog.Any("error", err))
		}
	}
	return binErr
}
