//go:build !windows && !darwin

package decommission

import (
	"log/slog"
	"os"
)

// stopServiceEarly на Linux и прочих unix (кроме darwin): systemctl disable --now
// НЕ убивает процесс синхронно (SIGTERM с grace-периодом), teardown успевает
// завершиться — поэтому службу снимаем здесь, до удаления файлов, как и раньше.
func stopServiceEarly(fn func() error, log *slog.Logger) {
	if fn == nil {
		return
	}
	if err := fn(); err != nil {
		log.Warn("decommission: снятие службы не удалось — продолжаю снос", slog.Any("error", err))
	}
}

// scheduleSelfDelete на unix удаляет остаточные каталоги и бинарь синхронно:
// unlink работающего исполняемого файла легален (inode живёт, пока процесс держит
// открытый образ). stopService здесь уже вызван в stopServiceEarly — параметр не
// используется (сигнатура единая для всех платформ).
func scheduleSelfDelete(binPath string, leftover []string, _ func() error, log *slog.Logger) error {
	for _, d := range safeLeftover(leftover, log) {
		if err := os.RemoveAll(d); err != nil {
			log.Warn("decommission: не удалить остаточный каталог", slog.String("path", d), slog.Any("error", err))
		}
	}
	if binPath == "" {
		return nil
	}
	if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
		log.Warn("decommission: не удалить бинарь", slog.String("path", binPath), slog.Any("error", err))
		return err
	}
	// Дерегистрация пакета (dpkg/rpm) — СТРОГО после удаления бинаря: preremove
	// пакета гардит вызов `agent uninstall` по [ -x бинарь ]; с ещё живым бинарём
	// dpkg -r дёрнул бы systemctl disable --now и послал SIGTERM самому процессу
	// сноса на полпути. С удалённым бинарём гард false → preremove тихо проходит.
	deregisterPackage(log)
	log.Warn("decommission: бинарь удалён — агент снят с устройства", slog.String("path", binPath))
	return nil
}
