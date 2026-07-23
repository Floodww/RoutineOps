//go:build !windows

package decommission

import (
	"log/slog"
	"os"
)

// scheduleSelfDelete на unix удаляет бинарь сразу: unlink работающего
// исполняемого файла легален (inode живёт, пока процесс держит открытый образ, и
// освобождается на выходе). leftover-каталоги на unix пусты — RemoveAll там не
// упирается в открытые хэндлы, как на Windows, поэтому отдельного делетера не надо.
func scheduleSelfDelete(binPath string, leftover []string, log *slog.Logger) error {
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
