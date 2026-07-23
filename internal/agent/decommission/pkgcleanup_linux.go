//go:build linux

package decommission

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// pkgRemoveTimeout ограничивает dpkg/rpm: подвисший пакетный менеджер (чужой
// lock БД пакетов, зависший конфиг-менеджмент) не должен вечно держать
// терминальный снос — лучше оставить регистрацию, чем не доснести агента.
const pkgRemoveTimeout = 90 * time.Second

// pkgManager описывает, как проверить регистрацию пакета и как её снять. query
// гейтит remove: на системе могут стоять оба менеджера (rpm как утилита поверх
// Debian) — снимаем только тем, в чьей БД пакет реально числится.
type pkgManager struct {
	query  []string
	remove []string
}

// linuxPackageManagers — dpkg и rpm. --force-depends/--nodeps: своих зависимостей
// у пакета нет, но обычный remove отказал бы, если бы на агента что-то зависело —
// а decommission обязан пройти. Файлы к этому моменту уже удалены сносом: remove
// лишь чистит регистрацию и запускает preremove, чей гард [ -x бинарь ] на уже
// удалённом бинаре пропускает self-uninstall (см. scheduleSelfDelete).
var linuxPackageManagers = []pkgManager{
	{
		query:  []string{"dpkg-query", "-W", linuxPackageName},
		remove: []string{"dpkg", "-r", "--force-depends", linuxPackageName},
	},
	{
		query:  []string{"rpm", "-q", linuxPackageName},
		remove: []string{"rpm", "-e", "--nodeps", linuxPackageName},
	},
}

// deregisterPackage снимает регистрацию пакета агента в БД dpkg/rpm. Без этого
// списанная машина остаётся в состоянии «пакет установлен, файлов нет» — ровно
// та несогласованность, которую админ чинит `apt install --reinstall`, а
// reinstall запускает postinstall с авто-энроллом: устройство возвращается в
// парк новой записью без участия оператора. enroll.env удаляет план сноса — это
// первый барьер; дерегистрация закрывает и путь «раскатка новой версии пакета»
// (postinstall не гардит апгрейд). Best-effort: установка из tar.gz (менеджера
// или записи нет) — норма; провал remove логируется, но снос не прерывает.
func deregisterPackage(log *slog.Logger) {
	for _, m := range linuxPackageManagers {
		if _, err := exec.LookPath(m.query[0]); err != nil {
			continue
		}
		if !runQuiet(m.query) {
			continue // пакет в БД этого менеджера не числится
		}
		if out, err := runCapture(m.remove); err != nil {
			log.Warn("decommission: снятие регистрации пакета не удалось — запись останется в БД менеджера",
				slog.String("cmd", strings.Join(m.remove, " ")),
				slog.Any("error", err), slog.String("output", strings.TrimSpace(out)))
			continue
		}
		log.Warn("decommission: регистрация пакета в БД менеджера снята",
			slog.String("cmd", strings.Join(m.remove, " ")))
		return
	}
}

// runQuiet выполняет команду с таймаутом; true — нулевой код возврата.
func runQuiet(argv []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), pkgRemoveTimeout)
	defer cancel()
	return exec.CommandContext(ctx, argv[0], argv[1:]...).Run() == nil
}

// runCapture выполняет команду с таймаутом и возвращает объединённый вывод.
func runCapture(argv []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pkgRemoveTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	return string(out), err
}
