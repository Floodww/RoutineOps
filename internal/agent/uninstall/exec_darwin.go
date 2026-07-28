//go:build darwin

package uninstall

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

// Каталоги, снос бандла из которых действительно означает деинсталляцию.
// Значения дублируют коллектор ОСОЗНАННО: это последняя проверка перед
// os.RemoveAll, и она не должна зависеть от корректности другого пакета —
// ошибка в общем хелпере разоружила бы обе проверки разом.
const (
	appsDir       = "/Applications"
	userAppsDir   = "Applications" // /Users/<кто-то>/Applications
	usersPrefix   = "/Users/"
	appExt        = ".app"
	pkgutilBinary = "/usr/sbin/pkgutil"
	defaultsBin   = "/usr/bin/defaults"
)

// execute снимает приложение: удаляет бандл и снимает квитанцию установщика.
//
// Порядок — сначала идентификатор, потом снос: после удаления Info.plist читать
// уже неоткуда, а без идентификатора pkgutil --forget нечего забывать, и в
// системе осталась бы квитанция о несуществующем пакете.
func execute(ctx context.Context, target collector.Software, log *slog.Logger) (string, error) {
	if target.UninstallMethod != collector.UninstallMacAppBundle {
		return "", fmt.Errorf("способ снятия %q не поддержан на macOS", target.UninstallMethod)
	}
	path := strings.TrimRight(strings.TrimSpace(target.InstallLocation), "/")
	if !removableAppBundle(path) {
		return "", fmt.Errorf("путь %q не является приложением, которое допустимо снимать (ожидается .app непосредственно в /Applications или ~/Applications)", target.InstallLocation)
	}
	// Проверяем, что это действительно каталог-бандл: файл с таким именем —
	// не приложение, а RemoveAll снёс бы его молча.
	st, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("цель недоступна: %w", err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%q не каталог-бандл — снимать нечего", path)
	}

	var out strings.Builder
	bundleID := readBundleID(ctx, path, log)

	if err := os.RemoveAll(path); err != nil {
		return out.String(), fmt.Errorf("удаление бандла: %w", err)
	}
	fmt.Fprintf(&out, "удалён бандл %s\n", path)

	// Квитанция pkgutil есть только у приложений, поставленных .pkg-инсталлятором.
	// Её отсутствие — норма (перетаскивание из .dmg), поэтому ошибка forget не
	// делает всю операцию неуспешной: бандла уже нет, ПО снято.
	if bundleID != "" {
		res, ferr := runCommand(ctx, pkgutilBinary, []string{"--forget", bundleID}, nil)
		if ferr != nil {
			log.Info("uninstall: квитанции pkgutil для бандла нет — это норма для установки перетаскиванием",
				slog.String("bundle_id", bundleID))
			fmt.Fprintf(&out, "квитанция pkgutil для %s не найдена\n", bundleID)
		} else {
			fmt.Fprintf(&out, "снята квитанция pkgutil %s\n%s", bundleID, res)
		}
	}
	return out.String(), nil
}

// readBundleID достаёт CFBundleIdentifier. Info.plist чаще всего в бинарном
// формате, поэтому читаем через defaults, а не парсим XML сами. Пустой ответ —
// не ошибка: без идентификатора просто пропускаем снятие квитанции.
func readBundleID(ctx context.Context, appPath string, log *slog.Logger) string {
	plist := filepath.Join(appPath, "Contents", "Info")
	out, err := runCommand(ctx, defaultsBin, []string{"read", plist, "CFBundleIdentifier"}, nil)
	if err != nil {
		log.Info("uninstall: CFBundleIdentifier не прочитан — снятие квитанции пропущено",
			slog.String("app", appPath))
		return ""
	}
	id := strings.TrimSpace(out)
	// Идентификатор уезжает в argv pkgutil — пробелы и переводы строк означают,
	// что прочиталось не то.
	if id == "" || strings.ContainsAny(id, " \t\n\r/") {
		return ""
	}
	return id
}

// removableAppBundle — независимая проверка формы пути. Бандл обязан лежать
// НЕПОСРЕДСТВЕННО в /Applications или в ~/Applications: вложенные бандлы это
// части чужой установки, а .app под /System и /Library/Apple защищены SIP.
func removableAppBundle(p string) bool {
	if !strings.HasSuffix(p, appExt) || p == appExt {
		return false
	}
	if p != filepath.Clean(p) || strings.Contains(p, "..") {
		return false
	}
	dir := filepath.Dir(p)
	if dir == appsDir {
		return true
	}
	rest, ok := strings.CutPrefix(dir, usersPrefix)
	if !ok {
		return false
	}
	user, tail, _ := strings.Cut(rest, "/")
	return user != "" && user != ".." && tail == userAppsDir
}
