//go:build darwin && cgo

package main

import (
	_ "embed"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"fyne.io/systray"

	"github.com/Floodww/RoutineOps/internal/agent/service"
)

//go:embed assets/trayTemplate.png
var trayIconTemplate []byte

// setTrayIcon: в строке меню macOS иконка обязана быть template-маской — иначе она не
// перекрашивается под светлую/тёмную тему и тёмный знак сливается с тёмной строкой меню.
// Второй аргумент (цветная иконка) на darwin в systray v1.12.2 игнорируется — отдаём ту же
// маску, чтобы не вшивать в бинарь мёртвый ассет.
func setTrayIcon() { systray.SetTemplateIcon(trayIconTemplate, trayIconTemplate) }

// launchTrayInActiveSession бутстрапит LaunchAgent трея в уже открытую GUI-сессию
// сразу после установки. launchd подхватывает новый LaunchAgent из
// /Library/LaunchAgents САМ только при СЛЕДУЮЩЕМ логоне пользователя — если во
// время постинсталла (root) юзер уже залогинен в Aqua, трей молча не появится до
// релогина/ребута (полевой баг v1.5.1: пришлось поднимать вручную). Best-effort:
// никто не залогинен в консоль (loginwindow, owner=root) — норма, трей поднимется
// штатно при следующем логоне.
func launchTrayInActiveSession(log *slog.Logger) {
	out, err := exec.Command("stat", "-f", "%u", "/dev/console").Output()
	if err != nil {
		log.Warn("трей: не удалось определить активного консольного пользователя", slog.Any("error", err))
		return
	}
	uid := strings.TrimSpace(string(out))
	if uid == "" || uid == "0" {
		return
	}
	plist := service.TrayPlistPath()
	// Снять возможный стейл-инстанс, переживший прошлую установку: иначе bootstrap
	// упрётся в EIO «уже загружен», а стейл-трей висит без иконки (спавнился в чужом
	// контексте). На чистом слоте bootout — безвредный no-op. bootout АСИНХРОНЕН:
	// launchd снимает job не мгновенно, и немедленный bootstrap ловит ту же EIO уже по
	// гонке, оставляя сессию вовсе без трея, — поэтому bootstrap ретраим ~3с, пока слот
	// освобождается (на чистом слоте проходит с первой попытки).
	_ = exec.Command("launchctl", "bootout", "gui/"+uid+"/"+service.Name+".tray").Run()
	// out/err уже объявлены выше (вызов stat) — переиспользуем, не переобъявляя.
	for i := 0; i < 10; i++ {
		if out, err = exec.Command("launchctl", "bootstrap", "gui/"+uid, plist).CombinedOutput(); err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		log.Warn("трей: не удалось забутстрапить LaunchAgent в активную сессию",
			slog.String("uid", uid), slog.String("output", strings.TrimSpace(string(out))), slog.Any("error", err))
		return
	}
	log.Info("трей забутстрапен в активную сессию сразу после установки", slog.String("uid", uid))
}

// relaunchTrayAtServiceStart — no-op на macOS. Трей здесь — LaunchAgent юзер-сессии,
// и самообновление демона его НЕ убивает (taskkill-механика — Windows-специфика;
// на macOS подмена бинаря идёт rename'ом, работающий трей доживает на старом inode
// до следующего логона). Бутстрапить plist на каждый старт демона нельзя:
// launchctl bootstrap по уже загруженному LaunchAgent возвращает ошибку — был бы
// Warn-шум при каждом рестарте службы. Подъём в свежую сессию делает
// launchTrayInActiveSession из enroll -install-service, штатный логон — launchd сам.
func relaunchTrayAtServiceStart(_ *slog.Logger) {}

func setupTrayPlatform() {
	// В macOS приложение запускается без привязки к окну консоли (особенно если это LaunchAgent).
	// Дополнительно прятать консоль не нужно.
}

func configureLockScreenCmd(cmd *exec.Cmd) {
	// Никаких специфических атрибутов для процесса замка на macOS не требуется
}
