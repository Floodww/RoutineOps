//go:build windows || (darwin && cgo)

package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"fyne.io/systray"

	"github.com/Floodww/RoutineOps/internal/agent/admin"
	"github.com/Floodww/RoutineOps/internal/agent/config"
	"github.com/Floodww/RoutineOps/internal/agent/lock"
	"github.com/Floodww/RoutineOps/internal/agent/status"
)

// runTray запускает иконку статуса в системном трее (Windows/macOS). Это отдельный
// per-user процесс: служба и трей не общаются напрямую,
// поэтому статус трей читает из status-файла, который пишет служба
// (см. internal/agent/status). Меню и пункта «выход» нет — это индикатор, а не
// управление: остановить агента может только админ через службу.
func runTray(cfg *config.Config) {
	setupTrayPlatform() // платформенно-зависимая настройка (например, скрытие консоли)

	// «Нет связи», если последний heartbeat старше 2× интервала.
	staleAfter := 2 * cfg.HeartbeatInterval
	statusPath := statusFilePath(cfg)

	update := func() {
		st, err := status.Read(statusPath)
		switch {
		case err != nil:
			systray.SetTooltip("RoutineOps: агент не запущен")
		case st.Online(staleAfter):
			id := st.DeviceID
			if id == "" {
				id = "—"
			}
			systray.SetTooltip(fmt.Sprintf("RoutineOps: на связи (%s)", id))
		default:
			systray.SetTooltip("RoutineOps: нет связи с сервером")
		}
	}

	// Замок блокировки: трей (юзер-сессия) запускает отдельный процесс
	// `agent lock-screen`, когда устройство заблокировано (служба в session-0 GUI
	// показать не может). Состояние читаем из общего файла; lockRunning не даёт
	// плодить лишние окна, пока одно уже висит.
	lockPath := lockStatePath(cfg)
	var lockMu sync.Mutex
	var lockCmd *exec.Cmd

	checkLock := func() {
		st, err := lock.ReadState(lockPath)

		lockMu.Lock()
		defer lockMu.Unlock()

		isLocked := err == nil && st.Locked

		if !isLocked {
			if lockCmd != nil && lockCmd.Process != nil {
				_ = lockCmd.Process.Kill()
				lockCmd = nil
			}
			return
		}

		if lockCmd != nil {
			return // уже запущен
		}

		exe, err := os.Executable()
		if err != nil {
			return
		}
		cmd := exec.Command(exe, "lock-screen", "-lock-state", lockPath)
		configureLockScreenCmd(cmd) // платформенно-зависимые атрибуты процесса
		if err := cmd.Start(); err != nil {
			return
		}
		lockCmd = cmd
		go func(c *exec.Cmd) {
			_ = c.Wait()
			lockMu.Lock()
			if lockCmd == c {
				lockCmd = nil
			}
			lockMu.Unlock()
		}(cmd)
	}

	// Кнопка «Запросить админ-права»: трей кладёт файл-заявку, службу её подхватит
	// и отправит RequestAdminAccess (у трея нет машинной mTLS-идентичности).
	//
	// 🔴 Раньше галочка «Запрос отправлен ✓» показывалась сразу после ЗАПИСИ ФАЙЛА —
	// то есть подтверждала действие трея, а не доставку заявки. При отказе на стороне
	// сервера (04.08: RLS отбивала вставку, служба ретраила вечно) сотрудник видел
	// успех, а заявка не появлялась в панели никогда, и пожаловаться ему было не на что.
	//
	// Признак того, что служба заявку ЗАБРАЛА, — исчезновение файла: она удаляет его и
	// при успехе, и при окончательном отказе сервера, а транзиент оставляет для повтора.
	// Отличить успех от окончательного отказа отсюда нечем (отдельного канала результата
	// нет), поэтому и текст обещает ровно то, что проверено: «принята агентом».
	adminReqPath := adminRequestPath(cfg)
	requestAdmin := func(mi testableMenuItem) { submitAdminRequest(mi, adminReqPath, adminPickupTimeout) }

	onReady := func() {
		setTrayIcon() // иконка платформенная: .ico на Windows, template-PNG на macOS
		mReqAdmin := systray.AddMenuItem("Запросить админ-права", "Запросить временные права администратора")
		go func() {
			for range mReqAdmin.ClickedCh {
				requestAdmin(mReqAdmin)
			}
		}()
		update()
		checkLock()
		go func() {
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for range t.C {
				update()
				checkLock()
			}
		}()
	}

	systray.Run(onReady, func() {})
}

// submitAdminRequest — тело кнопки: положить заявку и дождаться, пока служба её
// заберёт. Вынесено из runTray, чтобы проверялось тестом: сама runTray поднимает
// systray, а он без живой оконной системы не стартует.
func submitAdminRequest(mi testableMenuItem, path string, timeout time.Duration) {
	if err := admin.WriteUserRequest(path, "запрос с устройства (трей)"); err != nil {
		// На Windows так выглядит сломанный ACL общего каталога состояния: трей
		// работает от пользователя, каталог держит SYSTEM.
		mi.SetTitle("Не удалось отправить — повторить")
		return
	}
	mi.SetTitle("Отправляю…")
	go func() {
		if waitRequestPickedUp(path, timeout) {
			mi.SetTitle("Заявка принята агентом ✓")
		} else {
			// Файл на месте — служба его не забрала: остановлена, не видит каталог
			// или упирается в транзиентную ошибку. Молчать тут нельзя: сотрудник
			// иначе будет ждать прав, которых никто не запрашивал.
			mi.SetTitle("Агент не забрал заявку — повторить")
		}
		time.Sleep(10 * time.Second)
		mi.SetTitle("Запросить админ-права")
	}()
}

// adminPickupTimeout — сколько трей ждёт, пока служба заберёт файл-заявку. Служба
// опрашивает каталог раз в 5 секунд (admin.WatchUserRequests), так что запас в три
// тика отделяет «служба стоит» от «просто не совпали по фазе».
const adminPickupTimeout = 16 * time.Second

// testableMenuItem — то, что нужно кнопке от пункта меню. Интерфейс, а не *systray.MenuItem:
// systray без живой оконной системы не поднимается, и без этого шва логику ожидания
// нечем проверить нигде, кроме живой машины с графической сессией.
type testableMenuItem interface {
	SetTitle(string)
}

// waitRequestPickedUp ждёт исчезновения файла-заявки. true = служба его забрала.
func waitRequestPickedUp(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
}
