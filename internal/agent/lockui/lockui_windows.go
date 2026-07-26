//go:build windows

// Package lockui — полноэкранный замок блокировки устройства (юзер-сессия).
//
// Запускается как `agent lock-screen` отдельным процессом в сессии пользователя
// (служба в session-0 GUI показать не может). Читает состояние блокировки из
// общего файла (lock.DefaultPath, ProgramData), и пока устройство заблокировано
// держит полноэкранное окно поверх всех с полем пароля. Разблокировка ОФФЛАЙН:
// введённый пароль сверяется с bcrypt-хешем из файла локально (без сети) — но это
// лишь для мгновенного «Неверный пароль» в самом окне. Снять блокировку окно НЕ
// вправе: сам файл состояния лежит в намеренно user-writable каталоге, поэтому
// любое «разблокировано», пришедшее из него, недоказуемо. При верном пароле окно
// кладёт запрос демону (lock.WriteUnlockRequest), демон ПЕРЕ-сверяет пароль и
// снимает лок авторитетно, а окно закрывается, увидев снятое состояние в файле.
//
// Чтобы это был настоящий замок, а не просто окно:
//   - экран удерживается от засыпания (SetThreadExecutionState) — иначе монитор
//     гаснет, и со стороны выглядит будто «просто чёрный экран»;
//   - low-level keyboard hook глушит Alt+Tab / Win / Ctrl+Esc / Alt+Esc / Alt+F4,
//     чтобы нельзя было переключиться на рабочий стол;
//   - окно растянуто на весь виртуальный экран (все мониторы) и раз в секунду
//     переподнимается поверх всех + в фокус, чтобы его нельзя было закрыть/спрятать;
//   - раз в секунду проверяется файл состояния: если админ разблокировал с сервера,
//     окно закрывается само.
//
// Ограничение: Ctrl+Alt+Del (Secure Attention Sequence) из пользовательского
// процесса перехватить нельзя — это требует политики (DisableLockWorkstation /
// credential provider). По Ctrl+Alt+Del пользователь попадёт на безопасный экран
// Windows, но к рабочему столу всё равно не получит доступ без пароля учётки;
// наш замок останется висеть и вернётся при возврате на десктоп.
package lockui

import (
	"log/slog"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	declarative "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"golang.org/x/crypto/bcrypt"

	"github.com/Floodww/RoutineOps/internal/agent/lock"
)

var (
	user32                  = syscall.NewLazyDLL("user32.dll")
	procSetWindowsHookEx    = user32.NewProc("SetWindowsHookExW")
	procCallNextHookEx      = user32.NewProc("CallNextHookEx")
	procUnhookWindowsHookEx = user32.NewProc("UnhookWindowsHookEx")
	procGetAsyncKeyState    = user32.NewProc("GetAsyncKeyState")

	kernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procSetThreadExecutionState = kernel32.NewProc("SetThreadExecutionState")
	procCreateMutexW            = kernel32.NewProc("CreateMutexW")
)

const (
	whKeyboardLL = 13
	hcAction     = 0
	wmKeyDown    = 0x0100
	wmSysKeyDown = 0x0104

	// SetThreadExecutionState: держим систему и дисплей «занятыми», пока висит замок.
	esContinuous      = 0x80000000
	esSystemRequired  = 0x00000001
	esDisplayRequired = 0x00000002

	errAlreadyExists = 183 // ERROR_ALREADY_EXISTS — мьютекс уже создан другим процессом

	// unlockWaitTimeout — сколько ждём, что демон обработает отправленный запрос на
	// разблокировку (Manager.Run тикает раз в секунду). Если не дождались — служба
	// остановлена или не отвечает; возвращаем поле ввода, чтобы сотрудник мог
	// повторить попытку, а не остался перед мёртвым замком без объяснения.
	unlockWaitTimeout = 10 * time.Second
)

// singleInstance не даёт показать два замка сразу: и трей, и служба могут запустить
// `agent lock-screen`. Именованный мьютекс — первый процесс держит его до выхода,
// второй видит ERROR_ALREADY_EXISTS и сразу выходит. Возвращает false, если оверлей
// уже показан другим процессом.
func singleInstance() bool {
	name, err := syscall.UTF16PtrFromString(`Global\MDMLockScreenOverlay`)
	if err != nil {
		return true // не смогли проверить — не блокируем показ
	}
	h, _, callErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h != 0 && callErr == syscall.Errno(errAlreadyExists) {
		return false // мьютекс уже есть → другой оверлей висит
	}
	return true // хэндл намеренно НЕ закрываем — держим мьютекс до конца процесса
}

// kbdLLHookStruct — раскладка KBDLLHOOKSTRUCT (lParam в low-level keyboard hook).
type kbdLLHookStruct struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

// keyDown — нажата ли клавиша сейчас (старший бит GetAsyncKeyState).
func keyDown(vk int32) bool {
	r, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
	return r&0x8000 != 0
}

// blockedKey решает, проглотить ли нажатие, чтобы не дать уйти с замка.
func blockedKey(vk uint32) bool {
	switch vk {
	case win.VK_LWIN, win.VK_RWIN:
		return true // клавиша Windows — открыла бы меню «Пуск»/переключение
	case win.VK_TAB:
		return keyDown(win.VK_MENU) // Alt+Tab
	case win.VK_ESCAPE:
		return keyDown(win.VK_CONTROL) || keyDown(win.VK_MENU) // Ctrl+Esc / Alt+Esc / Ctrl+Shift+Esc
	case win.VK_F4:
		return keyDown(win.VK_MENU) // Alt+F4
	}
	return false
}

// lowLevelKeyboardProc — колбэк WH_KEYBOARD_LL: глушит запрещённые комбинации.
func lowLevelKeyboardProc(code uintptr, wparam uintptr, lparam uintptr) uintptr {
	if code == hcAction && (wparam == wmKeyDown || wparam == wmSysKeyDown) {
		k := (*kbdLLHookStruct)(unsafe.Pointer(lparam))
		if blockedKey(k.VkCode) {
			return 1 // не передаём дальше — клавиша «съедена»
		}
	}
	ret, _, _ := procCallNextHookEx.Call(0, code, wparam, lparam)
	return ret
}

// keepAwake удерживает дисплей и систему включёнными (вызывать на GUI-потоке).
func keepAwake() {
	procSetThreadExecutionState.Call(uintptr(esContinuous | esSystemRequired | esDisplayRequired))
}

// Run показывает полноэкранный замок, если устройство заблокировано (по statePath).
// Блокирует поток, пока не введён верный пароль (или если блокировки нет — выходит).
func Run(statePath string, log *slog.Logger) {
	st, err := lock.ReadState(statePath)
	if err != nil || !st.Locked {
		return // не заблокировано — показывать нечего
	}
	if !singleInstance() {
		log.Info("lock-screen: замок уже показан другим процессом — выходим")
		return // трей и служба могли запустить нас оба; держим одно окно
	}
	runtime.LockOSThread() // GUI walk и keyboard hook требуют постоянного OS-потока
	keepAwake()
	defer procSetThreadExecutionState.Call(uintptr(esContinuous)) // снять удержание на выходе

	reason := st.Reason
	if reason == "" {
		reason = "Устройство заблокировано администратором. Обратитесь в IT для разблокировки."
	}

	var mw *walk.MainWindow
	var pwEdit *walk.LineEdit
	var errLabel *walk.Label
	unlocked := false
	// pendingUntil — крайний срок ожидания, что демон обработает отправленный
	// запрос на разблокировку (zero = запрос не отправлен). Пока ждём, ввод
	// заблокирован, а окно закроет сторож-тикер, увидев снятое состояние в файле.
	// Переменная читается и пишется только из GUI-потока (обработчики виджетов и
	// mw.Synchronize в сторо́же), поэтому синхронизация не нужна.
	var pendingUntil time.Time

	submit := func() {
		if !pendingUntil.IsZero() {
			return // запрос уже отправлен — ждём ответа демона
		}
		// Сверяем со СВЕЖИМ состоянием, а не с прочитанным при старте оверлея:
		// окно может висеть часами, и за это время демон мог применить НОВЫЙ лок
		// (эскалация ИБ, другой hash). Кэшированный хеш принимал бы пароль уже
		// снятой заявки и затирал новый лок (см. lock.MarkUnlocked).
		cur, err := lock.ReadState(statePath)
		if err != nil {
			// Fail-closed, симметрично сторожу-тикеру и демону (оба на ошибке
			// чтения держат текущее состояние): транзиентный сбой I/O — не повод
			// закрывать замок. Повторный Enter попробует ещё раз.
			errLabel.SetText("Не удалось проверить состояние блокировки — попробуйте ещё раз")
			return
		}
		if !cur.Locked {
			unlocked = true // разблокировано сервером, пока вводили пароль
			mw.Close()
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(cur.Hash), []byte(pwEdit.Text())) != nil {
			errLabel.SetText("Неверный пароль")
			pwEdit.SetText("")
			return
		}
		// Сверка выше — только для мгновенного «Неверный пароль» в этом окне. Снять
		// блокировку вправе лишь демон: он владелец lock.json и только его сверка
		// пароля доказуема. Раньше здесь писался lock.MarkUnlocked прямо в
		// lock.json, а демон верил файлу на слово — и тогда обычный пользователь
		// одной строкой {"locked":false} в том же (намеренно user-writable) файле
		// заказывал у демона durable-подавление пере-запирания, переживающее ребут,
		// вообще без пароля (находка 1.3, docs/lock-offline-unlock-hardening.md).
		// Теперь кладём запрос с паролем — тем же путём, что macOS-замок, — а окно
		// закроется, когда демон реально снимет лок и сторож увидит это в файле.
		if err := lock.WriteUnlockRequest(filepath.Dir(statePath), pwEdit.Text()); err != nil {
			log.Error("lock-screen: не удалось отправить запрос на разблокировку", slog.Any("error", err))
			errLabel.SetText("Не удалось отправить запрос на разблокировку — попробуйте ещё раз")
			return
		}
		pendingUntil = time.Now().Add(unlockWaitTimeout)
		pwEdit.SetText("")
		pwEdit.SetEnabled(false)
		errLabel.SetText("Проверка пароля…")
	}

	err = (declarative.MainWindow{
		AssignTo: &mw,
		Title:    "Устройство заблокировано",
		Layout:   declarative.VBox{Margins: declarative.Margins{Left: 80, Top: 80, Right: 80, Bottom: 80}},
		Children: []declarative.Widget{
			declarative.VSpacer{},
			declarative.Label{
				Text:      "Устройство заблокировано",
				Font:      declarative.Font{PointSize: 28, Bold: true},
				Alignment: declarative.AlignHCenterVCenter,
			},
			declarative.Label{Text: reason, Alignment: declarative.AlignHCenterVCenter},
			declarative.Composite{
				Layout: declarative.HBox{},
				Children: []declarative.Widget{
					declarative.HSpacer{},
					declarative.LineEdit{
						AssignTo:     &pwEdit,
						PasswordMode: true,
						MinSize:      declarative.Size{Width: 280},
						OnKeyDown: func(key walk.Key) {
							if key == walk.KeyReturn {
								submit()
							}
						},
					},
					declarative.PushButton{Text: "Разблокировать", OnClicked: submit},
					declarative.HSpacer{},
				},
			},
			declarative.Label{
				AssignTo:  &errLabel,
				TextColor: walk.RGB(220, 40, 40),
				Alignment: declarative.AlignHCenterVCenter,
			},
			declarative.VSpacer{},
		},
	}).Create()
	if err != nil {
		log.Error("lock-screen: не удалось создать окно замка", slog.Any("error", err))
		return
	}

	// Перекрываем весь виртуальный экран (все мониторы) и держим поверх всех.
	vx := win.GetSystemMetrics(win.SM_XVIRTUALSCREEN)
	vy := win.GetSystemMetrics(win.SM_YVIRTUALSCREEN)
	vw := win.GetSystemMetrics(win.SM_CXVIRTUALSCREEN)
	vh := win.GetSystemMetrics(win.SM_CYVIRTUALSCREEN)
	_ = mw.SetFullscreen(true)
	win.SetWindowPos(mw.Handle(), win.HWND_TOPMOST, vx, vy, vw, vh, win.SWP_SHOWWINDOW)
	win.SetForegroundWindow(mw.Handle())

	// Не даём закрыть окно (Alt+F4) до верного пароля.
	mw.Closing().Attach(func(canceled *bool, _ walk.CloseReason) {
		if !unlocked {
			*canceled = true
		}
	})

	// Глушим переключение с замка (Alt+Tab, Win, Ctrl+Esc и т.п.). Хук живёт на этом
	// же потоке, где крутится цикл сообщений walk (mw.Run ниже).
	hook, _, _ := procSetWindowsHookEx.Call(
		uintptr(whKeyboardLL),
		syscall.NewCallback(lowLevelKeyboardProc),
		uintptr(win.GetModuleHandle(nil)),
		0,
	)
	if hook != 0 {
		defer procUnhookWindowsHookEx.Call(hook)
	} else {
		log.Warn("lock-screen: keyboard hook не установлен — комбинации выхода не блокируются")
	}

	// Сторож: раз в секунду переподнимаем окно поверх всех и в фокус, удерживаем
	// экран и проверяем снятие блокировки. Файл стал !Locked — значит лок снял сам
	// демон (по команде сервера или обработав наш запрос с паролем), и это
	// единственный сигнал, по которому окно закрывается: сверка пароля в этом
	// процессе доказательством не является (см. submit).
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				mw.Synchronize(func() {
					if s, err := lock.ReadState(statePath); err == nil && !s.Locked {
						unlocked = true // демон снял блокировку — закрываемся
						mw.Close()
						return
					}
					// Запрос отправлен, но демон за отведённое время лок не снял:
					// служба остановлена или не отвечает. Возвращаем ввод, иначе
					// сотрудник остался бы перед замком с «Проверка пароля…»
					// навсегда, не понимая, что делать.
					if !pendingUntil.IsZero() && time.Now().After(pendingUntil) {
						pendingUntil = time.Time{}
						pwEdit.SetEnabled(true)
						errLabel.SetText("Служба управления не ответила — попробуйте ещё раз или обратитесь в IT")
					}
					win.SetWindowPos(mw.Handle(), win.HWND_TOPMOST, vx, vy, vw, vh, win.SWP_SHOWWINDOW)
					win.SetForegroundWindow(mw.Handle())
					keepAwake()
				})
			}
		}
	}()

	mw.Run()
	close(stop)
}
