//go:build linux

// Полноэкранный замок блокировки для Linux (X11). Аналог Windows- и macOS-оверлеев:
// запускается как `agent lock-screen` в графической сессии пользователя (служба живёт
// вне сессии и рисовать не может), читает состояние из общего файла и держит
// полноэкранное окно с полем пароля, пока устройство заблокировано.
//
// Контракт разблокировки ТОТ ЖЕ, что на других платформах и переигрывать его здесь
// нельзя: bcrypt-сверка в окне нужна лишь для мгновенного «Неверный пароль», снять
// блокировку вправе только демон (владелец файла состояния), поэтому при верном
// пароле окно кладёт запрос через lock.WriteUnlockRequest и закрывается, лишь увидев
// снятое состояние в файле. Файл состояния намеренно user-writable, значит любое
// «разблокировано», пришедшее из окна, недоказуемо.
//
// Чем это замок, а не просто окно:
//   - окно override-redirect на весь корневой экран: оконный менеджер его не
//     переставляет, не декорирует и не может «свернуть»;
//   - активный захват клавиатуры и указателя (GrabKeyboard/GrabPointer) уводит ввод
//     у всех остальных клиентов, включая пассивные горячие клавиши WM (Alt+Tab и
//     прочее до рабочего стола не доходят);
//   - раз в секунду окно переподнимается наверх, возвращает фокус и, если захват
//     потерян (WM успел перехватить на старте сессии), берёт его заново;
//   - хранитель экрана выключается на время замка, иначе через минуту экран гаснет и
//     со стороны это выглядит как «просто чёрный экран», а не как блокировка.
//
// Границы, которые честнее назвать, чем сделать вид, что их нет:
//   - Wayland: клиент не может ни перекрыть экран, ни забрать клавиатуру — это
//     привилегия компоновщика. Под Wayland замок не запускается вовсе (см.
//     DetectBackend и docs/lock-linux.md), а служба сообщает об этом в лог;
//   - переключение на текстовую консоль (Ctrl+Alt+F2) X-клиенту не перехватить —
//     ровно так же, как Ctrl+Alt+Del на Windows. Замок остаётся висеть и вернётся
//     при возврате в графику.
package lockui

import (
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
	"golang.org/x/crypto/bcrypt"

	"github.com/Floodww/RoutineOps/internal/agent/lock"
	"github.com/Floodww/RoutineOps/internal/agent/x11ui"
)

const (
	// unlockWaitTimeout — сколько ждём, что демон обработает отправленный запрос
	// (Manager.Run тикает раз в секунду). Не дождались — возвращаем поле ввода, чтобы
	// сотрудник не остался перед замком с вечным «Проверка пароля…».
	unlockWaitTimeout = 10 * time.Second

	// grabRetryTimeout — сколько добиваемся захвата ввода при старте. На входе в
	// сессию WM/дисплей-менеджер часто держит собственный захват несколько секунд.
	grabRetryTimeout = 5 * time.Second
	grabRetryPause   = 200 * time.Millisecond

	watchdogInterval = time.Second
)

// Тексты замка парами: вторая строка — латиница на случай, когда на машине нет ни
// одного Unicode-шрифта (см. pickFonts). Показать латиницу честнее, чем пустой экран.
var (
	titleText     = text{"Устройство заблокировано", "Device locked"}
	promptText    = text{"Введите пароль разблокировки:", "Enter unlock password:"}
	defaultReason = text{
		"Устройство заблокировано администратором. Обратитесь в IT для разблокировки.",
		"This device was locked by your administrator. Contact IT to unlock.",
	}
	msgWrongPassword   = text{"Неверный пароль", "Wrong password"}
	msgStateUnreadable = text{
		"Не удалось проверить состояние блокировки — попробуйте ещё раз",
		"Could not read lock state - please try again",
	}
	msgSendFailed = text{
		"Не удалось отправить запрос на разблокировку — попробуйте ещё раз",
		"Could not send the unlock request - please try again",
	}
	msgChecking     = text{"Проверка пароля…", "Checking password..."}
	msgDaemonSilent = text{
		"Служба управления не ответила — попробуйте ещё раз или обратитесь в IT",
		"The management service did not respond - try again or contact IT",
	}
)

// text — строка замка на двух языках. Выбор делает overlay.t по тому, есть ли
// Unicode-шрифт.
type text struct{ ru, en string }

// Run показывает замок, если устройство заблокировано (по statePath). Возвращается,
// когда демон снял блокировку либо когда показать замок невозможно — служба поднимет
// нас заново своим циклом, поэтому выходить с ошибкой безопасно.
func Run(statePath string, log *slog.Logger) {
	st, err := lock.ReadState(statePath)
	if err != nil || !st.Locked {
		return // не заблокировано — показывать нечего
	}
	if b := lock.DetectBackend(os.Getenv); b != lock.BackendX11 {
		log.Error("lock-screen: графический замок недоступен в этой сессии",
			slog.String("backend", string(b)),
			slog.String("подробности", "оверлей реализован только для X11, см. docs/lock-linux.md"))
		return
	}
	release, ok := singleInstance(log)
	if !ok {
		log.Info("lock-screen: замок уже показан другим процессом — выходим")
		return
	}
	defer release()

	ui, err := newOverlay(statePath, st.Reason, log)
	if err != nil {
		log.Error("lock-screen: не удалось поднять окно замка", slog.Any("error", err))
		return
	}
	defer ui.close()
	ui.loop()
}

// singleInstance не даёт показать два замка сразу: поднять `agent lock-screen` могут
// и трей, и служба. Блокировка файла в runtime-каталоге пользователя снимается ядром
// при любом завершении процесса — в отличие от pid-файла, который переживает kill -9
// и запирал бы замок навсегда.
func singleInstance(log *slog.Logger) (release func(), ok bool) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.OpenFile(filepath.Join(dir, "routineops-lock-screen.lock"),
		os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		log.Warn("lock-screen: не удалось открыть файл единственного экземпляра",
			slog.Any("error", err))
		return func() {}, true // не смогли проверить — показываем замок, это безопаснее
	}
	if err := flockNB(f); err != nil {
		_ = f.Close()
		return nil, false
	}
	return func() { _ = f.Close() }, true
}

// overlay — состояние окна замка. Всё рисование и обработка событий идут в одном
// потоке (loop), поэтому синхронизация полей не нужна.
type overlay struct {
	log       *slog.Logger
	statePath string
	reason    text

	conn    *xgb.Conn
	win     xproto.Window
	root    xproto.Window
	w, h    uint16
	gcTitle xproto.Gcontext
	gcText  xproto.Gcontext
	gcDim   xproto.Gcontext
	gcErr   xproto.Gcontext
	gcBg    xproto.Gcontext
	fBig    xproto.Font
	fText   xproto.Font
	// twoByte — умеет ли выбранный шрифт рисовать двухбайтовые символы (кодировка
	// iso10646-1). Если на машине таких шрифтов нет, замок переходит на латиницу:
	// пустой экран вместо текста — худший исход, сотрудник не понимает, что произошло.
	twoByte bool

	kb           x11ui.Keyboard
	password     []rune
	message      text
	pendingUntil time.Time
	done         bool
}

func newOverlay(statePath, reason string, log *slog.Logger) (*overlay, error) {
	conn, err := xgb.NewConn()
	if err != nil {
		return nil, err
	}
	ui := &overlay{log: log, statePath: statePath, reason: reasonText(reason), conn: conn}
	if err := ui.setup(); err != nil {
		conn.Close()
		return nil, err
	}
	return ui, nil
}

func (u *overlay) setup() error {
	setup := xproto.Setup(u.conn)
	screen := setup.DefaultScreen(u.conn)
	u.root = screen.Root
	u.w, u.h = screen.WidthInPixels, screen.HeightInPixels

	win, err := xproto.NewWindowId(u.conn)
	if err != nil {
		return err
	}
	u.win = win
	// OverrideRedirect: окно вне управления WM — его не свернуть, не переставить и не
	// закрыть кнопкой. Класс InputOutput на весь корневой экран (в X11 он покрывает и
	// все мониторы Xinerama, поэтому отдельная логика на мультимонитор не нужна).
	err = xproto.CreateWindowChecked(u.conn, screen.RootDepth, win, u.root,
		0, 0, u.w, u.h, 0, xproto.WindowClassInputOutput, screen.RootVisual,
		xproto.CwBackPixel|xproto.CwOverrideRedirect|xproto.CwEventMask,
		[]uint32{
			screen.BlackPixel,
			1,
			uint32(xproto.EventMaskKeyPress | xproto.EventMaskExposure |
				xproto.EventMaskVisibilityChange | xproto.EventMaskStructureNotify),
		}).Check()
	if err != nil {
		return err
	}
	u.nameWindow()
	if err := xproto.MapWindowChecked(u.conn, win).Check(); err != nil {
		return err
	}
	u.pickFonts()
	// Отдельный GC под заголовок: шрифт — свойство GC, а не аргумент рисования.
	// Пока заголовок рисовался общим gcText, он МЕРИЛСЯ крупным шрифтом, а
	// РИСОВАЛСЯ мелким — выглядел как обычный текст и уезжал влево на разницу ширин.
	u.gcTitle = u.newGC(0xffffff, u.fBig)
	u.gcText = u.newGC(0xffffff, u.fText)
	u.gcDim = u.newGC(0xb0b0b0, u.fText)
	u.gcErr = u.newGC(0xff5555, u.fText)
	u.gcBg = u.newGC(0x000000, u.fText)

	kb, err := x11ui.NewKeyboard(u.conn)
	if err != nil {
		return err
	}
	u.kb = kb

	u.raise()
	u.grabInput()
	u.disableScreenSaver()
	return nil
}

// pickFonts выбирает шрифты и решает, доступен ли двухбайтовый вывод вообще.
//
// Сам подбор живёт в x11ui: та же задача стоит перед плашкой наблюдения за экраном, а
// две копии проверки «рисует ли шрифт кириллицу» разъехались бы молча — с исходом «окно
// без текста у сотрудника».
func (u *overlay) pickFonts() {
	f := x11ui.PickFonts(u.conn, u.log)
	u.fBig, u.fText, u.twoByte = f.Big, f.Text, f.TwoByte
}

// nameWindow подписывает окно. Оверлей override-redirect не показывается в списке
// окон, и без имени администратор, разбирающий «чёрный экран у сотрудника» через
// xwininfo, видит безымянное окно неизвестного происхождения.
func (u *overlay) nameWindow() {
	const name = "RoutineOps lock"
	xproto.ChangeProperty(u.conn, xproto.PropModeReplace, u.win, xproto.AtomWmName,
		xproto.AtomString, 8, uint32(len(name)), []byte(name))
	class := []byte("routineops-lock\x00RoutineOps\x00")
	xproto.ChangeProperty(u.conn, xproto.PropModeReplace, u.win, xproto.AtomWmClass,
		xproto.AtomString, 8, uint32(len(class)), class)
}

func (u *overlay) newGC(fg uint32, font xproto.Font) xproto.Gcontext {
	gc, err := xproto.NewGcontextId(u.conn)
	if err != nil {
		return 0
	}
	mask := uint32(xproto.GcForeground | xproto.GcBackground)
	vals := []uint32{fg, 0x000000}
	if font != 0 {
		mask |= xproto.GcFont
		vals = append(vals, uint32(font))
	}
	xproto.CreateGC(u.conn, gc, xproto.Drawable(u.win), mask, vals)
	return gc
}

// raise возвращает окно наверх стопки и в фокус. Зовётся и по тику сторожа: новый
// клиент (уведомление, автозапуск) мог всплыть поверх замка.
func (u *overlay) raise() {
	xproto.ConfigureWindow(u.conn, u.win, xproto.ConfigWindowStackMode,
		[]uint32{xproto.StackModeAbove})
	xproto.SetInputFocus(u.conn, xproto.InputFocusParent, u.win, xproto.TimeCurrentTime)
}

// grabInput забирает клавиатуру и указатель. Возвращает true, когда клавиатура наша:
// без неё замок не замок — ввод уходил бы в приложения под ним.
func (u *overlay) grabInput() bool {
	deadline := time.Now().Add(grabRetryTimeout)
	for {
		kb, err := xproto.GrabKeyboard(u.conn, true, u.win, xproto.TimeCurrentTime,
			xproto.GrabModeAsync, xproto.GrabModeAsync).Reply()
		if err == nil && kb.Status == xproto.GrabStatusSuccess {
			xproto.GrabPointer(u.conn, true, u.win, 0,
				xproto.GrabModeAsync, xproto.GrabModeAsync, u.win, 0, xproto.TimeCurrentTime)
			return true
		}
		if time.Now().After(deadline) {
			u.log.Warn("lock-screen: клавиатура не захвачена — замок показан, но ввод не перехвачен")
			return false
		}
		time.Sleep(grabRetryPause)
	}
}

// disableScreenSaver выключает гашение экрана на время замка: иначе через штатную
// минуту простоя монитор погаснет, и блокировка визуально неотличима от спящего экрана.
func (u *overlay) disableScreenSaver() {
	xproto.SetScreenSaver(u.conn, 0, 0, xproto.BlankingNotPreferred, xproto.ExposuresNotAllowed)
}

func (u *overlay) close() {
	// Возвращаем хранитель экрана к системным значениям (-1 = «как настроено»).
	xproto.SetScreenSaver(u.conn, -1, -1, xproto.BlankingDefault, xproto.ExposuresDefault)
	xproto.UngrabKeyboard(u.conn, xproto.TimeCurrentTime)
	xproto.UngrabPointer(u.conn, xproto.TimeCurrentTime)
	xproto.DestroyWindow(u.conn, u.win)
	u.conn.Close()
}

// loop — единственный поток, где происходят рисование и обработка ввода. События X
// читает отдельная горутина: WaitForEvent блокирующий, а сторожу нужно тикать даже
// когда пользователь ничего не нажимает.
func (u *overlay) loop() {
	events := make(chan xgb.Event, 16)
	go func() {
		defer close(events)
		for {
			ev, err := u.conn.WaitForEvent()
			if ev == nil && err == nil {
				return // соединение закрыто
			}
			if ev != nil {
				events <- ev
			}
		}
	}()

	u.draw()
	t := time.NewTicker(watchdogInterval)
	defer t.Stop()
	for !u.done {
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			u.handleEvent(ev)
		case <-t.C:
			u.watchdog()
		}
	}
}

func (u *overlay) handleEvent(ev xgb.Event) {
	switch e := ev.(type) {
	case xproto.KeyPressEvent:
		u.handleKey(e)
	case xproto.ExposeEvent, xproto.VisibilityNotifyEvent, xproto.MapNotifyEvent:
		// Экран перерисовали или кто-то всплыл поверх — вернуть себе верх и картинку.
		u.raise()
		u.draw()
	}
}

func (u *overlay) handleKey(e xproto.KeyPressEvent) {
	if !u.pendingUntil.IsZero() {
		return // запрос уже у демона — ввод заморожен до ответа
	}
	action, r := DecodeKeysym(u.keysym(e))
	switch action {
	case KeyChar:
		u.password = append(u.password, r)
	case KeyErase:
		if n := len(u.password); n > 0 {
			u.password = u.password[:n-1]
		}
	case KeySubmit:
		u.submit()
		return
	default:
		return
	}
	u.message = text{}
	u.draw()
}

// keysym переводит код клавиши в keysym с учётом Shift. Берём столбец 1 (сдвинутый),
// когда нажат Shift, иначе столбец 0 — этого достаточно для ввода пароля; групповые
// раскладки (столбцы 2-3) сознательно не трогаем, чтобы не гадать о состоянии группы.
func (u *overlay) keysym(e xproto.KeyPressEvent) uint32 {
	return u.kb.Keysym(e.Detail, u.shiftColumn(e.State))
}

func (u *overlay) shiftColumn(state uint16) int {
	if state&uint16(xproto.ModMaskShift) != 0 {
		return 1
	}
	return 0
}

// submit повторяет контракт Windows- и macOS-замков: сверка с ПЕРЕЧИТАННЫМ состоянием
// (окно висит часами, за это время мог приехать НОВЫЙ лок с другим хешем), затем
// запрос демону; окно закрывается не по своей сверке, а увидев снятый лок в файле.
func (u *overlay) submit() {
	cur, err := lock.ReadState(u.statePath)
	if err != nil {
		// Fail-closed, как у сторожа и демона: транзиентный сбой чтения — не повод
		// открывать замок.
		u.message = msgStateUnreadable
		u.draw()
		return
	}
	if !cur.Locked {
		u.done = true // разблокировали с сервера, пока вводили пароль
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(cur.Hash), []byte(string(u.password))) != nil {
		u.password = nil
		u.message = msgWrongPassword
		u.draw()
		return
	}
	if err := lock.WriteUnlockRequest(filepath.Dir(u.statePath), string(u.password)); err != nil {
		u.log.Error("lock-screen: не удалось отправить запрос на разблокировку", slog.Any("error", err))
		u.password = nil
		u.message = msgSendFailed
		u.draw()
		return
	}
	u.password = nil
	u.pendingUntil = time.Now().Add(unlockWaitTimeout)
	u.message = msgChecking
	u.draw()
}

// watchdog — раз в секунду: снят ли лок, не потеряли ли верх/захват, не завис ли
// отправленный запрос.
func (u *overlay) watchdog() {
	if st, err := lock.ReadState(u.statePath); err == nil && !st.Locked {
		u.done = true // демон снял блокировку — единственный сигнал закрыться
		return
	}
	if !u.pendingUntil.IsZero() && time.Now().After(u.pendingUntil) {
		u.pendingUntil = time.Time{}
		u.message = msgDaemonSilent
	}
	u.raise()
	u.grabIfLost()
	u.disableScreenSaver()
	u.draw()
}

// grabIfLost перезабирает клавиатуру, если её увёл другой клиент (так бывает при
// старте сессии и при переключении VT). Одна попытка: длинный ретрай здесь заморозил
// бы сторожа.
func (u *overlay) grabIfLost() {
	kb, err := xproto.GrabKeyboard(u.conn, true, u.win, xproto.TimeCurrentTime,
		xproto.GrabModeAsync, xproto.GrabModeAsync).Reply()
	if err != nil || kb.Status != xproto.GrabStatusSuccess {
		return
	}
	xproto.GrabPointer(u.conn, true, u.win, 0,
		xproto.GrabModeAsync, xproto.GrabModeAsync, u.win, 0, xproto.TimeCurrentTime)
}

func (u *overlay) draw() {
	xproto.PolyFillRectangle(u.conn, xproto.Drawable(u.win), u.gcBg,
		[]xproto.Rectangle{{X: 0, Y: 0, Width: u.w, Height: u.h}})

	cy := int16(u.h) / 2
	u.centerText(u.t(titleText), cy-120, u.gcTitle, u.fBig)
	u.centerText(u.t(u.reason), cy-60, u.gcDim, u.fText)
	u.centerText(u.t(promptText), cy, u.gcDim, u.fText)
	u.centerText(MaskPassword(len(u.password)), cy+40, u.gcText, u.fText)
	u.drawInputLine(cy + 50)
	if u.message != (text{}) {
		u.centerText(u.t(u.message), cy+100, u.gcErr, u.fText)
	}
}

// drawInputLine рисует черту под полем пароля. Без неё пустое поле неотличимо от
// «замок завис»: на экране просто нет места, куда набирать.
func (u *overlay) drawInputLine(y int16) {
	const width = 320
	x := (int16(u.w) - width) / 2
	xproto.PolyFillRectangle(u.conn, xproto.Drawable(u.win), u.gcDim,
		[]xproto.Rectangle{{X: x, Y: y, Width: width, Height: 1}})
}

// centerText рисует строку по центру экрана.
func (u *overlay) centerText(s string, y int16, gc xproto.Gcontext, font xproto.Font) {
	x11ui.DrawCentered(u.conn, xproto.Drawable(u.win), gc, font, u.twoByte, s, y, u.w)
}

// t выбирает язык строки: кириллицу, когда есть Unicode-шрифт, иначе латиницу.
func (u *overlay) t(v text) string {
	if u.twoByte {
		return v.ru
	}
	return v.en
}

// reasonText оборачивает причину, пришедшую с сервера. Латинского перевода у неё нет,
// поэтому в fallback-режиме показываем общий текст: строка из «?» вместо кириллицы
// пугает сильнее, чем отсутствие подробностей.
func reasonText(reason string) text {
	if reason == "" {
		return defaultReason
	}
	en := reason
	for _, r := range reason {
		if r > 0x7f {
			en = defaultReason.en
			break
		}
	}
	return text{reason, en}
}

// flockNB — неблокирующий эксклюзивный flock. Отдельной функцией, чтобы условие
// «замок уже показан» читалось в singleInstance, а не тонуло в syscall-деталях.
func flockNB(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
