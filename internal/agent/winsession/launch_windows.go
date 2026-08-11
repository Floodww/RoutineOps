//go:build windows

package winsession

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrNoActiveSession — сейчас никто не залогинен (нет интерактивной консольной
// сессии). Это не ошибка вызова: процесс (лок-оверлей/трей) поднимется, как только
// пользователь войдёт (для трея это делает HKLM\…\Run, для лока — фоновый цикл локера).
var ErrNoActiveSession = errors.New("нет активной консольной сессии")

// LaunchInActiveSession запускает "<exe> args…" в активной консольной сессии под
// токеном залогиненного пользователя и возвращает хэндл запущенного процесса.
// Вызывающий обязан либо закрыть хэндл (windows.CloseHandle) сразу — «запустить и
// забыть», либо использовать его для слежения за жизнью процесса. Применяется
// службой (session 0, LocalSystem), у которой нет рабочего стола: GUI рисует
// отдельный процесс в сессии пользователя.
func LaunchInActiveSession(exe string, args []string) (windows.Handle, error) {
	h, _, err := LaunchInActiveSessionOpts(exe, args, Options{})
	return h, err
}

// Options — то, что отличает запуск захватчика от запуска трея.
type Options struct {
	// UIAccess — попытаться выдать процессу право слать ввод окнам БОЛЕЕ ВЫСОКОЙ
	// целостности.
	//
	// 🔴 Гипотеза, которую эта опция проверяет в поле (10.08.2026). Полевой отказ
	// управления оказался UIPI: окно администратора в фокусе — и наш синтетический ввод
	// молча выбрасывается. Известный путь к UIAccess — манифест `uiAccess="true"` плюс
	// ПОДПИСАННЫЙ бинарь в защищённом каталоге, то есть деньги и отдельная задача.
	//
	// Но этот путь — для процессов, поднимаемых через AppInfo (обычный запуск
	// пользователем). Наш захватчик запускает СЛУЖБА, работающая от LocalSystem, а у неё
	// есть SeTcbPrivilege — привилегия, позволяющая выставить флаг UIAccess прямо в
	// токене (`TokenUIAccess`) перед созданием процесса. Проверки подписи и каталога на
	// этом пути делает не AppInfo, а ядро — и оно проверяет ПРИВИЛЕГИЮ.
	//
	// Если гипотеза верна, управление элевированными окнами не требует ни покупки
	// сертификата, ни манифеста. Если неверна — узнаем это одной строкой лога, а не
	// после оплаты годовой подписи.
	UIAccess bool
}

// LaunchInActiveSessionOpts — то же, что LaunchInActiveSession, плюс опции. Второе
// возвращаемое значение — удалось ли выдать UIAccess (для лога вызывающего).
func LaunchInActiveSessionOpts(exe string, args []string, opt Options) (windows.Handle, bool, error) {
	h, granted, err := launchInSession(exe, args, opt)
	return h, granted, err
}

func launchInSession(exe string, args []string, opt Options) (windows.Handle, bool, error) {
	sid := windows.WTSGetActiveConsoleSessionId()
	if sid == 0xFFFFFFFF {
		return 0, false, ErrNoActiveSession
	}
	var userTok windows.Token
	if err := windows.WTSQueryUserToken(sid, &userTok); err != nil {
		return 0, false, ErrNoActiveSession // нет залогиненного пользователя в этой сессии
	}
	defer userTok.Close()

	var dupTok windows.Token
	if err := windows.DuplicateTokenEx(userTok, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &dupTok); err != nil {
		return 0, false, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer dupTok.Close()

	// Флаг ставится ДО создания процесса: после старта право уже не выдать, токен процесса
	// в этой части неизменяем. Отказ — не ошибка запуска: без UIAccess захватчик работает
	// ровно как раньше, теряя только окна администратора, а падение здесь стоило бы
	// сеанса целиком.
	uiAccess := false
	if opt.UIAccess {
		if err := setTokenUIAccess(dupTok); err == nil {
			uiAccess = true
		}
	}

	// Блок окружения пользователя (не критично — при сбое стартуем без него).
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, dupTok, false); err != nil {
		env = nil
	}
	defer func() {
		if env != nil {
			windows.DestroyEnvironmentBlock(env)
		}
	}()

	cmdLine, err := windows.UTF16PtrFromString(buildCmdLine(exe, args))
	if err != nil {
		return 0, false, err
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW)
	if err := windows.CreateProcessAsUser(dupTok, nil, cmdLine, nil, nil, false,
		flags, env, nil, &si, &pi); err != nil {
		return 0, false, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	return pi.Process, uiAccess, nil
}

// setTokenUIAccess выставляет TokenUIAccess=1. Требует SeTcbPrivilege у ВЫЗЫВАЮЩЕГО —
// у службы под LocalSystem она есть, у обычного пользователя нет и не будет.
func setTokenUIAccess(t windows.Token) error {
	const tokenUIAccess = 26 // TOKEN_INFORMATION_CLASS.TokenUIAccess
	one := uint32(1)
	return windows.SetTokenInformation(t, tokenUIAccess,
		(*byte)(unsafe.Pointer(&one)), uint32(unsafe.Sizeof(one)))
}
