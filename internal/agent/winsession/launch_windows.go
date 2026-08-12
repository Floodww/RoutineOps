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
	return LaunchInActiveSessionOpts(exe, args, Options{})
}

// Options — то, что отличает запуск захватчика экрана от запуска трея/оверлея.
type Options struct {
	// AsSystem — запустить процесс под токеном SYSTEM (собственным токеном службы), но
	// в АКТИВНОЙ пользовательской сессии, а не под токеном пользователя.
	//
	// 🔴 Зачем и почему это решение владельца (11.08.2026), а не оптимизация. Захватчик
	// экрана под токеном ПОЛЬЗОВАТЕЛЯ упирается в две стены сразу: UIPI не пускает его
	// синтетический ввод в окна БОЛЕЕ ВЫСОКОЙ целостности (диспетчер задач и всё
	// «от администратора»), а защищённый рабочий стол Winlogon (UAC, Ctrl+Alt+Del,
	// экран блокировки) пользовательскому процессу не открывается вовсе. Обе снимаются
	// одним фактом: у процесса под SYSTEM целостность System (выше High — UIPI молчит),
	// и права на объект рабочего стола Winlogon у SYSTEM есть.
	//
	// Это ЗАМЕНА пути UIAccess (манифест + подписанный бинарь в защищённом каталоге), а
	// не добавка к нему: UIAccess закрывал только первую стену и ценой подписи, а вторую
	// не закрывал ни при какой подписи. Разобрано в docs/remote-desktop-contract.md.
	//
	// Радиус поражения при этом НЕ растёт: захватчик и так порождается службой под
	// LocalSystem, то есть SYSTEM-код на машине уже исполняется — меняется лишь то, под
	// каким токеном живёт короткоживущий дочерний процесс сеанса. Зафиксировано как
	// решение в контракте и модели угроз, а не как находка аудита.
	AsSystem bool
}

// LaunchInActiveSessionOpts — то же, что LaunchInActiveSession, плюс опции.
func LaunchInActiveSessionOpts(exe string, args []string, opt Options) (windows.Handle, error) {
	sid := windows.WTSGetActiveConsoleSessionId()
	if sid == 0xFFFFFFFF {
		return 0, ErrNoActiveSession
	}

	primary, err := sessionPrimaryToken(sid, opt.AsSystem)
	if err != nil {
		return 0, err
	}
	defer primary.Close()

	// Блок окружения (не критично — при сбое стартуем без него). Под SYSTEM это
	// окружение самого SYSTEM, под пользовательским токеном — окружение пользователя;
	// захватчику ни то, ни другое не важно (путь лога передаётся аргументом), а трею
	// и оверлею нужен пользовательский профиль — они и идут пользовательским токеном.
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, primary, false); err != nil {
		env = nil
	}
	defer func() {
		if env != nil {
			windows.DestroyEnvironmentBlock(env)
		}
	}()

	cmdLine, err := windows.UTF16PtrFromString(buildCmdLine(exe, args))
	if err != nil {
		return 0, err
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Desktop: desktop}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW)
	if err := windows.CreateProcessAsUser(primary, nil, cmdLine, nil, nil, false,
		flags, env, nil, &si, &pi); err != nil {
		return 0, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	return pi.Process, nil
}

// sessionPrimaryToken отдаёт primary-токен для запуска в сессии sid.
//
// asSystem=false: токен ЗАЛОГИНЕННОГО пользователя (трей, оверлей — им нужен профиль
// и права пользователя). asSystem=true: собственный токен службы (SYSTEM), проштампованный
// нужной сессией, — захватчику экрана нужны права SYSTEM в сессии пользователя.
func sessionPrimaryToken(sid uint32, asSystem bool) (windows.Token, error) {
	if asSystem {
		return systemTokenForSession(sid)
	}
	var userTok windows.Token
	if err := windows.WTSQueryUserToken(sid, &userTok); err != nil {
		return 0, ErrNoActiveSession // нет залогиненного пользователя в этой сессии
	}
	defer userTok.Close()
	var dup windows.Token
	if err := windows.DuplicateTokenEx(userTok, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx(user): %w", err)
	}
	return dup, nil
}

// systemTokenForSession дублирует токен ТЕКУЩЕГО процесса (служба = LocalSystem) и
// переставляет его сессию на sid, чтобы SYSTEM-процесс жил в сессии пользователя.
//
// Смена сессии токена требует SeTcbPrivilege У ВЫЗЫВАЮЩЕГО процесса. У LocalSystem она
// есть, но в токене может быть выключена — включаем перед вызовом. Если её нет вовсе
// (агент запущен не как служба), запуск честно откажет здесь, а не молча стартует
// захватчик в session 0, где нет рабочего стола сотрудника.
func systemTokenForSession(sid uint32) (windows.Token, error) {
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &self); err != nil {
		return 0, fmt.Errorf("OpenProcessToken(self): %w", err)
	}
	defer self.Close()

	var dup windows.Token
	if err := windows.DuplicateTokenEx(self, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx(self): %w", err)
	}

	if err := enableProcessPrivilege(seTcbName); err != nil {
		dup.Close()
		return 0, fmt.Errorf("SeTcbPrivilege (агент запущен не как служба под LocalSystem?): %w", err)
	}
	if err := windows.SetTokenInformation(dup, uint32(windows.TokenSessionId),
		(*byte)(unsafe.Pointer(&sid)), uint32(unsafe.Sizeof(sid))); err != nil {
		dup.Close()
		return 0, fmt.Errorf("SetTokenInformation(session %d): %w", sid, err)
	}
	return dup, nil
}

// seTcbName — имя привилегии «действовать как часть ОС». Строкой, а не через готовую
// константу x/sys: там её нет отдельным символом, а строковое имя — часть стабильного
// Win32 API.
const seTcbName = "SeTcbPrivilege"

// enableProcessPrivilege включает привилегию в токене ТЕКУЩЕГО процесса.
//
// Именно процесса, а не дублированного токена: SetTokenInformation(session id) сверяет
// привилегию у ВЫЗЫВАЮЩЕГО, а не у изменяемого токена. AdjustTokenPrivileges сообщает
// об отсутствии привилегии не ошибкой, а ERROR_NOT_ALL_ASSIGNED при нулевом err —
// поэтому проверяем оба.
func enableProcessPrivilege(name string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return fmt.Errorf("OpenProcessToken(adjust): %w", err)
	}
	defer tok.Close()

	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValue(%s): %w", name, err)
	}
	priv := windows.Tokenprivileges{PrivilegeCount: 1}
	priv.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(tok, false, &priv, 0, nil, nil); err != nil {
		return fmt.Errorf("AdjustTokenPrivileges: %w", err)
	}
	// ERROR_NOT_ALL_ASSIGNED приезжает как последняя ошибка при nil err выше: привилегии
	// в токене нет, включать нечего. Даже если проверка ложно промолчит (last-error
	// затёрт планировщиком), корректность держит SetTokenInformation ниже — он всё равно
	// откажет без привилегии; эта проверка лишь даёт более раннюю и понятную строку.
	if errors.Is(windows.GetLastError(), windows.ERROR_NOT_ALL_ASSIGNED) {
		return fmt.Errorf("%s отсутствует в токене", name)
	}
	return nil
}
