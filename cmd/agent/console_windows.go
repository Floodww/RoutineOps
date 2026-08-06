//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// AttachConsole нет типизированной обёртки в x/sys/windows — зовём из kernel32.
var procAttachConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

// attachParentConsole привязывает stdout/stderr агента к консоли родительского
// процесса, если он запущен из неё (cmd/powershell — ручные CLI-ветки enroll,
// version, -h). Бинарь собран как GUI-subsystem (-H windowsgui), поэтому своей
// консоли у него нет: иначе в интерактивной сессии всплывало бы окно, закрытие
// которого слало CTRL_CLOSE_EVENT и убивало агент. Цена GUI-subsystem — CLI-ветки
// теряют stdout/stderr, что и чиним этим re-attach.
//
// Если родительской консоли нет (служба в session 0, трей, запуск из MSI),
// AttachConsole возвращает 0 — тогда ничего не делаем (вывод и так не нужен).
//
// 🔴 Перенаправленный поток НЕ ТРОГАЕМ, и это не осторожность, а починка.
//
// Прежняя версия после успешного AttachConsole подменяла os.Stdout/os.Stderr на CONOUT$
// БЕЗУСЛОВНО. Родитель с консолью есть почти всегда (cmd, powershell, сессия sshd), и
// подмена затирала дескрипторы, которые он выдал НАМЕРЕННО:
//
//	Start-Process agent -ArgumentList version -RedirectStandardOutput out.txt
//	→ out.txt пустой, вывод ушёл в консоль родителя, где его никто не читает
//
// В поле это выглядело так, что агент «не умеет писать в stdout вообще»: `version` —
// команда, вся суть которой напечатать версию, — отдавала НОЛЬ БАЙТ и код 0. Отсюда же
// вывод, что screen-probe на Windows бесполезна: она отвечала только кодом возврата,
// потому что её текст уезжал в ту же дыру.
//
// Различаем по ТИПУ дескриптора, а не по его наличию: у GUI-процесса, запущенного из
// cmd без перенаправления, stdout это унаследованный дескриптор ЧУЖОЙ консоли —
// писать в него до AttachConsole нельзя, и вот его подменять надо. Файл и пайп
// (перенаправление, конвейер, .NET-редирект у Start-Process) — наоборот, единственно
// верный адресат.
func attachParentConsole() {
	outRedirected := redirectedToFile(windows.STD_OUTPUT_HANDLE)
	errRedirected := redirectedToFile(windows.STD_ERROR_HANDLE)
	if outRedirected && errRedirected {
		return // родитель всё сказал сам
	}

	const attachParentProcess = 0xFFFFFFFF // ATTACH_PARENT_PROCESS == DWORD(-1)
	if r, _, _ := procAttachConsole.Call(uintptr(attachParentProcess)); r == 0 {
		return
	}
	// Открываем консоль родителя напрямую: надёжнее GetStdHandle, который у
	// GUI-процесса мог закэшировать невалидный дескриптор.
	name, err := windows.UTF16PtrFromString("CONOUT$")
	if err != nil {
		return
	}
	h, err := windows.CreateFile(name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(h), "CONOUT$")
	if !outRedirected {
		os.Stdout = f
	}
	if !errRedirected {
		os.Stderr = f
	}
}

// redirectedToFile — поток уже направлен родителем в файл или пайп.
//
// GetFileType, а не «дескриптор не пуст»: у консольного дескриптора тип FILE_TYPE_CHAR,
// и именно его надо перебивать на CONOUT$ (писать в консоль, к которой мы ещё не
// привязаны, нельзя). FILE_TYPE_DISK и FILE_TYPE_PIPE — это осознанный выбор родителя:
// `>файл`, конвейер, Start-Process -RedirectStandard*, sshd. Ошибка или неизвестный тип
// трактуются как «не перенаправлено»: тогда работает прежнее поведение, а не тишина.
func redirectedToFile(std uint32) bool {
	h, err := windows.GetStdHandle(std)
	if err != nil || h == 0 || h == windows.InvalidHandle {
		return false
	}
	t, err := windows.GetFileType(h)
	if err != nil {
		return false
	}
	return t == windows.FILE_TYPE_DISK || t == windows.FILE_TYPE_PIPE
}
