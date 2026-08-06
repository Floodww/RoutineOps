//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// 🔴 Полевой факт, ради которого этот гейт написан.
//
// Агент линкуется -H windowsgui, и attachParentConsole подхватывал консоль родителя,
// БЕЗУСЛОВНО подменяя ею os.Stdout/os.Stderr. Родитель с консолью есть почти всегда
// (cmd, powershell, сессия sshd), поэтому подмена затирала дескрипторы, которые он выдал
// намеренно:
//
//	Start-Process agent -ArgumentList version -RedirectStandardOutput out.txt → out.txt пуст
//
// Наружу это выглядело как «агент не умеет писать в stdout вообще»: `version` отдавала
// ноль байт и код 0, а screen-probe — только код возврата, из-за чего полевая диагностика
// захвата на Windows не работала в принципе.
//
// Гейт проверяет ровно ту развилку, на которой всё держится, и в ОБЕ стороны: файл и пайп
// — это выбор родителя, его перебивать нельзя; консольный и невалидный дескриптор —
// наоборот, обязаны быть перебиты, иначе GUI-процесс пишет в консоль, к которой не
// привязан, и вывод исчезает.
func TestRedirectedToFileRespectsParentChoice(t *testing.T) {
	restore := func(std uint32, h windows.Handle) {
		if err := windows.SetStdHandle(std, h); err != nil {
			t.Fatalf("вернуть дескриптор: %v", err)
		}
	}

	orig, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		t.Fatalf("GetStdHandle: %v", err)
	}
	defer restore(windows.STD_OUTPUT_HANDLE, orig)

	// 1. Перенаправление в ФАЙЛ — трогать нельзя.
	f, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	if err != nil {
		t.Fatalf("создать файл: %v", err)
	}
	defer f.Close()
	if err := windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(f.Fd())); err != nil {
		t.Fatalf("SetStdHandle(файл): %v", err)
	}
	if !redirectedToFile(windows.STD_OUTPUT_HANDLE) {
		t.Fatal("файл не опознан как перенаправление — вывод снова уедет в консоль родителя, " +
			"и `-RedirectStandardOutput` останется пустым")
	}

	// 2. Перенаправление в ПАЙП (конвейер, .NET-редирект у Start-Process) — тоже выбор родителя.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer pr.Close()
	defer pw.Close()
	if err := windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(pw.Fd())); err != nil {
		t.Fatalf("SetStdHandle(пайп): %v", err)
	}
	if !redirectedToFile(windows.STD_OUTPUT_HANDLE) {
		t.Fatal("пайп не опознан как перенаправление — вывод в конвейер потерялся бы так же")
	}

	// 3. Невалидный дескриптор — перенаправления НЕТ, и подмена на CONOUT$ обязана
	// произойти. Без этой половины гейт зеленел бы на «считаем перенаправлением всё».
	if err := windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.InvalidHandle); err != nil {
		t.Fatalf("SetStdHandle(invalid): %v", err)
	}
	if redirectedToFile(windows.STD_OUTPUT_HANDLE) {
		t.Fatal("невалидный дескриптор принят за перенаправление — CLI-ветки (version, enroll, -h) " +
			"замолчали бы в интерактивной консоли")
	}
}
