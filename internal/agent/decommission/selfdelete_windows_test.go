//go:build windows

package decommission

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/agent/service"
)

const testProductCode = "{11111111-2222-3333-4444-555555555555}"

func testLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

// serviceName обязан совпадать с service.Name — по нему делетер дерегистрирует службу
// (sc stop/delete). Ренейм в пакете service разошёлся бы молча: sc промахнулся бы, служба
// осталась бы зарегистрирована с FailureActions и воскресила агента — симптом неотличим
// от исходного бага. Тот же класс дрейфа, что закрывает TestWxsContract для констант wxs.
func TestServiceNameMatchesServicePackage(t *testing.T) {
	if serviceName != service.Name {
		t.Errorf("serviceName=%q разошёлся с service.Name=%q — sc stop/delete промахнётся", serviceName, service.Name)
	}
}

// Батч-делетер: корректная структура (ждёт, дерегистрирует службу, снимает трей, штатно
// снимает MSI, цикл по exe, rmdir каталога установки и остатков, добивает реестр,
// самоудаление), пути в кавычках.
func TestBuildDeleterScript(t *testing.T) {
	s := buildDeleterScript(`C:\Program Files\RoutineOps\RoutineOps-agent.exe`,
		`C:\Program Files\RoutineOps`,
		testProductCode,
		[]string{`C:\ProgramData\RoutineOps`})

	must := []string{
		"@echo off",
		"ping 127.0.0.1 -n 4 >nul",                                    // ожидание выхода агента
		"sc stop RoutineOps-agent >nul 2>&1",                          // дерегистрация службы (гасит SCM recovery)
		"sc delete RoutineOps-agent >nul 2>&1",                        // ← до taskkill
		"taskkill /F /IM RoutineOps-agent.exe >nul 2>&1",              // снятие трея
		"taskkill /F /IM RoutineOps-agent.exe.old >nul 2>&1",          // .old прерванного self-update
		"for /L %%m in (1,1,6) do (",                                  // ретрай msiexec на «занят»
		"msiexec /x " + testProductCode + " /qn /norestart >nul 2>&1", // штатное снятие MSI
		":msidone", // метка выхода из ретрая
		`if not exist "C:\Program Files\RoutineOps\RoutineOps-agent.exe"`, // путь с пробелом в кавычках
		"goto bindone",
		`rmdir /s /q "C:\ProgramData\RoutineOps"`,                                           // остаточный каталог состояния
		`rmdir /s /q "C:\Program Files\RoutineOps"`,                                         // каталог установки (пустой certs + сам каталог)
		`reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v RoutineOpsTray`, // автозапуск трея
		`reg delete "HKLM\SOFTWARE\RoutineOps" /f`,                                          // пустая ветка флагов
		`del /f /q "%~f0"`, // самоудаление батника
	}
	for _, m := range must {
		if !strings.Contains(s, m) {
			t.Errorf("в скрипте нет фрагмента %q\nскрипт:\n%s", m, s)
		}
	}
	// del самого exe идёт ДО метки bindone (внутри цикла).
	if strings.Index(s, `del /f /q "C:\Program Files`) > strings.Index(s, ":bindone") {
		t.Error("удаление exe должно быть внутри цикла, до метки bindone")
	}
	// sc delete службы — ДО taskkill (иначе taskkill уронил бы живую службу → SCM recovery).
	if strings.Index(s, "sc delete ") > strings.Index(s, "taskkill /F /IM") {
		t.Error("sc delete службы должен идти до taskkill")
	}
	// taskkill трея — ДО цикла удаления exe (иначе живой трей держит файл).
	if strings.Index(s, "taskkill /F /IM") > strings.Index(s, "goto bindone") {
		t.Error("taskkill трея должен идти до цикла удаления exe")
	}
	// msiexec — ПОСЛЕ taskkill (exe освобождён), но ДО ручного удаления exe (msiexec
	// снимает штатно; ручной цикл — лишь фолбэк, если msiexec недоступен).
	taskkillAt, msiAt, bindoneAt := strings.Index(s, "taskkill /F /IM"), strings.Index(s, "msiexec /x"), strings.Index(s, "goto bindone")
	if taskkillAt >= msiAt || msiAt >= bindoneAt {
		t.Error("msiexec должен идти после taskkill и до ручного цикла удаления exe")
	}
	// Каталог установки сносится ПОСЛЕ удаления exe (exe внутри него).
	if strings.Index(s, `rmdir /s /q "C:\Program Files\RoutineOps"`) < strings.Index(s, ":bindone") {
		t.Error("снос каталога установки должен идти после удаления exe (после метки bindone)")
	}
}

// resolveInstallDir сносит каталог установки ТОЛЬКО когда его basename == "RoutineOps"
// (INSTALLFOLDER из wxs). Место запуска бинаря (os.Executable) может быть чужим/системным
// каталогом — его rmdir /s /q необратимо снёс бы данные оператора/системы (находка #1).
func TestResolveInstallDir(t *testing.T) {
	tests := []struct {
		name    string
		binPath string
		want    string
	}{
		{"штатная MSI-установка", `C:\Program Files\RoutineOps\RoutineOps-agent.exe`, `C:\Program Files\RoutineOps`},
		{"регистр не важен", `c:\program files\routineops\RoutineOps-agent.exe`, `c:\program files\routineops`},
		{"System32 НЕ сносим", `C:\Windows\System32\RoutineOps-agent.exe`, ""},
		{"Downloads оператора НЕ сносим", `C:\Users\admin\Downloads\RoutineOps-agent.exe`, ""},
		{"пустой путь", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveInstallDir(tt.binPath, testLog()); got != tt.want {
				t.Errorf("resolveInstallDir(%q)=%q, want %q", tt.binPath, got, tt.want)
			}
		})
	}
}

// Нештатное место запуска (installDir="") → каталога в rmdir скрипта НЕТ, сносится только exe.
func TestBuildDeleterScript_NonInstallDirNotRemoved(t *testing.T) {
	s := buildDeleterScript(`C:\Windows\System32\RoutineOps-agent.exe`, "", "", nil)
	if strings.Contains(s, `rmdir /s /q "C:\Windows`) {
		t.Errorf("нештатный каталог не должен сноситься rmdir:\n%s", s)
	}
	if !strings.Contains(s, "goto bindone") {
		t.Error("сам exe всё равно должен удаляться (цикл на месте)")
	}
}

// Продукт MSI не найден (productCode="") — строки msiexec нет, снос идёт ручными шагами.
func TestBuildDeleterScript_NoProductCode(t *testing.T) {
	s := buildDeleterScript(`C:\Program Files\RoutineOps\RoutineOps-agent.exe`,
		`C:\Program Files\RoutineOps`, "", nil)
	if strings.Contains(s, "msiexec") {
		t.Error("без ProductCode строки msiexec быть не должно")
	}
	if !strings.Contains(s, "goto bindone") {
		t.Error("ручное удаление exe должно остаться как фолбэк")
	}
}

// Без бинаря цикла удаления exe нет, но службу, реестр и трей всё равно добиваем.
func TestBuildDeleterScript_OnlyDirs(t *testing.T) {
	s := buildDeleterScript("", "", "", []string{`C:\ProgramData\RoutineOps`})
	if strings.Contains(s, "goto bindone") {
		t.Error("без бинаря цикла удаления exe быть не должно")
	}
	if !strings.Contains(s, `rmdir /s /q "C:\ProgramData\RoutineOps"`) {
		t.Error("каталог должен сноситься")
	}
	if !strings.Contains(s, "sc delete RoutineOps-agent") {
		t.Error("дерегистрация службы должна выполняться даже без бинаря")
	}
	if !strings.Contains(s, `reg delete "HKLM\SOFTWARE\RoutineOps" /f`) {
		t.Error("очистка реестра должна выполняться даже без бинаря")
	}
}
