//go:build windows

package decommission

import "strings"

import "testing"

// Батч-делетер: корректная структура (ждёт, цикл по exe, rmdir остатков,
// самоудаление последней строкой), пути в кавычках.
func TestBuildDeleterScript(t *testing.T) {
	s := buildDeleterScript(`C:\Program Files\RoutineOps\RoutineOps-agent.exe`,
		[]string{`C:\ProgramData\RoutineOps`})

	must := []string{
		"@echo off",
		"ping 127.0.0.1 -n 4 >nul", // ожидание выхода агента
		`if not exist "C:\Program Files\RoutineOps\RoutineOps-agent.exe"`, // путь с пробелом в кавычках
		"goto bindone",
		`rmdir /s /q "C:\ProgramData\RoutineOps"`,
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
}

// Пустой план — ничего не планируем (nil-скрипт не собираем).
func TestBuildDeleterScript_OnlyDirs(t *testing.T) {
	s := buildDeleterScript("", []string{`C:\ProgramData\RoutineOps`})
	if strings.Contains(s, "goto bindone") {
		t.Error("без бинаря цикла удаления exe быть не должно")
	}
	if !strings.Contains(s, `rmdir /s /q "C:\ProgramData\RoutineOps"`) {
		t.Error("каталог должен сноситься")
	}
}
