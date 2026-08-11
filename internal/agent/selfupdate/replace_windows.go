//go:build windows

package selfupdate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// replaceExecutable подменяет текущий исполняемый файл на Windows. Запущенный
// .exe удалить нельзя, но можно переименовать: отодвигаем текущий в .old и
// ставим новый на его место. Замена АТОМАРНА: новый бинарь сперва пишется во
// временный файл (пока текущий exe на месте и рабочий), синкается на диск, и
// лишь затем два быстрых rename переставляют файлы. Прежний прямой
// os.WriteFile(exe) держал exe частичным/битым на весь объём записи (~20МБ):
// краш/сбой питания посреди неё оставлял 0-байтный агент без восстановления —
// SCM крутил бы crash-loop, требовалась ручная переустановка MSI. Старый .old
// удалится при следующем запуске (до перезапуска он ещё занят процессом).
func replaceExecutable(data []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	old := exe + ".old"
	dir := filepath.Dir(exe)

	// Крупная I/O — при живом exe: если тут краш, текущий бинарь цел, .tmp
	// останется мусором и будет подметён CleanupOld при следующем старте.
	tmp, err := os.CreateTemp(dir, ".routineops-upd-*.exe")
	if err != nil {
		return fmt.Errorf("создание временного .exe: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("запись нового .exe: %w", err)
	}
	if err := tmp.Sync(); err != nil { // durable на диск ДО rename
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("fsync нового .exe: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("закрытие нового .exe: %w", err)
	}

	// Убиваем другие экземпляры (например, tray в юзер-сессии), чтобы они
	// отпустили блокировку файла .old от прошлого обновления.
	//
	// Кроме тех, чьё завершение обязано быть штатным: захватчик экрана запускается ТЕМ
	// ЖЕ exe и под /IM попадает гарантированно, а /F — это TerminateProcess без
	// финализации записи сеанса и без события (§9.1 контракта удалённого стола).
	baseExe := filepath.Base(exe)
	keep := protectedPIDs()
	_ = exec.Command("taskkill", taskkillArgs(baseExe, os.Getpid(), keep)...).Run()
	_ = exec.Command("taskkill", taskkillArgs(baseExe+".old", os.Getpid(), keep)...).Run()

	_ = os.Remove(old) // подчистить .old от прошлого обновления (если уже не занят)

	// Только теперь два rename — окно, где exe отсутствует, сведено к паре
	// метаданных-операций (микросекунды), а не к 20МБ записи.
	if err := os.Rename(exe, old); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("отодвинуть текущий .exe: %w", err)
	}
	if err := os.Rename(tmpName, exe); err != nil {
		_ = os.Rename(old, exe) // откат: вернуть рабочий бинарь на место
		os.Remove(tmpName)
		return fmt.Errorf("публикация нового .exe: %w", err)
	}
	return nil
}

// SweepTemp подметает осиротевшие temp-файлы прерванного апдейта
// (.routineops-upd-*.exe): best-effort, вызывать при старте — прошлый процесс их уже
// не держит. Без подметания повторные неудачные апдейты (краш/сбой питания в окне
// записи) копили бы ~20МБ-файлы в каталоге установки без верхней границы.
//
// 🔴 <exe>.old отсюда убран намеренно, см. DropPrevious.
func SweepTemp() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(exe), ".routineops-upd-*.exe")); err == nil {
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
}

// DropPrevious удаляет прежний бинарь <exe>.old, оставшийся после самообновления.
//
// 🔴 Зовётся не при старте, а после того, как работающая версия себя ПОДТВЕРДИЛА
// (selfupdate.confirmRunning). Прежде удаление стояло в самом начале main: агент,
// который поднялся и умер через две секунды (несовместимая DLL, паника на старте,
// битая сборка), успевал снести единственный путь восстановления ещё до того, как
// сломаться, — а SCM дальше крутил бы crash-loop уже без запасного бинаря. Именно
// .old спас стенд после инцидента с подписанным мусором 10.08.2026.
//
// Одним файлом всё и ограничено: replaceExecutable сам удаляет .old перед тем, как
// отодвинуть туда текущий exe, так что накопления не будет даже при выключенном
// самообновлении.
func DropPrevious() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	_ = os.Remove(exe + ".old")
}
