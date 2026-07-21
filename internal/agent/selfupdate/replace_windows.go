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
	baseExe := filepath.Base(exe)
	_ = exec.Command("taskkill", "/F", "/IM", baseExe, "/FI", fmt.Sprintf("PID ne %d", os.Getpid())).Run()
	_ = exec.Command("taskkill", "/F", "/IM", baseExe+".old", "/FI", fmt.Sprintf("PID ne %d", os.Getpid())).Run()

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

// CleanupOld удаляет оставшийся после обновления <exe>.old И осиротевшие
// temp-файлы прерванного апдейта (.routineops-upd-*.exe): best-effort, вызывать
// при старте — прошлый процесс их уже не держит. Без подметания temp повторные
// неудачные апдейты (краш/сбой питания в окне записи) копили бы ~20МБ-файлы в
// каталоге установки без верхней границы.
func CleanupOld() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	_ = os.Remove(exe + ".old")
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(exe), ".routineops-upd-*.exe")); err == nil {
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
}
