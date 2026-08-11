//go:build !windows

package selfupdate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// replaceExecutable атомарно подменяет текущий исполняемый файл новым.
// На unix os.Rename в пределах той же ФС атомарен, а уже запущенный процесс
// продолжает работать со старым inode — безопасно заменить «себя» на ходу.
func replaceExecutable(data []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)

	tmp, err := os.CreateTemp(dir, ".agent-update-*")
	if err != nil {
		return fmt.Errorf("temp в %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // если до Rename не дошли — подчистим

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// На macOS бинарь может быть защищён флагом schg (tamper protection).
	// Перед заменой пытаемся снять флаг (best-effort, на Linux команда просто упадёт).
	_ = exec.Command("chflags", "noschg", exe).Run()

	if err := os.Rename(tmpName, exe); err != nil {
		// В случае ошибки возвращаем флаг на место
		_ = exec.Command("chflags", "schg", exe).Run()
		return fmt.Errorf("замена %s: %w", exe, err)
	}

	// Возвращаем защиту schg на новый бинарь
	_ = exec.Command("chflags", "schg", exe).Run()

	return nil
}

// SweepTemp и DropPrevious на unix не нужны: os.Rename переставляет бинарь одним
// шагом, а прежний inode держит сам запущенный процесс и освобождает его сам.
//
// 🔴 Обратная сторона, которую стоит назвать прямо: запасного файла на диске здесь
// не остаётся ВООБЩЕ. Windows после неудачного обновления восстанавливается копией
// из <exe>.old (так спасали стенд 10.08.2026), на macOS и Linux того же пути нет —
// там единственный способ вернуть агента в строй — переустановка пакета.
func SweepTemp()    {}
func DropPrevious() {}
