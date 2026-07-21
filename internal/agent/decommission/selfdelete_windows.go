//go:build windows

package decommission

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// scheduleSelfDelete на Windows не может удалить запущенный .exe и каталоги с
// открытыми хэндлами, поэтому пишет самоудаляющийся .bat во %TEMP% и запускает
// его ОТСОЕДИНённым cmd.exe. Батник ждёт выхода процесса агента и в цикле сносит
// бинарь и остаточные каталоги, затем удаляет сам себя.
//
// Именно .bat, а не one-liner `cmd /c`: батч-контекст даёт корректные метки/goto
// и `%%i`, которые в командной строке `cmd /c` ведут себя иначе; плюс батник
// живёт вне удаляемых каталогов (во %TEMP%) и не держит их хэндлом.
func scheduleSelfDelete(binPath string, leftover []string, log *slog.Logger) error {
	leftover = safeLeftover(leftover, log) // defense-in-depth перед rmdir /s /q
	if binPath == "" && len(leftover) == 0 {
		return nil
	}

	script := buildDeleterScript(binPath, leftover)
	tmp, err := os.CreateTemp("", "routineops-rm-*.bat")
	if err != nil {
		return fmt.Errorf("создание bat-делетера: %w", err)
	}
	batPath := tmp.Name()
	if _, err := tmp.WriteString(script); err != nil {
		tmp.Close()
		return fmt.Errorf("запись bat-делетера: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("закрытие bat-делетера: %w", err)
	}

	cmd := exec.Command("cmd.exe", "/c", batPath)
	// Запускаем ИЗ %TEMP% (не из удаляемого каталога — иначе держали бы его хэндлом).
	cmd.Dir = filepath.Dir(batPath)
	// DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP|CREATE_NO_WINDOW: делетер переживает
	// выход агента и не висит на его консоли/группе, без мелькающего окна.
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP | 0x08000000,
	}
	if err := cmd.Start(); err != nil {
		_ = os.Remove(batPath)
		return fmt.Errorf("запуск отложенного делетера: %w", err)
	}
	log.Warn("decommission: отложенный делетер запущен — бинарь и остатки удалятся после выхода агента",
		slog.String("bin", binPath), slog.String("bat", batPath))
	return nil
}

// buildDeleterScript собирает батч: подождать выхода агента, до 30 попыток снести
// exe (пока SCM асинхронно доостанавливает службу и освобождается файл), снести
// остаточные каталоги, удалить сам батник (`del "%~f0"` последней строкой —
// известный приём самоудаления: cmd уже прочитал скрипт).
func buildDeleterScript(binPath string, leftover []string) string {
	var b strings.Builder
	b.WriteString("@echo off\r\n")
	// Дать процессу агента завершиться (SCM снимет службу, отпустятся хэндлы).
	b.WriteString("ping 127.0.0.1 -n 4 >nul\r\n")
	if binPath != "" {
		fmt.Fprintf(&b, "for /L %%%%i in (1,1,30) do (\r\n")
		fmt.Fprintf(&b, "  if not exist \"%s\" goto bindone\r\n", binPath)
		fmt.Fprintf(&b, "  del /f /q \"%s\" >nul 2>&1\r\n", binPath)
		b.WriteString("  ping 127.0.0.1 -n 2 >nul\r\n")
		b.WriteString(")\r\n:bindone\r\n")
	}
	for _, d := range leftover {
		fmt.Fprintf(&b, "rmdir /s /q \"%s\" >nul 2>&1\r\n", d)
	}
	b.WriteString("del /f /q \"%~f0\" >nul 2>&1\r\n")
	return b.String()
}
