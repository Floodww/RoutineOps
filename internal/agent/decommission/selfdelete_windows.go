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
	// Снять трей/оверлей ДО планирования делетера: пока трей юзер-сессии жив, он держит
	// exe открытым, и Windows не даёт удалить ни бинарь, ни каталог установки. Здесь же
	// — убрать автозапуск трея (иначе поднимется на следующем логоне) и пустую ветку
	// флагов tamper. Это доводит серверный decommission до паритета с uninstall.bat.
	killResidualAgentProcesses(log)
	removeTrayAutostart(log)

	leftover = safeLeftover(leftover, log) // defense-in-depth перед rmdir /s /q
	// Каталог установки (Program Files\RoutineOps) целиком: MSI кладёт туда бинарь и
	// подкаталог certs, но в plan.Dirs они по отдельности не попадают (на Windows
	// CertDir/BinPath из Layout пусты). Без этого после сноса оставался бы пустой certs
	// и сам каталог. Сносится ПОСЛЕ удаления exe (он внутри) — см. buildDeleterScript.
	installDir := resolveInstallDir(binPath, log)
	// Штатное снятие MSI: находим ProductCode по стабильному UpgradeCode и планируем
	// `msiexec /x` в делетере — MSI сам уберёт свой бинарь, Run-ключ и запись в
	// «Установка и удаление программ» (ARP) вместе с регистрацией в Installer-БД, чего
	// ручной снос не делает. Запускается ПОСЛЕ выхода службы (см. buildDeleterScript):
	// бинарь на месте — msiexec отработает UnenrollExec. Не найден продукт → "" → шаг
	// пропускается, снос доводится ручными шагами.
	productCode, _ := resolveProductCode(log)

	if binPath == "" && installDir == "" && productCode == "" && len(leftover) == 0 {
		return nil
	}

	script := buildDeleterScript(binPath, installDir, productCode, leftover)
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

// resolveInstallDir возвращает каталог установки для полного сноса (rmdir /s /q) — или
// "" если сносить нельзя. binPath на Windows = os.Executable() (Relocate=false, lay.BinPath
// пуст), то есть МЕСТО ЗАПУСКА бинаря, а не гарантированно наш путь: при ручной установке
// из C:\Users\<op>\Downloads или размещении в C:\Windows\System32 filepath.Dir дал бы
// чужой/системный каталог, а isDangerousDir ловит только ТОЧНЫЕ c:\windows|program files|
// program files (x86)|users, но НЕ их подкаталоги (System32, Downloads). rmdir /s /q такого
// каталога необратимо снёс бы данные оператора/системы. Поэтому: сносим ТОЛЬКО когда
// basename каталога == installDirName ("RoutineOps" = Directory INSTALLFOLDER из wxs). Для
// штатной MSI-установки (…\RoutineOps) поведение не меняется; для чужого места установки
// каталог целиком не трогаем — сам файл добьёт exe-цикл. safeLeftover даёт тот же барьер,
// что и для leftover: isDangerousDir + отсев reparse-точек (junction/symlink).
func resolveInstallDir(binPath string, log *slog.Logger) string {
	if binPath == "" {
		return ""
	}
	dir := filepath.Dir(binPath)
	if !strings.EqualFold(filepath.Base(dir), installDirName) {
		log.Warn("decommission: каталог установки не сношу — имя не совпадает с ожидаемым (нештатное место запуска)",
			slog.String("dir", dir), slog.String("expected_base", installDirName))
		return ""
	}
	if safe := safeLeftover([]string{dir}, log); len(safe) == 1 {
		return safe[0]
	}
	return ""
}

// buildDeleterScript собирает батч: подождать выхода агента, снести остаточный трей
// (подстраховка на случай, если внутрипроцессный taskkill не сработал или трей успел
// подняться), штатно снять MSI (msiexec /x — уберёт бинарь, Run-ключ и ARP-запись),
// затем ПОДСТРАХОВОЧНО до 30 попыток снести exe (если msiexec не отработал), снести
// каталог установки и остаточные каталоги, добить очистку реестра, удалить сам батник
// (`del "%~f0"` последней строкой — известный приём самоудаления: cmd уже прочитал скрипт).
//
// Порядок важен: taskkill освобождает exe → msiexec (с живым бинарём для UnenrollExec)
// делает штатное снятие → ручные шаги добивают остаток, если msiexec недоступен/сбоил.
func buildDeleterScript(binPath, installDir, productCode string, leftover []string) string {
	var b strings.Builder
	b.WriteString("@echo off\r\n")
	// Дать процессу агента завершиться (SCM снимет службу, отпустятся хэндлы).
	b.WriteString("ping 127.0.0.1 -n 4 >nul\r\n")
	// Дерегистрировать службу ДО taskkill. Если внутрипроцессный StopService (service.
	// Uninstall) провалился, служба осталась зарегистрирована с FailureActions (рестарт
	// 5с, см. install_windows.go) — тогда безусловный `taskkill /F` уронил бы живую службу
	// с ненулевым кодом → SCM воскресил бы агента, и он снова держал бы exe, а цикл del
	// проиграл бы. sc stop+delete снимают регистрацию (пометка delete-pending гасит
	// recovery); при успешном StopService это no-op (службы уже нет). Как в uninstall.bat.
	fmt.Fprintf(&b, "sc stop %s >nul 2>&1\r\n", serviceName)
	fmt.Fprintf(&b, "sc delete %s >nul 2>&1\r\n", serviceName)
	// Подстраховка: снять трей/оверлей (это НЕ службы, SCM их не воскрешает), если
	// внутрипроцессный taskkill не отработал или трей успел подняться. Служба (self) к
	// этому моменту уже вышла и дерегистрирована выше. Освобождает exe до msiexec/ручного
	// удаления. `.old` — на случай зависшего процесса прерванного self-update (симметрично
	// внутрипроцессному killResidualAgentProcesses).
	fmt.Fprintf(&b, "taskkill /F /IM %s >nul 2>&1\r\n", agentImageName)
	fmt.Fprintf(&b, "taskkill /F /IM %s.old >nul 2>&1\r\n", agentImageName)
	// Штатное снятие MSI: удаляет бинарь, Run-ключ трея и запись в «Установка и удаление
	// программ» (ARP) с регистрацией в Installer-БД разом. /qn — тихо; /norestart — не
	// перезагружать (offboarding не должен ронять машину).
	//
	// Ретрай ровно на 1618 (ERROR_INSTALL_ALREADY_RUNNING — держит _MSIExecute другой
	// установкой): без него decommission во время cumulative-update молча оставил бы
	// ARP-запись — тот самый хвост, ради которого шаг добавлен. errorlevel: 0 — снято;
	// <1618 (1605 «не установлено», 5 «отказ») — выходим к фолбэку; >=1619 (вкл. 3010/
	// 1641 успех+нужен ребут, подавлен /norestart, и необслуживаемые 1619/1620) — тоже
	// выходим; ровно 1618 — ждём ~10с и повторяем. errorlevel НЕ проверяем после ping
	// (ping обнуляет его) — busy-ветка идёт последней в теле цикла.
	if productCode != "" {
		fmt.Fprintf(&b, "for /L %%%%m in (1,1,6) do (\r\n")
		fmt.Fprintf(&b, "  msiexec /x %s /qn /norestart >nul 2>&1\r\n", productCode)
		b.WriteString("  if not errorlevel 1 goto msidone\r\n")    // 0 — снято
		b.WriteString("  if not errorlevel 1618 goto msidone\r\n") // <1618 — не занят, выходим
		b.WriteString("  if errorlevel 1619 goto msidone\r\n")     // >=1619 (вкл. 3010/1641) — выходим
		b.WriteString("  ping 127.0.0.1 -n 11 >nul\r\n")           // ровно 1618 — занят: ждём и повторяем
		b.WriteString(")\r\n:msidone\r\n")
	}
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
	// Каталог установки — ПОСЛЕ удаления exe (он внутри): снимает пустой certs и сам каталог.
	if installDir != "" {
		fmt.Fprintf(&b, "rmdir /s /q \"%s\" >nul 2>&1\r\n", installDir)
	}
	// Подстраховка по реестру, если внутрипроцессная removeTrayAutostart не прошла.
	fmt.Fprintf(&b, "reg delete \"HKLM\\%s\" /v %s /f >nul 2>&1\r\n", runKeyPath, trayRunValue)
	fmt.Fprintf(&b, "reg delete \"HKLM\\%s\" /f >nul 2>&1\r\n", vendorKeyPath)
	b.WriteString("del /f /q \"%~f0\" >nul 2>&1\r\n")
	return b.String()
}
