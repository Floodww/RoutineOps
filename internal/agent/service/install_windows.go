//go:build windows

package service

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Install регистрирует службу в SCM с автозапуском и СРАЗУ её стартует (нужны
// права администратора).
//
// Идемпотентна: если служба уже стоит (прошлая версия MSI, апгрейд, ручная
// распаковка установщика с другим путём к бинарю), она снимается и ставится
// заново. Без этого CreateService падал бы «служба уже установлена», enroll
// -install-service возвращал бы ошибку → MSI (Return=check) откатывал бы ВСЮ
// установку, выметая файлы из Program Files (полевой баг v22).
//
// Старт выполняется здесь же: служба регистрируется AUTO_START, но SCM при
// установке сам её не запускает — после `msiexec /qn` она оставалась STOPPED
// (WIN32_EXIT_CODE 1077 «never started»), и оператор стартовал её вручную. Linux
// (systemctl enable --now) и macOS (RunAtLoad) стартуют службу в Install —
// приводим Windows к тому же контракту: одна команда установки = служба работает.
func Install(cfg Config) error {
	exe, err := exePath(cfg)
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("подключение к SCM (нужен админ?): %w", err)
	}
	defer m.Disconnect()

	// Снять прежнюю службу с тем же именем (любой путь к бинарю), если есть.
	if err := stopDeleteWait(m, Name); err != nil {
		return fmt.Errorf("снятие существующей службы %s перед переустановкой: %w", Name, err)
	}

	s, err := m.CreateService(Name, exe, mgr.Config{
		DisplayName: displayName,
		Description: description,
		StartType:   mgr.StartAutomatic,
	}, append([]string{"run"}, cfg.Args...)...)
	if err != nil {
		return err
	}
	defer s.Close()

	// Перезапуск службы при ненулевом завершении: нужен и для падений, и для
	// штатного перезапуска после самообновления (агент выходит с ошибкой, чтобы
	// SCM поднял новый бинарь). Сброс счётчика — раз в сутки.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400); err != nil {
		return fmt.Errorf("настройка автоперезапуска службы: %w", err)
	}

	// Старт — НЕ фатально для регистрации: если SCM откажет, служба остаётся
	// зарегистрированной (AUTO_START + recovery), и вызывающий по ErrServiceStartFailed
	// продолжит хардненинг/трей/чистку, а не свалится, пропустив их.
	if err := s.Start(); err != nil {
		return fmt.Errorf("%w (%s): %v", ErrServiceStartFailed, Name, err)
	}
	return nil
}

// stopDeleteWait снимает службу name, если она зарегистрирована: останавливает
// (best-effort) и удаляет, затем ждёт фактического исчезновения имени из SCM.
// Delete асинхронный — пока есть открытые хэндлы или служба не остановлена, имя
// остаётся помеченным на удаление (ERROR_SERVICE_MARKED_FOR_DELETE), и немедленный
// повторный CreateService упал бы. Если службы нет — это не ошибка (ставим сразу).
func stopDeleteWait(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return nil // службы нет
	}
	if _, err := s.Control(svc.Stop); err == nil {
		waitState(s, svc.Stopped, 20*time.Second)
	}
	delErr := s.Delete()
	s.Close()
	if delErr != nil {
		return fmt.Errorf("удаление службы: %w", delErr)
	}
	// Дождаться, пока имя освободится (OpenService начнёт давать ошибку).
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		probe, oerr := m.OpenService(name)
		if oerr != nil {
			return nil // имя свободно
		}
		probe.Close()
		time.Sleep(300 * time.Millisecond)
	}
	return nil // не дождались — пусть CreateService вернёт явную ошибку
}

// waitState ждёт перехода службы в нужное состояние до timeout (best-effort:
// по таймауту просто возвращается, не считая это ошибкой).
func waitState(s *mgr.Service, want svc.State, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil || st.State == want {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// hardenedServiceSDDL — DACL службы. SYSTEM и Administrators управляют полностью;
// интерактивные (IU) и служебные (SU) пользователи могут только читать статус и
// конфиг и опрашивать службу, но НЕ запускать/останавливать/паузить (нет RP/WP/DT).
// Так обычный пользователь не остановит агента через `sc stop` или Services.msc.
// Права службы в SDDL: CC=QueryConfig, DC=ChangeConfig, LC=QueryStatus,
// SW=EnumDependents, RP=Start, WP=Stop, DT=PauseContinue, LO=Interrogate,
// CR=UserDefinedControl; RC/SD/WD/WO — ReadControl/Delete/WriteDac/WriteOwner.
const hardenedServiceSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)" +
	"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
	"(A;;CCLCSWLOCRRC;;;IU)" +
	"(A;;CCLCSWLOCRRC;;;SU)"

// Harden ужесточает DACL службы, чтобы её не мог остановить непривилегированный
// пользователь (требование «нельзя закрыть»). Идемпотентна — DACL ставится
// PROTECTED, чтобы наследуемые ACE не вернули право остановки. От локального
// администратора защиты нет (он может переустановить DACL) — это вне объёма.
func Harden() error {
	sd, err := windows.SecurityDescriptorFromString(hardenedServiceSDDL)
	if err != nil {
		return fmt.Errorf("разбор SDDL службы: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("извлечение DACL из SDDL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		Name, windows.SE_SERVICE,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("установка DACL службы %s: %w", Name, err)
	}
	return nil
}

// Uninstall удаляет службу из SCM, предварительно остановив её (иначе exe остаётся
// залоченным — каталог установки не удалить, — а служба висит «marked for delete»
// до перезагрузки).
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("подключение к SCM (нужен админ?): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(Name)
	if err != nil {
		return fmt.Errorf("служба %s не найдена: %w", Name, err)
	}
	defer s.Close()
	if _, serr := s.Control(svc.Stop); serr == nil {
		waitState(s, svc.Stopped, 20*time.Second)
	}
	return s.Delete()
}

// agentImageName — имя образа агента. То же, что кладёт MSI (File Name в авторинге).
const agentImageName = "RoutineOps-agent.exe"

// StopUserProcesses снимает процессы агента в ПОЛЬЗОВАТЕЛЬСКИХ сессиях: трей и оверлей
// блокировки.
//
// 🔴 Снятия службы недостаточно, и это поймано в поле. Трей живёт в сессии вошедшего
// пользователя, службой не является и после `sc delete` продолжает работать — а вместе с
// ним остаётся ОТКРЫТЫМ `RoutineOps-agent.exe`. Удаление каталога об это спотыкается:
// «Отказано в доступе к файлу RoutineOps-agent.exe», каталог остаётся, и выглядит это
// как «удаление не сработало». Тот же хвост получал и MSI: файлы, занятые живым
// процессом, он оставляет до перезагрузки.
//
// Безусловный taskkill здесь безопасен ровно потому, что зовётся ПОСЛЕ снятия службы:
// трей и оверлей не службы, и воскрешать их через FailureActions некому. Себя процесс не
// трогает — фильтр по PID: иначе снос убил бы сам себя на середине.
//
// Best-effort: код возврата 1 у taskkill означает «процессов не найдено» (никто не
// залогинен), и это норма, а не сбой.
func StopUserProcesses(log *slog.Logger) {
	filter := fmt.Sprintf("PID ne %d", os.Getpid())
	// `.exe.old` — запущенный старый бинарь незавершённого самообновления: держит файл
	// точно так же.
	for _, image := range []string{agentImageName, agentImageName + ".old"} {
		_ = exec.Command("taskkill", "/F", "/IM", image, "/FI", filter).Run()
	}
	log.Info("остаточные процессы агента (трей, оверлей) сняты", slog.Int("keep_pid", os.Getpid()))
}

// legacyDirs — каталоги ПРЕЖНИХ (ручных) установок агента, которые MSI не
// отслеживает как свои компоненты и потому сам не удаляет: при ручной распаковке
// MSI служба ставилась из C:\mdm-extract. После перехода на штатную установку их
// надо подчистить, чтобы не осталось параллельной копии бинаря/состояния.
var legacyDirs = []string{
	`C:\mdm-extract`,
}

// RemoveLegacyArtifacts удаляет следы ручных установок (каталоги legacyDirs).
// Службу RoutineOps-agent с любым путём к бинарю снимает сам Install (по имени, через
// stopDeleteWait) — здесь добиваем оставшиеся каталоги. Best-effort: ошибки лишь
// логируются (легаси может отсутствовать — это норма). Каталог, внутри которого
// лежит текущий бинарь, не трогаем (страховка от самоудаления).
func RemoveLegacyArtifacts(log *slog.Logger) {
	self, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	selfDir := filepath.Dir(self)
	for _, d := range legacyDirs {
		// Lstat (не Stat): если кто-то подменил C:\mdm-extract на symlink/junction,
		// os.RemoveAll под SYSTEM мог бы целиться в каталог-цель. Реально создать что-то
		// в корне C:\ может только админ/SYSTEM, но защищаемся явно — репарс-точку пропускаем.
		fi, err := os.Lstat(d)
		if err != nil {
			continue // нет такого каталога
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			log.Warn("legacy: пропускаю — каталог оказался symlink/junction (возможная подмена)",
				slog.String("dir", d))
			continue
		}
		if selfDir != "" && strings.EqualFold(filepath.Clean(d), filepath.Clean(selfDir)) {
			log.Warn("legacy: пропускаю каталог — из него запущен текущий бинарь", slog.String("dir", d))
			continue
		}
		if err := os.RemoveAll(d); err != nil {
			log.Warn("legacy: не удалось удалить каталог прежней установки",
				slog.String("dir", d), slog.Any("error", err))
			continue
		}
		log.Info("legacy: удалён каталог прежней установки", slog.String("dir", d))
	}
}
