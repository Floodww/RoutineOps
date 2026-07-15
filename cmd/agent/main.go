// Command agent — MDM-агент.
//
// Подкоманды:
//
//	agent enroll     — получить mTLS-сертификат по одноразовому токену (Этап 3)
//	agent run        — запустить агент (по умолчанию; под launchd/Windows Service или в консоли)
//	agent install    — зарегистрировать системную службу (нужны root/админ)
//	agent uninstall  — снять службу
//	agent tray       — иконка статуса в системном трее (Windows, per-user процесс)
//	agent tamper-*   — защита от удаления: status/disarm/cleanup (Windows: SafeBoot+реестр,
//	                   macOS: immutable-флаг schg; на Linux защиты нет — см. internal/agent/tamper)
//	agent version    — версия и параметры сборки
//
// Флаги (-server, -cert, …) идут после подкоманды и при install сохраняются в
// конфигурацию службы. Пути к сертификатам при install указывайте абсолютными.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/admin"
	"github.com/Floodww/RoutineOps/internal/agent/applog"
	"github.com/Floodww/RoutineOps/internal/agent/collector"
	"github.com/Floodww/RoutineOps/internal/agent/command"
	"github.com/Floodww/RoutineOps/internal/agent/config"
	"github.com/Floodww/RoutineOps/internal/agent/enroll"
	"github.com/Floodww/RoutineOps/internal/agent/heartbeat"
	"github.com/Floodww/RoutineOps/internal/agent/inventory"
	"github.com/Floodww/RoutineOps/internal/agent/keystore"
	"github.com/Floodww/RoutineOps/internal/agent/lock"
	"github.com/Floodww/RoutineOps/internal/agent/lockui"
	"github.com/Floodww/RoutineOps/internal/agent/outbox"
	"github.com/Floodww/RoutineOps/internal/agent/policy"
	"github.com/Floodww/RoutineOps/internal/agent/scripts"
	"github.com/Floodww/RoutineOps/internal/agent/security"
	"github.com/Floodww/RoutineOps/internal/agent/selfupdate"
	"github.com/Floodww/RoutineOps/internal/agent/service"
	"github.com/Floodww/RoutineOps/internal/agent/status"
	"github.com/Floodww/RoutineOps/internal/agent/tamper"
	"github.com/Floodww/RoutineOps/internal/agent/transport"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// version проставляется при сборке через -ldflags "-X main.version=...".
var version = "dev"

// releasePubKey — base64 ed25519 публичного ключа релиза, ВШИВАЕТСЯ в бинарь при
// сборке релиза через -ldflags "-X main.releasePubKey=<base64>". Так публичный
// ключ нельзя подменить через env/флаг в проде (это снизило бы доверие к
// самообновлению). -update-pubkey/ROUTINEOPS_UPDATE_PUBKEY остаётся для dev-override.
var releasePubKey = ""

// FileVault escrow (age-recipient пиннинг + цепочка internal/agent/filevault) — это
// enterprise-фича. Ldflags-символы main.escrowRecipient/escrowRecipientFpr и вся
// проводка живут в filevault_wiring.go (//go:build enterprise); free-стаб —
// filevault_stub.go. Open-core-агент escrow не собирает (нет age в графе).

func main() {
	// exe собран как GUI-subsystem (-H windowsgui), чтобы трей не открывал
	// консольное окно в юзер-сессии (его закрытие убивало агент). Для ручных
	// CLI-веток (enroll/version/-h) привязываем вывод к консоли родителя, если
	// запущены из неё; для службы/трея/MSI — безопасный no-op. На !windows пусто.
	attachParentConsole()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Подкоманда — первый не-флаговый аргумент (по умолчанию run).
	cmd, rest := "run", os.Args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		cmd, rest = rest[0], rest[1:]
	}

	// Глобальная справка с примерами — до разбора флагов (иначе config.Load на -h
	// вернул бы ErrHelp с голым списком флагов без сценариев использования).
	if cmd == "help" || hasHelpFlag(rest) {
		printUsage(os.Stdout)
		return
	}

	cfg, err := config.Load(flag.NewFlagSet("agent", flag.ContinueOnError), rest)
	if err != nil {
		log.Error("конфигурация", slog.Any("error", err))
		os.Exit(2)
	}

	switch cmd {
	case "enroll":
		// MSI запускает enroll под SYSTEM и ИГНОРИРУЕТ его код возврата (EnrollExec
		// стоит Return="ignore", чтобы сбой не откатывал раскладку файлов), а stderr
		// при /qn не виден нигде. Итог в поле (13.07): enroll упал на TLS, файлы лежат,
		// службы нет, причины не найти — лога просто не существовало. Пишем в тот же
		// файл, что и служба: это единственное место, куда смотрят при разборе.
		if lg, closer, lerr := applog.NewServiceLogger(service.LogFilePath(), slog.LevelInfo); lerr == nil {
			defer closer.Close()
			log = lg
		} // не удалось (ручной enroll под обычным юзером) — остаёмся на stderr
		if err := runEnroll(cfg, log); err != nil {
			log.Error("энроллмент", slog.Any("error", err))
			os.Exit(1)
		}
	case "run":
		// Под службой stderr уходит в никуда (Windows) — дублируем лог в файл, иначе
		// причину «служба не стартует / не подключается» в поле не увидеть.
		logPath := service.LogFilePath()
		if lg, closer, lerr := applog.NewServiceLogger(logPath, slog.LevelInfo); lerr != nil {
			log.Warn("файловый лог службы недоступен, пишу только в stderr",
				slog.String("path", logPath), slog.Any("error", lerr))
		} else {
			defer closer.Close()
			log = lg
			log.Info("лог службы пишется в файл", slog.String("path", logPath))
		}
		runAgentService(cfg, log)
	case "request-admin":
		dialer, err := buildDialer(cfg)
		if err != nil {
			log.Error("инициализация mTLS", slog.Any("error", err))
			os.Exit(1)
		}
		if err := admin.RequestAdmin(context.Background(), dialer, cfg.Reason, log); err != nil {
			log.Error("запрос прав администратора", slog.Any("error", err))
			os.Exit(1)
		}
	case "install":
		if err := service.Install(service.Config{Args: rest}); err != nil {
			// Частичные сбои (не встал трей на macOS; служба зарегистрирована, но не
			// стартовала сразу на Windows) не должны выбрасывать нас с os.Exit(1) ДО
			// Harden и tamper.Arm — иначе агент остаётся установленным, но незащищённым.
			if serviceInstallFatal(err) {
				log.Error("установка службы", slog.Any("error", err))
				os.Exit(1)
			}
			log.Warn("служба установлена частично — продолжаю настройку", slog.Any("error", err))
		}
		if err := service.Harden(); err != nil {
			log.Warn("не удалось ужесточить права службы (остановить сможет и непривилегированный пользователь)",
				slog.Any("error", err))
		}
		// Tamper-protection: взвести защиту от удаления (Windows). Регистрирует службу
		// в SafeBoot, чтобы её нельзя было снести из безопасного режима; снятие — по
		// процедуре «безопасный режим → tamper-disarm → reboot → uninstall.bat».
		if err := tamper.Arm(log); err != nil {
			log.Warn("не удалось взвести tamper-protection (агент устанавливается без защиты от удаления)",
				slog.Any("error", err))
		}
		log.Info("служба установлена", slog.String("name", service.Name),
			slog.String("note", "если запускали не под root/админом — активируйте службу с повышенными правами"))
	case "uninstall":
		if err := service.Uninstall(); err != nil {
			log.Error("удаление службы", slog.Any("error", err))
			os.Exit(1)
		}
		// Заодно подчистить следы прежних ручных установок (C:\mdm-extract) — best-effort.
		service.RemoveLegacyArtifacts(log)
		log.Info("служба удалена", slog.String("name", service.Name))
	case "cleanup-legacy":
		// Снять следы прежних (ручных) установок: каталоги вроде C:\mdm-extract.
		// Идемпотентно; зовётся uninstall.bat и при ручной починке полевых машин.
		service.RemoveLegacyArtifacts(log)
		log.Info("legacy-артефакты прежних установок очищены")
	case "tray":
		runTray(cfg)
	case "lock-screen":
		// Полноэкранный замок в юзер-сессии (запускается треем при блокировке).
		// Служба (session 0) GUI показать не может — отсюда отдельный процесс.
		lockui.Run(lockStatePath(cfg), log)
	case "version":
		printVersion(os.Stdout, cfg)
	case "diag":
		os.Exit(runDiagCommand(os.Stdout, cfg))
	case "tamper-status":
		// Показать состояние защиты от удаления. Механизм и процедура снятия у платформ
		// принципиально разные (Windows — флаги в реестре + SafeBoot со сторожем; macOS —
		// schg, который держит ядро), поэтому отчёт собирает чистая tamperStatusReport по
		// runtime.GOOS: раньше и формат, и подсказка были Windows-only, и оператор мака
		// читал про безопасный режим, HKLM и uninstall.bat, которых у него нет.
		p, g, safe := tamper.Status()
		fmt.Print(tamperStatusReport(runtime.GOOS, p, g, safe))
	case "tamper-disarm":
		// Разоружить защиту. Windows: сработает только в безопасном режиме (в обычном сторож
		// перевзведёт флаги обратно — об этом скажет ошибка). macOS: chflags noschg, нужен
		// root; это ОБЯЗАТЕЛЬНЫЙ шаг перед uninstall — под schg даже root не удалит бинарь и
		// plist'ы. Прочие ОС: tamper.ErrUnsupported.
		if err := tamper.Disarm(); err != nil {
			log.Error("разоружение tamper-protection", slog.Any("error", err))
			os.Exit(1)
		}
		log.Info(tamperDisarmDoneMsg(runtime.GOOS))
	case "tamper-cleanup":
		// Снять SafeBoot-регистрацию и удалить ветку флагов. Вызывается uninstall.bat
		// после разоружения и reboot в обычный режим.
		tamper.Cleanup()
		log.Info("tamper-protection: SafeBoot-ключи и флаги удалены")
	case "filevault-provision":
		// Дозавершение FileVault-provisioning на уже энролленном устройстве —
		// путь для headless-постустановки (build/pkg/build-pkg.sh postinstall
		// работает без TTY, ProvisionAtEnroll там пропускается, см. enroll.go
		// ProvisionResult.SkipReason). Требует ИНТЕРАКТИВНОГО запуска (TTY) —
		// сам захват пароля сотрудника, как и на энролле.
		if err := runFileVaultProvision(cfg, log); err != nil {
			log.Error("filevault-provision", slog.Any("error", err))
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда: %q\n\n", cmd)
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

// hasHelpFlag сообщает, есть ли в аргументах флаг запроса справки.
func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "-help" || a == "--help" {
			return true
		}
	}
	return false
}

// printUsage печатает справку с командами, ключевыми флагами и реальными
// примерами развёртывания (enroll+install «в одну команду», cert-source=keystore).
func printUsage(w io.Writer) {
	fmt.Fprintf(w, `RoutineOps-agent %s — RMM/MDM агент

ИСПОЛЬЗОВАНИЕ:
  agent <команда> [флаги]        (без команды → run)

КОМАНДЫ:
  enroll          получить mTLS-сертификат по одноразовому токену
  run             запустить агент (по умолчанию)
  install         зарегистрировать и запустить системную службу (нужны root/админ)
  uninstall       снять службу
  cleanup-legacy  удалить следы прежних ручных установок (Windows: C:\mdm-extract)
  request-admin   запросить временные права администратора
  diag            диагностика: конфиг, сертификат, (опц.) проба связи
  tray            иконка статуса в трее (Windows и macOS, per-user)
%s
  filevault-provision  дозавершить FileVault-provisioning (macOS, интерактивно,
                  для устройств, где enroll прошёл без TTY — postinstall)
  version         версия и параметры сборки
  help            эта справка

КЛЮЧЕВЫЕ ФЛАГИ (идут ПОСЛЕ команды; каждый можно задать через env):
  Связь:
    -server host:port           адрес gRPC-сервера (ROUTINEOPS_SERVER_ADDR)
    -server-name name           ожидаемое имя в серверном сертификате
  mTLS-материал:
    -cert / -key / -ca PATH     клиентский серт, ключ, корневой CA
    -cert-source file|keystore  источник идентичности (keystore = хранилище ОС)
    -keystore-label id          метка в keystore (обычно device_id = CN)
  Энроллмент (команда enroll):
    -enroll-url URL             эндпоинт энроллмента (.../api/v1/enroll)
    -token TOKEN                одноразовый enrollment-токен
    -ca-url URL                 откуда скачать CA, если -ca нет на диске
    -ca-sha256 HEX              пин sha256 CA-бандла (против MITM при -ca-url)
    -install-service            после enroll сразу зарегистрировать службу
  Диагностика:
    -probe                      diag: дополнительно проверить mTLS-соединение

  Полный список флагов с дефолтами: agent run -h

ПРИМЕРЫ:
  # Энроллмент «в одну команду»: получить серт, скачать CA, поставить службу.
  # Запускать от администратора/root (служба под LocalSystem/root). -ca-sha256
  # ОБЯЗАТЕЛЕН при -ca-url (TOFU-скачивание без пина отклоняется, см. -ca-sha256
  # выше) — либо разложите CA локальным файлом через -ca и уберите -ca-url.
  agent enroll -enroll-url https://routineops.example:8081/api/v1/enroll \
    -token <one-time-token> -ca-url https://routineops.example:8081/ca.crt \
    -ca-sha256 <hex-sha256-ca.crt> -server routineops.example:50051 -install-service

  # То же, но идентичность в защищённом хранилище ОС (Keychain/NCrypt).
  # cert-source=keystore + install-service ОБЯЗАТЕЛЬНО от админа/root.
  agent enroll -enroll-url https://routineops.example:8081/api/v1/enroll \
    -token <one-time-token> -ca-url https://routineops.example:8081/ca.crt \
    -ca-sha256 <hex-sha256-ca.crt> -server routineops.example:50051 \
    -cert-source keystore -install-service

  # Ручной запуск в консоли (отладка), файловые серты.
  agent run -server routineops.example:50051 \
    -cert certs/agent.crt -key certs/agent.key -ca certs/ca.crt

  # Запуск с идентичностью из keystore (ключа на диске нет).
  agent run -server routineops.example:50051 -cert-source keystore

  # Диагностика на устройстве (конфиг, серт, проба связи).
  agent diag -server routineops.example:50051 -probe

  # Запросить временные права администратора.
  agent request-admin -server routineops.example:50051 -reason "установка ПО"

ЗАМЕЧАНИЯ:
  • При install/enroll -install-service пути к сертам сохраняются в конфиг службы —
    указывайте их абсолютными (служба стартует с произвольным рабочим каталогом).
  • Для удалённого устройства всегда передавайте реальный -server host:port:
    без него служба уедет в localhost и не подключится.
`, version, tamperUsage(runtime.GOOS))
}

// tamperUsage возвращает строки справки по tamper-командам для конкретной ОС.
// Механизмы у платформ разные: Windows — SafeBoot-регистрация плюс флаги в реестре,
// которые перевзводит сторож; macOS — immutable-флаг schg, его держит ядро и сторож
// не нужен; Linux — защиты нет вовсе. Единый Windows-текст врал оператору мака: он
// видел работающую команду, описанную как «только Windows», и не делал disarm перед
// uninstall (а без него удаление упирается в schg). Функция чистая и параметризована
// goos — чтобы текст проверялся тестом с любой платформы.
func tamperUsage(goos string) string {
	switch goos {
	case "windows":
		return `  tamper-status   состояние защиты от удаления: флаги в реестре + режим загрузки
  tamper-disarm   разоружить защиту (только из безопасного режима: в обычном сторож
                  вернёт флаги обратно)
  tamper-cleanup  снять SafeBoot-регистрацию и флаги защиты (для uninstall.bat)`
	case "darwin":
		return `  tamper-status   состояние защиты от удаления: флаг schg на бинаре и Launch-plist'ах
  tamper-disarm   снять schg (chflags noschg, нужен root). ОБЯЗАТЕЛЕН ПЕРЕД uninstall:
                  под schg файлы не удалить даже под root
  tamper-cleanup  no-op на macOS: флаги снимает tamper-disarm`
	default:
		return `  tamper-status   состояние защиты от удаления (на этой ОС защиты нет — всегда нули)
  tamper-disarm   не поддерживается: tamper-protection на этой ОС не реализована
  tamper-cleanup  no-op на этой ОС`
	}
}

// tamperStatusReport форматирует вывод tamper-status под конкретную ОС. Поля
// tamper.Status() заточены под Windows (TamperProtection/SafeBootGuard/safe_mode); на
// macOS осмысленно только первое (schg на /usr/local/bin/RoutineOps-agent), а подсказка про
// безопасный режим и HKLM там — прямая ложь. Вынесено в чистую функцию, а не печатается
// по месту, чтобы одним кросс-платформенным тестом покрыть все три ветки.
func tamperStatusReport(goos string, protection, safeBoot uint32, safeMode bool) string {
	armed := protection != 0 || safeBoot != 0
	var b strings.Builder
	switch goos {
	case "windows":
		b.WriteString("платформа: Windows (SafeBoot-регистрация + флаги в реестре, сторож перевзводит)\n")
		fmt.Fprintf(&b, "TamperProtection=%d SafeBootGuard=%d safe_mode=%t\n", protection, safeBoot, safeMode)
		if armed {
			b.WriteString("Защита ВЗВЕДЕНА. Снятие: загрузиться в безопасном режиме → " +
				"`RoutineOps-agent tamper-disarm` (или обнулить оба DWORD в HKLM\\SOFTWARE\\RoutineOps\\Agent) → " +
				"перезагрузиться в обычный режим → запустить uninstall.bat от админа.\n")
		} else {
			b.WriteString("Защита СНЯТА — можно удалять (uninstall.bat от админа).\n")
		}
	case "darwin":
		b.WriteString("платформа: macOS (immutable-флаг schg на бинаре и Launch-plist'ах; сторожа нет — флаг держит ядро)\n")
		fmt.Fprintf(&b, "schg=%d (проверяется /usr/local/bin/RoutineOps-agent)\n", protection)
		if armed {
			b.WriteString("Защита ВЗВЕДЕНА. Снятие: `sudo RoutineOps-agent tamper-disarm` (chflags noschg), " +
				"затем `sudo RoutineOps-agent uninstall`. Без disarm удаление бинаря и plist'ов вернёт " +
				"«operation not permitted» даже под root.\n")
		} else {
			b.WriteString("Защита СНЯТА — можно удалять (`sudo RoutineOps-agent uninstall`).\n")
		}
	default:
		fmt.Fprintf(&b, "платформа: %s — tamper-protection не реализована, файлы агента ничем не защищены\n", goos)
		b.WriteString("Удаление: `sudo RoutineOps-agent uninstall` — разоружать нечего.\n")
	}
	return b.String()
}

// tamperDisarmDoneMsg — что оператору делать ПОСЛЕ успешного разоружения. На Windows
// нужен reboot в обычный режим и uninstall.bat; на macOS ни того, ни другого нет —
// сразу uninstall. Раньше Windows-инструкция печаталась на всех платформах.
func tamperDisarmDoneMsg(goos string) string {
	switch goos {
	case "windows":
		return "tamper-protection разоружена — перезагрузитесь в обычный режим и запустите uninstall.bat от админа"
	case "darwin":
		return "tamper-protection разоружена (schg снят) — теперь `sudo RoutineOps-agent uninstall` и удаление файлов агента пройдут"
	default:
		return "tamper-protection разоружена"
	}
}

// runDiagCommand собирает зависимости diag из конфига и печатает отчёт. При
// -probe выполняет реальный mTLS-dial. Вынесено из main для тестируемости runDiag.
func runDiagCommand(w io.Writer, cfg *config.Config) int {
	provider, err := certProvider(cfg)
	if err != nil {
		fmt.Fprintf(w, "RoutineOps-agent diag\n  ОШИБКА инициализации провайдера сертификата: %v\n", err)
		return 1
	}
	var probe func() error
	if cfg.Probe {
		probe = func() error {
			dialer, derr := transport.NewDialer(cfg.ServerAddr, cfg.ServerName, provider)
			if derr != nil {
				return derr
			}
			conn, derr := dialer.Dial()
			if derr != nil {
				return derr
			}
			return conn.Close()
		}
	}
	return runDiag(w, cfg, provider, time.Now(), probe)
}

// printVersion печатает версию агента и параметры сборки в stdout (для
// ops/саппорта: проверить, что установлено, и включено ли самообновление —
// без чтения логов службы).
func printVersion(w io.Writer, cfg *config.Config) {
	fmt.Fprintf(w, "RoutineOps-agent %s\n", version)
	fmt.Fprintf(w, "  platform: %s/%s, %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	// Раньше здесь проверялся ТОЛЬКО вшитый releasePubKey — и универсальный агент
	// (PKG/MSI, ключ приезжает из enroll-ответа) всегда рапортовал «выключено».
	// Из-за этого настоящую поломку — потерянный при раскладке release_pubkey —
	// нельзя было отличить от нормальной универсальной сборки.
	if ok, detail := updateKeyStatus(cfg); ok {
		fmt.Fprintf(w, "  self-update: включено (%s)\n", detail)
	} else {
		fmt.Fprintf(w, "  self-update: ВЫКЛЮЧЕНО (%s)\n", detail)
	}
	if ready, detail := escrowSealerStatus(); ready {
		fmt.Fprintln(w, "  filevault escrow: sealer готов (recipient вшит и сверен)")
	} else {
		fmt.Fprintf(w, "  filevault escrow: выключен (%s)\n", detail)
	}
}

// normalizeEnrollURL делает enroll-URL терпимым к «голому» базовому адресу: если
// путь пустой или "/", дописывает канонический /api/v1/enroll. URL с явным путём
// не трогаем (deriveUpdateURL для нестандартного пути сам вернёт ""). Так одна и та
// же ошибка оператора (ENROLL_URL без /api/v1/enroll) больше не валит установку.
func normalizeEnrollURL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw // нераспарсиваемое/без хоста не чиним — упадёт явной ошибкой ниже
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/api/v1/enroll"
		return u.String()
	}
	return raw
}

// serviceInstallFatal решает, валить ли установку по ошибке service.Install.
// НЕ фатальны ровно два случая, в которых служба уже зарегистрирована и дальнейшие
// шаги (Harden, tamper.Arm, чистка легаси, подъём трея) имеют смысл:
//   - ErrServiceStartFailed — служба зарегистрирована, не удался лишь немедленный
//     старт (Windows): поднимется по AUTO_START при ребуте;
//   - ErrTrayInstallFailed — демон (macOS) установлен и запущен, не встал лишь
//     LaunchAgent меню-бара: агент полностью рабочий, трей подхватится при логоне.
//
// Всё остальное значит «службы нет» — идти дальше незачем (на Windows это ещё и
// сигнал MSI с Return=check откатить установку).
func serviceInstallFatal(err error) bool {
	if err == nil {
		return false
	}
	return !errors.Is(err, service.ErrServiceStartFailed) &&
		!errors.Is(err, service.ErrTrayInstallFailed)
}

// runEnroll выполняет bootstrap-энроллмент (Этап 3): получает mTLS-серт по
// одноразовому токену и раскладывает cert/key/ca по путям из конфигурации
// (-cert/-key/-ca). При -cert-source=keystore идентичность переносится в
// защищённое хранилище ОС (Keychain), а ключ с диска удаляется. При
// -install-service после успеха регистрирует службу с правильным источником.
func runEnroll(cfg *config.Config, log *slog.Logger) error {
	// mTLS-материал кладём по АБСОЛЮТНЫМ путям. Служба стартует с произвольным
	// рабочим каталогом (Windows — C:\Windows\System32, systemd — /), поэтому
	// относительные пути (дефолт certs/agent.crt) при старте службы не находятся.
	// Якорь относительных путей — каталог бинаря (installDir), а не CWD enroll.
	dir := installDir()
	cfg.CertFile = absCertPath(cfg.CertFile, dir)
	cfg.KeyFile = absCertPath(cfg.KeyFile, dir)
	cfg.CAFile = absCertPath(cfg.CAFile, dir)

	// Терпимость к «голому» enroll-URL (напр. из MSI ENROLL_URL=https://host:8081
	// без пути): дописываем канонический /api/v1/enroll. Иначе POST уходит в корень
	// (HTTP 405), а deriveUpdateURL не находит путь и тихо выключает self-update.
	cfg.EnrollURL = normalizeEnrollURL(cfg.EnrollURL)

	// Идемпотентность энроллмента: если валидная (непросроченная) идентичность уже
	// есть (повторный запуск установщика, апгрейд, ручной перезаход), НЕ дёргаем
	// enroll повторно — одноразовый токен уже погашен, и сервер вернул бы HTTP 401
	// "token already used". С Return=check у MSI это откатывало бы всю установку
	// (полевой баг v22). Берём device_id из существующего серта и идём сразу
	// ставить/перезапускать службу (Install идемпотентен).
	deviceID, reused, err := reusableIdentity(cfg, time.Now(), log)
	if err != nil {
		return err
	}
	if reused {
		log.Info("идентичность уже выдана — пропускаю энроллмент (идемпотентность)",
			slog.String("device_id", deviceID))
	} else {
		info := collector.Collect()
		id, err := enroll.Run(context.Background(), enroll.Request{
			EnrollURL:     cfg.EnrollURL,
			Token:         cfg.EnrollToken,
			CAFile:        cfg.CAFile,
			CAURL:         cfg.CAURL,
			CASHA256:      cfg.CASHA256,
			CertOut:       cfg.CertFile,
			KeyOut:        cfg.KeyFile,
			CAOut:         cfg.CAFile,
			ReleaseKeyOut: releasePubKeyPath(cfg),
			Hostname:      info.Hostname,
			OS:            info.OS,
			Arch:          runtime.GOARCH,
		}, log)
		if err != nil {
			return err
		}
		deviceID = id

		// Режим keystore: переносим выданную идентичность в Keychain (label=device_id,
		// = CN серта) и убираем приватный ключ с диска — дальше run работает по keystore.
		if cfg.CertSource == keystore.SourceKeystore {
			target := keystore.ProvisionTarget()
			// Служба работает под LocalSystem (Win) / root-демоном (mac) и читает только
			// машинное хранилище. Без повышения прав идентичность ляжет в пользовательский
			// стор (Windows CurrentUser\My / login keychain), недоступный службе — падаем
			// до импорта, чтобы не оставить устройство в нерабочем состоянии после установки.
			if cfg.EnrollInstall && !keystore.ProvisionIsMachineScope() {
				return fmt.Errorf("cert-source=keystore с -install-service требует запуска enroll "+
					"от администратора/root: иначе идентичность попадёт в пользовательское "+
					"хранилище (target=%q), недоступное службе под LocalSystem/root", target)
			}
			certPEM, kerr := os.ReadFile(cfg.CertFile)
			keyPEM, kerr2 := os.ReadFile(cfg.KeyFile)
			if kerr != nil || kerr2 != nil {
				return fmt.Errorf("чтение выданного материала для импорта в keychain: %v / %v", kerr, kerr2)
			}
			if err := keystore.Import(certPEM, keyPEM, target); err != nil {
				return fmt.Errorf("импорт идентичности в хранилище: %w", err)
			}
			if err := os.Remove(cfg.KeyFile); err != nil {
				log.Warn("не удалось удалить ключ с диска после импорта в хранилище", slog.Any("error", err))
			}
			log.Info("идентичность перенесена в защищённое хранилище",
				slog.String("label", deviceID), slog.String("target", target))
		}
	}

	if cfg.EnrollInstall {
		// Раскладка в постоянные пути (macOS/Linux): бинарь и серты из временного
		// каталога enroll (/tmp на macOS чистится при ребуте) переносятся в
		// стабильные каталоги, состояние — в DataDir. На Windows (MSI) Relocate=false.
		lay := service.InstallLayout()
		if lay.Relocate {
			if err := relocateForService(cfg, lay, log); err != nil {
				return fmt.Errorf("раскладка файлов службы: %w", err)
			}
		}

		// FileVault provisioning (seal-on-enroll) — ТОЛЬКО на свежем энролле
		// (не на идемпотентном reused-повторе: PRK ротировался бы заново без
		// нужды при каждом переустановщике/апгрейде). Best-effort — ошибка
		// сюда НЕ прерывает регистрацию базовой MDM-службы ниже.
		if !reused {
			provisionFileVaultAtEnroll(cfg, deviceID, log)
		}

		// Адрес сервера не должен молча уехать в дефолт: если -server не передали,
		// служба запустилась бы в localhost и устройство никогда не подключилось бы.
		if isLoopbackHost(cfg.ServerAddr) {
			log.Warn("служба регистрируется с локальным адресом сервера — для "+
				"удалённого устройства передайте реальный -server host:port, иначе "+
				"агент в службе будет стучаться в localhost",
				slog.String("server", cfg.ServerAddr))
		}
		svcCfg := service.Config{Args: enrollServiceArgs(cfg, deviceID)}
		if lay.Relocate {
			svcCfg.Exe = lay.BinPath
			svcCfg.WorkingDir = lay.DataDir
		}
		if err := service.Install(svcCfg); err != nil {
			if serviceInstallFatal(err) {
				return fmt.Errorf("регистрация службы после энроллмента: %w", err)
			}
			switch {
			// Сбой ТОЛЬКО старта (служба зарегистрирована) — не фатально: продолжаем
			// хардненинг/трей/чистку, служба поднимется по AUTO_START при ребуте.
			case errors.Is(err, service.ErrServiceStartFailed):
				log.Warn("служба зарегистрирована, но не стартовала сразу — поднимется по "+
					"AUTO_START при ребуте; проверьте Get-Service RoutineOps-agent и лог службы",
					slog.Any("error", err))
			// Демон (macOS) поставлен и запущен, не встал только LaunchAgent трея.
			// Продолжаем: агент полноценно работает без меню-бара, а трей подхватится
			// при следующем логоне. Ронять из-за него весь энроллмент нельзя — так
			// устройство оставалось вообще без агента.
			case errors.Is(err, service.ErrTrayInstallFailed):
				log.Warn("трей (меню-бар) не поставился — сама служба установлена и работает; "+
					"иконки в меню-баре не будет до следующего логона/переустановки",
					slog.Any("error", err))
			}
		}
		if err := service.Harden(); err != nil {
			log.Warn("не удалось ужесточить права службы (остановить сможет и непривилегированный пользователь)",
				slog.Any("error", err))
		}
		if err := tamper.Arm(log); err != nil {
			log.Warn("не удалось взвести защиту от удаления (tamper protection)", slog.Any("error", err))
		}
		log.Info("служба зарегистрирована", slog.String("name", service.Name),
			slog.String("device_id", deviceID))

		// Windows (установка из MSI): после регистрации и СТАРТА службы (а) добиваем
		// следы ручных установок — каталог C:\mdm-extract (службу с тем же именем уже
		// снял Install по имени) и (б) сразу поднимаем трей в активной сессии
		// пользователя. Иначе трей появился бы лишь при СЛЕДУЮЩЕМ логоне (через
		// HKLM\…\Run), и сразу после `msiexec /qn` его не было (полевой баг v22). Оба
		// шага — no-op вне Windows и best-effort: их сбой не валит установку.
		service.RemoveLegacyArtifacts(log)
		launchTrayInActiveSession(log)
	}
	return nil
}

// existingDeviceID возвращает device_id (CN), если на устройстве уже есть валидная
// (непросроченная) mTLS-идентичность по текущему источнику (файлы/keystore), и
// флаг её наличия. Используется для идемпотентного энроллмента: повторный enroll
// тем же одноразовым токеном сервер отверг бы (token already used). Любая проблема
// (нет серта, не парсится, истёк) → ("", false) → выполняем обычный enroll.
func existingDeviceID(cfg *config.Config, now time.Time) (string, bool) {
	provider, err := certProvider(cfg)
	if err != nil {
		return "", false
	}
	cert, err := provider.ClientCertificate()
	if err != nil {
		return "", false
	}
	ci, err := leafInfo(cert)
	if err != nil || ci.subjectCN == "" || ci.expired(now) {
		return "", false
	}
	return ci.subjectCN, true
}

// reusableIdentity решает, можно ли пропустить энроллмент, потому что валидная
// идентичность уже лежит на устройстве. CN и срок (existingDeviceID) — только
// половина ответа: после ПЕРЕИЗДАНИЯ CA на сервере старый серт остаётся
// непросроченным и с тем же CN, но подписан корнем, которого сервер больше не
// знает. Такой «reused» тихо пропускал энроллмент, установщик рапортовал успех, а
// служба вечно падала на mTLS-хендшейке — в поле это не диагностируется. Поэтому
// дополнительно сверяем цепочку с CA, которому сервер доверяет СЕЙЧАС.
//
// Исход при несовпадении:
//   - есть -token → reused=false: идём на полный энроллмент, он перевыпустит
//     cert/key/ca под новый CA (старые файлы перезапишутся);
//   - токена нет → падаем с внятной ошибкой: починить нечем, а молчать нельзя.
//
// Нормальный случай (CA тот же) обязан остаться идемпотентным: это защита от
// «token already used» при повторном прогоне установщика (полевой баг v22,
// MSI Return=check). Поэтому недоступность сети или отсутствие источника CA
// НЕ считаются провалом проверки — см. serverCABundle и ветку ErrNoCASource.
func reusableIdentity(cfg *config.Config, now time.Time, log *slog.Logger) (string, bool, error) {
	deviceID, ok := existingDeviceID(cfg, now)
	if !ok {
		return "", false, nil
	}
	caPEM, err := serverCABundle(cfg, log)
	if err != nil {
		if errors.Is(err, enroll.ErrNoCASource) {
			// Проверять нечем: ни -ca на диске, ни -ca-url. Сохраняем прежнее поведение
			// (доверяем существующей идентичности) — enroll.Run в этом состоянии всё
			// равно откажет по той же причине, а ломать идемпотентность там, где CA
			// раскладывает сам пакет, мы не имеем права.
			log.Warn("издателя существующего сертификата сверить нечем (нет ни -ca, ни -ca-url) — "+
				"пропускаю проверку CA", slog.String("device_id", deviceID))
			return deviceID, true, nil
		}
		return "", false, fmt.Errorf("получение текущего CA сервера для сверки идентичности: %w", err)
	}

	// Провайдер уже отработал в existingDeviceID — здесь он не может внезапно
	// сломаться, но ошибку глотаем в пользу обычного энроллмента, а не паники.
	provider, err := certProvider(cfg)
	if err != nil {
		return "", false, nil
	}
	cert, err := provider.ClientCertificate()
	if err != nil {
		return "", false, nil
	}
	if err := verifyIdentityChain(cert, caPEM); err != nil {
		if cfg.EnrollToken == "" {
			return "", false, fmt.Errorf("существующая идентичность (CN=%s) подписана НЕ текущим CA "+
				"сервера (%v) — mTLS-хендшейк не поднимется. Похоже, CA переиздан: переустановите "+
				"агент с новым одноразовым токеном (-token), тогда сертификат будет перевыпущен",
				deviceID, err)
		}
		log.Warn("существующая идентичность подписана не текущим CA сервера (CA переиздан?) — "+
			"выполняю полный энроллмент, сертификат будет перевыпущен",
			slog.String("device_id", deviceID), slog.Any("error", err))
		return "", false, nil
	}
	return deviceID, true, nil
}

// serverCABundle возвращает CA, которому сервер доверяет ПРЯМО СЕЙЧАС. Порядок
// источников СОЗНАТЕЛЬНО обратный enroll.LoadCABundle: сначала свежий бандл по
// -ca-url (сверенный с -ca-sha256), и только потом файл с диска. Файл — это CA,
// полученный на ПРОШЛОМ энроллменте, и по нему переиздание CA не увидеть в
// принципе: старый серт прекрасно проверяется старым корнем. Оба установщика
// (MSI и .pkg) -ca-url/-ca-sha256 передают всегда.
//
// Сеть недоступна — деградируем на файл с предупреждением: офлайн-переустановка
// не должна падать (сегодня она проходит), а битую цепочку служба всё равно
// покажет в логе при первом же коннекте.
func serverCABundle(cfg *config.Config, log *slog.Logger) ([]byte, error) {
	if cfg.CAURL != "" && cfg.CASHA256 != "" {
		b, err := enroll.FetchPinnedCA(cfg.CAURL, cfg.CASHA256)
		switch {
		case err == nil:
			return b, nil
		case errors.Is(err, enroll.ErrCAPinMismatch):
			// Пин не сошёлся — молча откатываться на CA с диска нельзя: это либо MITM,
			// либо протухший -ca-sha256 в команде установщика (CA переиздали, команду
			// не обновили). И то и другое оператор обязан увидеть.
			return nil, err
		default:
			log.Warn("не удалось скачать текущий CA сервера — сверяю издателя по CA с диска",
				slog.String("ca_url", cfg.CAURL), slog.Any("error", err))
		}
	}
	return enroll.LoadCABundle(cfg.CAFile, cfg.CAURL, cfg.CASHA256)
}

// verifyIdentityChain проверяет, что leaf клиентского серта выписан CA из caPEM.
// KeyUsages=ClientAuth — ровно тот EKU, который ставит серверный подписчик
// (internal/server/enroll/signer.go): заодно не примем за идентичность серверный
// или CA-серт, случайно оказавшийся в agent.crt.
//
// Единственный вопрос здесь — «подписан ли этот leaf ТЕКУЩИМ CA сервера», а НЕ
// «действителен ли он по времени прямо сейчас»: expired(now) уже проверил
// existingDeviceID (по NotAfter), а NotBefore идемпотентность СОЗНАТЕЛЬНО игнорирует.
//
// Часы здесь не участвуют вовсе, и своей проверки цепочки тут больше нет: обе живут в
// enroll.LeafSignedByCA. Раньше тут был x509.Verify с CurrentTime=leaf.NotBefore — он
// лечил съехавшие назад часы (севший CMOS, откат снапшота VM), но ломался на CA моложе
// минуты: сервер бэкдейтит leaf на минуту (internal/server/enroll/signer.go), а
// `openssl req -x509` (scripts/gen-certs.sh) корень не бэкдейтит, поэтому в момент
// leaf.NotBefore корень «ещё не действителен». Легитимная идентичность отвергалась, и
// reusableIdentity либо падал с «переустановите с -token», либо форсил полный
// энроллмент уже погашенным токеном → 401 → установка падает.
//
// Окно в 60 секунд — на ВЫПИСКЕ leaf, а не на проверке: leaf.NotBefore вшит в серт
// навсегда, поэтому «отравленный» серт (выданный в первую минуту жизни CA) отвергался
// бы при КАЖДОЙ последующей переустановке, а не только в ту минуту. Отсюда и главный
// пострадавший — ротация CA с немедленным переэнроллментом парка. Фикс лечит уже
// выданные серты ретроактивно: переэнроллмент парка не нужен.
func verifyIdentityChain(cert tls.Certificate, caPEM []byte) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("сертификат не содержит цепочки")
	}
	leaf := cert.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("разбор leaf-сертификата: %w", err)
		}
		leaf = parsed
	}
	caCerts, err := enroll.ParseCACerts(caPEM)
	if err != nil {
		return err
	}
	// Промежуточные СОЗНАТЕЛЬНО не берём из cert.Certificate[1:]: доверять можно только
	// бандлу сервера. Появится промежуточный CA — он приедет в бандле (иначе mTLS всё
	// равно не поднимется), и LeafSignedByCA его увидит.
	return enroll.LeafSignedByCA(leaf, caCerts)
}

// enrollServiceArgs формирует аргументы запуска службы после enroll. Все параметры
// (адрес сервера, источник идентичности, АБСОЛЮТНЫЕ пути к mTLS-материалу)
// прописываются явно: служба стартует с произвольным рабочим каталогом и без
// сохранённых параметров запустилась бы с дефолтами (localhost), а относительные
// пути к сертификатам не нашла бы.
// lockStatePath — путь к файлу состояния блокировки: явный из конфига или общий
// машинный (ProgramData\RoutineOps\lock.json), чтобы служба и лок-экран его разделяли.
func lockStatePath(cfg *config.Config) string {
	if cfg.LockStateFile != "" {
		return cfg.LockStateFile
	}
	return lock.DefaultPath()
}

// adminRequestPath — файл-заявка на админ-права (трей пишет, служба читает),
// в том же общем каталоге, что и состояние блокировки.
func adminRequestPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(lockStatePath(cfg)), "admin-request.json")
}

// statusFilePath — снимок состояния агента для трея, в том же общем каталоге, что и
// lock.json/admin-request.json. Пишет служба (root), читает трей (юзер-сессия),
// поэтому это НЕ os.TempDir(): на macOS он per-user — демон-root и трей-юзер получили
// бы РАЗНЫЕ каталоги, трей читал бы пустоту и показывал «агент не запущен», хотя
// служба жива. Общий машинный каталог оба процесса вычисляют одинаково из -lock-state
// (трей запускается тем же набором флагов, что и служба — install_darwin_tray.go).
func statusFilePath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(lockStatePath(cfg)), "status.json")
}

func enrollServiceArgs(cfg *config.Config, deviceID string) []string {
	var args []string
	if cfg.CertSource == keystore.SourceKeystore {
		args = []string{
			"-server", cfg.ServerAddr, "-server-name", cfg.ServerName,
			"-cert-source", "keystore", "-keystore-label", deviceID, "-ca", cfg.CAFile,
		}
	} else {
		args = []string{
			"-server", cfg.ServerAddr, "-server-name", cfg.ServerName,
			"-cert", cfg.CertFile, "-key", cfg.KeyFile, "-ca", cfg.CAFile,
		}
	}
	// Включаем самообновление: манифест релизов лежит на том же сервере, что и
	// энроллмент, поэтому URL выводим из enroll-URL (без новых MSI-свойств).
	// Без публикованного релиза это безвредный no-op; подпись проверяется вшитым
	// релизным ключом (releasePubKey), так что неподписанный апдейт не применится.
	if u := deriveUpdateURL(cfg.EnrollURL); u != "" {
		// Имя флага ДОЛЖНO совпадать с config.go (-update-url): иначе config.Load
		// при старте службы падает «flag provided but not defined» → os.Exit(2) ещё
		// до StartServiceCtrlDispatcher → SCM 1053. Покрыто TestEnrollServiceArgsParse.
		args = append(args, "-update-url", u)
	}
	// Пути к изменяемому состоянию прописываем в службу, только если они абсолютные.
	// После раскладки (relocateForService на macOS/Linux) они указывают в DataDir —
	// служба пишет туда, а не в read-only рабочий каталог (/). На Windows (MSI,
	// Relocate=false) пути остаются относительными дефолтами и сюда не попадают —
	// поведение установщика прежнее.
	args = appendAbsFlag(args, "-outbox-dir", cfg.OutboxDir)
	args = appendAbsFlag(args, "-task-state", cfg.TaskStateFile)
	args = appendAbsFlag(args, "-script-dedup", cfg.ScriptDedupFile)
	args = appendAbsFlag(args, "-forbidden-list", cfg.ForbiddenListFile)
	args = appendAbsFlag(args, "-lock-state", cfg.LockStateFile)
	return args
}

// appendAbsFlag добавляет пару (flag, val), только если val — абсолютный путь.
func appendAbsFlag(args []string, flag, val string) []string {
	if val != "" && filepath.IsAbs(val) {
		return append(args, flag, val)
	}
	return args
}

// deriveUpdateURL строит URL манифеста самообновления из enroll-URL: и энроллмент
// (/api/v1/enroll), и манифест (/api/v1/agent/version) обслуживает один сервер.
// Возвращает "", если enroll-URL не в стандартном виде (тогда self-update не
// включаем, чтобы не поллить произвольный адрес).
func deriveUpdateURL(enrollURL string) string {
	const enrollPath, manifestPath = "/api/v1/enroll", "/api/v1/agent/version"
	if enrollURL == "" || !strings.Contains(enrollURL, enrollPath) {
		return ""
	}
	return strings.Replace(enrollURL, enrollPath, manifestPath, 1)
}

// relocateForService раскладывает агента в постоянные пути службы (macOS/Linux):
// бинарь и mTLS-материал из временного каталога enroll переносятся в стабильные
// каталоги, а изменяемое состояние (outbox, *.seen, lock, forbidden) переводится
// в DataDir. Без этого служба после ребута стартовала бы с бинаря/сертов в /tmp
// (macOS чистит его), а run падал бы, пытаясь писать состояние в read-only CWD (/).
func relocateForService(cfg *config.Config, lay service.Layout, log *slog.Logger) error {
	// [B4] Путь release-pubkey снимаем ДО переустановки cfg.CAFile ниже: enroll положил
	// ключ рядом с CA, переданным флагом -ca (у PKG это /usr/local/etc/mdm/), а CertDir
	// службы — другой каталог. Вызов releasePubKeyPath ПОСЛЕ переустановки cfg.CAFile дал
	// бы пустой CertDir/release_pubkey и потерю ключа — так self-update и умирал молча на
	// всём macOS/Linux-флоте (универсальный агент без вшитого ключа берёт его из enroll).
	srcReleaseKey := releasePubKeyPath(cfg)

	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{lay.DataDir, 0o755},
		{lay.CertDir, 0o700},
		{lay.LogDir, 0o755},
	} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return fmt.Errorf("создание каталога %s: %w", d.path, err)
		}
	}

	// Бинарь: копия текущего исполняемого файла в стабильный путь.
	if err := os.MkdirAll(filepath.Dir(lay.BinPath), 0o755); err != nil {
		return fmt.Errorf("создание каталога бинаря %s: %w", filepath.Dir(lay.BinPath), err)
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("определение пути бинаря: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	// [B2] На lay.BinPath при переустановке может стоять schg (tamper.Arm с прошлого
	// энролла, сам никогда не снимает) И по нему уже работает демон — прямой O_TRUNC упал
	// бы EPERM (immutable) или ETXTBSY (busy exe). installBinary снимает immutable и
	// подменяет файл через temp+rename в том же каталоге. schg вернёт tamper.Arm ниже по
	// runEnroll — уже на новый файл. На Linux/Windows Unlock — no-op, rename безвреден.
	if err := installBinary(self, lay.BinPath); err != nil {
		return fmt.Errorf("установка бинаря в %s: %w", lay.BinPath, err)
	}

	// [B3] CA нужен на диске всегда (в т.ч. keystore-режим — ключ в Keychain, а корневой
	// CA читается из файла). Источника может НЕ быть: при reused-идемпотентности enroll.Run
	// не звался и ничего по cfg.CAFile не писал. Безусловный copyFile валил ВСЮ раскладку
	// («no such file or directory»), и устройство оставалось зарегистрированным, но БЕЗ
	// службы. adoptOrCopy: нет src — переиспользуем CA, уже лежащий в CertDir с прошлой
	// установки; нет ни src, ни dst — внятная ошибка с подсказкой, а не голый ENOENT.
	caDst := filepath.Join(lay.CertDir, "ca.crt")
	switch {
	// Полу-очищенная машина: идентичность жива (reused-путь, enroll.Run не звался и
	// CA по cfg.CAFile не писал), а сам CA стёрт и с исходного пути, и из CertDir —
	// но оператор ПЕРЕДАЛ -ca-url, то есть CA можно дотянуть пинованно, а не падать
	// «ни src, ни dst» (полевой случай: снесён /var/lib/RoutineOps-agent при живой
	// файловой идентичности рядом с бинарём). Скачивание держим здесь, а не в
	// adoptOrCopy: она общая для CA и release_pubkey, URL-источник — CA-специфика.
	// -ca-sha256 в условии сознательно не требуем: пустой пин отвергнет FetchPinnedCA
	// с точной TOFU-подсказкой — она полезнее общего «ни src, ни dst».
	case !fileExists(cfg.CAFile) && !fileExists(caDst) && cfg.CAURL != "":
		b, err := enroll.FetchPinnedCA(cfg.CAURL, cfg.CASHA256)
		if err != nil {
			return fmt.Errorf("CA-сертификата нет ни в %q, ни в %q, скачать по -ca-url тоже не удалось: %w",
				cfg.CAFile, caDst, err)
		}
		// Та же проверка пригодности, что на свежем энроллменте: пин гарантирует
		// «те ли байты», но не «это вообще CA» — лист-сертификат по -ca-url всплыл
		// бы иначе только вечным падением mTLS уже у службы.
		if _, err := enroll.ValidateCABundle(b); err != nil {
			return fmt.Errorf("скачанный по -ca-url бандл не годится как CA: %w", err)
		}
		// Запись через temp+rename: оборванный os.WriteFile оставил бы огрызок ca.crt,
		// который СЛЕДУЮЩИЙ прогон установщика молча адоптировал бы как валидный CA.
		tmp, err := os.CreateTemp(lay.CertDir, ".ca-*")
		if err != nil {
			return fmt.Errorf("временный файл для скачанного CA: %w", err)
		}
		tmpName := tmp.Name()
		defer os.Remove(tmpName) // no-op после успешного Rename
		if _, err := tmp.Write(b); err != nil {
			tmp.Close()
			return fmt.Errorf("запись скачанного CA: %w", err)
		}
		if err := tmp.Chmod(0o644); err != nil {
			tmp.Close()
			return fmt.Errorf("права на скачанный CA: %w", err)
		}
		if err := tmp.Close(); err != nil {
			return fmt.Errorf("закрытие временного файла CA: %w", err)
		}
		if err := os.Rename(tmpName, caDst); err != nil {
			return fmt.Errorf("установка скачанного CA в %s: %w", caDst, err)
		}
		log.Info("CA-сертификата не было на диске — дотянут по -ca-url и сверен с -ca-sha256",
			slog.String("path", caDst))
	default:
		if err := adoptOrCopy(cfg.CAFile, caDst, 0o644, "CA-сертификат",
			"передайте -ca <файл> либо -ca-url <url> -ca-sha256 <hex> и повторите enroll", log); err != nil {
			return err
		}
	}
	cfg.CAFile = caDst

	// [B4] Ключ самообновления переезжает вместе с CA — служба ищет его по releasePubKeyPath
	// от НОВОГО cfg.CAFile, т.е. в CertDir. Отсутствие исходника не фатально: (а) reused-повтор
	// не звал enroll.Run — ключ уже в CertDir с прошлого раза; (б) деплой без release-pubkey.
	// Но нет НИГДЕ — шумим Warn: агент будет работать и никогда не обновится, иначе это молча.
	dstReleaseKey := filepath.Join(lay.CertDir, releaseKeyFile)
	if _, err := os.Stat(srcReleaseKey); err == nil {
		if err := copyFile(srcReleaseKey, dstReleaseKey, 0o644); err != nil {
			return fmt.Errorf("копирование release-pubkey в %s: %w", dstReleaseKey, err)
		}
	} else if _, err := os.Stat(dstReleaseKey); err == nil {
		log.Info("release-pubkey уже в CertDir — самообновление сохранено",
			slog.String("path", dstReleaseKey))
	} else {
		log.Warn("release-pubkey НЕ НАЙДЕН — САМООБНОВЛЕНИЕ БУДЕТ ВЫКЛЮЧЕНО: универсальный "+
			"агент (PKG) собран без вшитого релизного ключа и берёт его только из enroll-ответа; "+
			"проверьте, что сервер запущен с release-pubkey",
			slog.String("ожидали", srcReleaseKey))
	}

	// [B3] Клиентский cert/key — только file-режим (в keystore ключ уже в Keychain).
	// Пару берём ТОЛЬКО целиком: половинки от разных энроллментов ломают mTLS молча.
	if cfg.CertSource != keystore.SourceKeystore {
		certDst := filepath.Join(lay.CertDir, "agent.crt")
		keyDst := filepath.Join(lay.CertDir, "agent.key")
		const idHint = "укажите -cert/-key существующей идентичности либо повторите enroll с новым -token"
		switch {
		case fileExists(cfg.CertFile) && fileExists(cfg.KeyFile):
			if err := copyFile(cfg.CertFile, certDst, 0o644); err != nil {
				return fmt.Errorf("копирование сертификата в %s: %w", certDst, err)
			}
			if err := copyFile(cfg.KeyFile, keyDst, 0o600); err != nil {
				return fmt.Errorf("копирование ключа в %s: %w", keyDst, err)
			}
		case fileExists(certDst) && fileExists(keyDst):
			log.Warn("идентичность по исходным путям не найдена — переиспользую пару из каталога службы",
				slog.String("cert", certDst), slog.String("key", keyDst))
		default:
			return fmt.Errorf("нет клиентской идентичности: ни (%s + %s), ни (%s + %s) — %s",
				cfg.CertFile, cfg.KeyFile, certDst, keyDst, idHint)
		}
		cfg.CertFile = certDst
		cfg.KeyFile = keyDst
	}

	// Изменяемое состояние — в DataDir (служба пишет туда, а не в read-only CWD).
	cfg.OutboxDir = filepath.Join(lay.DataDir, "outbox")
	cfg.TaskStateFile = filepath.Join(lay.DataDir, "tasks.seen")
	cfg.ScriptDedupFile = filepath.Join(lay.DataDir, "scripts.seen")
	cfg.ForbiddenListFile = filepath.Join(lay.DataDir, "forbidden_software.txt")
	cfg.UpdateFloorFile = filepath.Join(lay.DataDir, "update_floor.txt")
	cfg.FilevaultEscrowDir = filepath.Join(lay.DataDir, "filevault_escrow")
	// lock.json и admin-request.json — в отдельном подкаталоге DataDir, а не прямо в
	// нём: их пишет не только служба (root), но и юзер-сессия без прав root
	// (лок-экран снимает блокировку, трей кладёт заявку на права). EnsureUserWritableDir
	// делает ЭТОТ подкаталог доступным на запись всем — если бы это был DataDir
	// целиком, то же самое получил бы и CertDir (mTLS-ключ) по соседству.
	cfg.LockStateFile = filepath.Join(lay.DataDir, "shared", "lock.json")

	log.Info("файлы службы разложены в постоянные пути",
		slog.String("bin", lay.BinPath),
		slog.String("data_dir", lay.DataDir),
		slog.String("cert_dir", lay.CertDir))
	return nil
}

// copyFile копирует src→dst с правами perm (dst перезаписывается).
func copyFile(src, dst string, perm os.FileMode) error {
	if src == dst {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// src и dst могут быть РАЗНЫМИ строками, указывающими на ОДИН inode (напр. -ca
	// /private/var/... против CertDir /var/... — /var симлинк на /private/var на
	// macOS; guard `src == dst` выше такой алиас не ловит). Без этой проверки O_TRUNC
	// ниже обнулил бы общий файл ДО того, как io.Copy успеет прочитать src, и CA/
	// release_pubkey молча стал бы пустым (успех с потерей данных). os.SameFile
	// сравнивает по dev+inode, а не по строке.
	if si, serr := in.Stat(); serr == nil {
		if di, derr := os.Stat(dst); derr == nil && os.SameFile(si, di) {
			return nil
		}
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, perm)
}

// fileExists — существует ли обычный файл по пути (пустой путь → false).
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// adoptOrCopy кладёт файл службы в dst: копирует из src, а если src на диске нет —
// переиспользует dst, уже оставшийся от прошлой установки. Смысл в идемпотентности:
// при reused-идентичности enroll.Run не вызывается и НИЧЕГО по исходным путям не
// пишет, поэтому требовать src там нельзя — но и молча ставить службу с указателем
// на несуществующий файл нельзя тоже (mTLS не поднимется, служба будет флапать).
// Нет ни src, ни dst — падаем с внятной ошибкой и подсказкой hint, а не с голым
// «no such file or directory» от copyFile.
func adoptOrCopy(src, dst string, perm os.FileMode, what, hint string, log *slog.Logger) error {
	if fileExists(src) {
		if err := copyFile(src, dst, perm); err != nil {
			return fmt.Errorf("копирование %s в %s: %w", what, dst, err)
		}
		return nil
	}
	if fileExists(dst) {
		log.Warn("исходный файл не найден — переиспользую уже установленный",
			slog.String("что", what), slog.String("исходный", src), slog.String("установленный", dst))
		return nil
	}
	return fmt.Errorf("нет %s: ни %q, ни %q не существует — %s", what, src, dst, hint)
}

// installBinary кладёт агента в стабильный путь службы так, чтобы это пережило
// ПОВТОРНУЮ установку (переустановка pkg, апгрейд, повторный enroll). Прямая
// перезапись (copyFile → O_TRUNC) на этом пути невозможна сразу по двум причинам:
//   - файл под tamper-защитой (macOS: chflags schg, ставит tamper.Arm) — ядро
//     отвергает write/rename/unlink даже у root, пока флаг не снят;
//   - по этому пути УЖЕ работает демон (launchd KeepAlive / systemd), а запись в
//     исполняемый файл живого процесса даёт ETXTBSY — и на macOS, и на Linux.
//
// Поэтому: снимаем immutable-флаг и подменяем файл через temp+rename в том же
// каталоге — тот же приём, что в selfupdate/replace_unix.go: rename поверх busy-бинаря
// разрешён, а запущенный процесс доживает со старым inode. Защиту вернёт tamper.Arm
// в конце runEnroll — уже на новый файл.
func installBinary(self, dst string) error {
	if self == dst {
		return nil // уже на месте: postinstall pkg запускает как раз установленный бинарь
	}
	if err := tamper.Unlock(dst); err != nil {
		return fmt.Errorf("снятие tamper-защиты: %w", err)
	}
	in, err := os.Open(self)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".RoutineOps-agent-install-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // если до Rename не дошли — не оставляем мусор рядом с бинарём

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	// Права ставим до Rename: CreateTemp даёт 0600, а служба и трей запускают этот
	// файл (в т.ч. трей — из user-сессии), так что бит x нужен всем.
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

// installDir — каталог установленного бинаря, якорь для относительных путей к
// mTLS-материалу. Пусто, если путь к бинарю определить не удалось (тогда
// absCertPath падает на резолв относительно CWD).
func installDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe)
}

// absCertPath делает путь к mTLS-материалу абсолютным: уже абсолютный — без
// изменений; относительный — якорится к каталогу бинаря dir (а не к рабочему
// каталогу, который у службы непредсказуем). Пустой путь не трогаем.
func absCertPath(path, dir string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	if dir != "" {
		return filepath.Join(dir, path)
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// isLoopbackHost сообщает, указывает ли host:port на петлю (localhost/127.x/::1).
// Используется, чтобы предупредить о регистрации службы с локальным адресом сервера.
func isLoopbackHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// dispatchReport доставляет одну запись из outbox нужным unary-RPC.
// Возврат error → временный сбой (запись останется в очереди и повторится).
// Возврат nil → дроп записи из очереди. Дропаем в двух случаях, иначе запись
// навсегда заблокирует FIFO-очередь (poison pill):
//   - неизвестный/битый вид записи (распарсить нечего);
//   - сервер вернул терминальный gRPC-код (см. reportErr).
func dispatchReport(ctx context.Context, dialer *transport.Dialer, kind string, data []byte, log *slog.Logger) error {
	conn, err := dialer.Dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	cl := pb.NewAgentServiceClient(conn)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	switch kind {
	case outbox.KindSecurity:
		var ev pb.SecurityEvent
		if err := proto.Unmarshal(data, &ev); err != nil {
			log.Error("outbox: битый SecurityEvent отброшен", slog.Any("error", err))
			return nil
		}
		ack, err := cl.ReportSecurityEvent(ctx, &ev)
		if err != nil {
			return reportErr(err, kind, log)
		}
		return ackErr(ack.GetReceived())
	case outbox.KindAdmin:
		var req pb.ReportAdminAccessRequest
		if err := proto.Unmarshal(data, &req); err != nil {
			log.Error("outbox: битый ReportAdminAccess отброшен", slog.Any("error", err))
			return nil
		}
		ack, err := cl.ReportAdminAccess(ctx, &req)
		if err != nil {
			return reportErr(err, kind, log)
		}
		return ackErr(ack.GetReceived())
	case outbox.KindScript:
		var res pb.ScriptResult
		if err := proto.Unmarshal(data, &res); err != nil {
			log.Error("outbox: битый ScriptResult отброшен", slog.Any("error", err))
			return nil
		}
		ack, err := cl.ReportScriptResult(ctx, &res)
		if err != nil {
			return reportErr(err, kind, log)
		}
		return ackErr(ack.GetReceived())
	case outbox.KindLock:
		var req pb.ReportLockStatusRequest
		if err := proto.Unmarshal(data, &req); err != nil {
			log.Error("outbox: битый ReportLockStatusRequest отброшен", slog.Any("error", err))
			return nil
		}
		ack, err := cl.ReportLockStatus(ctx, &req)
		if err != nil {
			return reportErr(err, kind, log)
		}
		return ackErr(ack.GetReceived())
	default:
		log.Error("outbox: неизвестный вид записи отброшен", slog.String("kind", kind))
		return nil
	}
}

// reportErr классифицирует gRPC-ошибку доставки одного отчёта: повторять или
// дропнуть. Терминальные коды означают, что сервер вынес окончательный вердикт
// по этой записи и повтор бессмыслен — её надо убрать из очереди, иначе она
// навсегда заблокирует FIFO-очередь outbox (poison pill):
//
//   - NotFound          — целевой объект исчез (напр. заявка на права уже закрыта);
//   - InvalidArgument   — запись не пройдёт валидацию ни при каком повторе;
//   - FailedPrecondition— нарушено неустранимое предусловие на стороне сервера;
//   - ResourceExhausted — кадр больше grpc.MaxRecvMsgSize сервера. Payload в outbox
//     заморожен, размер не изменится ни при каком повторе, а запись стоит в голове
//     FIFO-очереди и блокирует доставку всего остального. Первичная защита —
//     обрезка вывода на источнике (scriptenc.TruncateOutput); это backstop.
//
// Всё остальное (Unavailable, DeadlineExceeded, обрыв связи, Unknown) считаем
// транзиентом и возвращаем исходную ошибку — запись остаётся и до-сылается.
// Whitelist именно терминальных кодов выбран намеренно: данные loss-sensitive,
// поэтому по умолчанию запись сохраняется, а дроп — только при явном отказе.
func reportErr(err error, kind string, log *slog.Logger) error {
	code := grpcstatus.Code(err)
	switch code {
	case codes.NotFound, codes.InvalidArgument, codes.FailedPrecondition, codes.ResourceExhausted:
		log.Error("outbox: сервер отклонил запись окончательно, дроп",
			slog.String("kind", kind),
			slog.String("code", code.String()),
			slog.Any("error", err))
		return nil
	default:
		return err
	}
}

// errNotAcked — сервер вернул received=false без gRPC-ошибки (напр. временная
// ошибка БД в gateway.ReportSecurityEvent). Это временный сбой: возвращаем ошибку,
// чтобы outbox сохранил запись и повторил, а не счёл доставленной и удалил
// (иначе security-событие/результат скрипта терялись бы молча). Защиту от вечного
// повтора обеспечивает age-retention очереди (см. outbox.Queue).
var errNotAcked = errors.New("outbox: сервер не подтвердил приём (received=false), повтор")

// ackErr превращает явный отказ подтверждения в повторяемую ошибку доставки.
func ackErr(received bool) error {
	if !received {
		return errNotAcked
	}
	return nil
}

// buildDialer собирает mTLS-Dialer из конфигурации (общий для run и request-admin).
// Источник сертификатов выбирается cert-source: файлы или хранилище ОС (Keychain).
// certProvider собирает источник mTLS-материала (file | keystore) из конфига.
func certProvider(cfg *config.Config) (transport.CertProvider, error) {
	return keystore.New(keystore.Options{
		Source:   cfg.CertSource,
		CertFile: cfg.CertFile,
		KeyFile:  cfg.KeyFile,
		CAFile:   cfg.CAFile,
		Label:    cfg.KeystoreLabel,
	})
}

// deviceIDFromProvider достаёт device_id (CN клиентского серта) для status-файла
// трея. Best-effort: при любой ошибке возвращает "" (трей просто не покажет id).
func deviceIDFromProvider(provider transport.CertProvider) string {
	cert, err := provider.ClientCertificate()
	if err != nil {
		return ""
	}
	ci, err := leafInfo(cert)
	if err != nil {
		return ""
	}
	return ci.subjectCN
}

func buildDialer(cfg *config.Config) (*transport.Dialer, error) {
	provider, err := certProvider(cfg)
	if err != nil {
		return nil, err
	}
	return transport.NewDialer(cfg.ServerAddr, cfg.ServerName, provider)
}

// runAgentService запускает агент под менеджером служб (или в консоли).
func runAgentService(cfg *config.Config, log *slog.Logger) {
	if err := service.Run(func(ctx context.Context) error {
		return runAgent(ctx, cfg, log)
	}); err != nil {
		log.Error("агент остановлен с ошибкой", slog.Any("error", err))
		os.Exit(1)
	}
	log.Info("агент остановлен")
}

// runAgent — рабочий цикл агента: heartbeat-стрим, инвентаризация, выполнение задач.
func runAgent(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	// Подчистить остатки прошлого самообновления (<exe>.old на Windows).
	selfupdate.CleanupOld()

	// Windows: самообновление рестартит службу через os.Exit(1) → SCM failure-actions,
	// а трей в юзер-сессии к этому моменту убит taskkill'ом на этапе подмены exe
	// (selfupdate/replace_windows.go). Раньше трей поднимал ТОЛЬКО enroll
	// -install-service, поэтому после КАЖДОГО self-update иконка пропадала до
	// перелогина (Run-ключ отрабатывает лишь на логоне). Поднимаем best-effort при
	// старте под службой; вне SCM и вне Windows — no-op (см. relaunchTrayAtServiceStart).
	relaunchTrayAtServiceStart(log)

	// Tamper-protection (Windows): сторож держит SafeBoot-регистрацию и флаги, пока
	// защита взведена и ОС в обычном режиме. В безопасном режиме / при снятых флагах
	// — пассивен (см. internal/agent/tamper). На прочих ОС — no-op.
	go tamper.Enforce(ctx, log)

	// Дочерний контекст: самообновление может инициировать перезапуск, отменив его
	// (graceful), не дожидаясь внешнего сигнала.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var updating atomic.Bool

	// Снимок устройства при старте — для наглядности в логах (не отправляется).
	info := collector.Collect()
	log.Info("агент запускается",
		slog.String("version", version),
		slog.String("server", cfg.ServerAddr),
		slog.Duration("heartbeat", cfg.HeartbeatInterval),
		slog.Duration("inventory", cfg.InventoryInterval),
		slog.String("hostname", info.Hostname),
		slog.String("os", info.OS),
		slog.String("os_version", info.OSVersion),
		slog.String("ip", info.IP),
	)

	// FileVault escrow: только видимость готовности пиннинга на старте (сборка с
	// нужными ldflags или нет) — сама escrow-цепочка (internal/agent/filevault)
	// пока без caller'а, захват секретов и revoke гейтятся физической
	// тест-сессией (внутренний handoff-контракт FileVault, §8).
	if ready, detail := escrowSealerStatus(); ready {
		log.Info("filevault escrow: sealer готов (recipient вшит и сверен на старте)")
	} else {
		log.Debug("filevault escrow выключен (recipient не вшит в эту сборку)", slog.String("detail", detail))
	}

	dialer, err := buildDialer(cfg)
	if err != nil {
		return err
	}

	// Проверка здоровья клиентского серта при старте: на реальной машине сразу
	// видно причину, если mTLS не поднимется (истёкший серт / сдвиг часов), а не
	// только молчаливый бэкофф реконнекта. Заодно достаём device_id (CN серта) для
	// status-файла трея.
	var deviceID string
	if provider, perr := certProvider(cfg); perr == nil {
		logCertHealth(log, provider, time.Now())
		deviceID = deviceIDFromProvider(provider)
	}

	// Status-файл для индикатора в трее (Windows/macOS): пишет служба, читает трей.
	// Путь (statusFilePath) оба процесса вычисляют одинаково через общий каталог
	// службы — иначе трей под юзером не найдёт файл, записанный службой под root.
	// Время обновляем на каждый heartbeat; «онлайн» трей выводит по свежести (см.
	// status). Запись best-effort — её ошибки не должны валить агента. Стартовая
	// запись с нулевым временем = «офлайн», пока не пройдёт первый heartbeat.
	statusPath := statusFilePath(cfg)
	if err := status.Write(statusPath, status.State{
		Version: version, DeviceID: deviceID, ServerAddr: cfg.ServerAddr,
	}); err != nil {
		log.Debug("не удалось записать стартовый status-файл", slog.Any("error", err))
	}
	writeStatus := func() {
		if err := status.Write(statusPath, status.State{
			Version:       version,
			DeviceID:      deviceID,
			ServerAddr:    cfg.ServerAddr,
			LastHeartbeat: time.Now(),
		}); err != nil {
			log.Debug("не удалось записать status-файл", slog.Any("error", err))
		}
	}

	// Outbox: устойчивая очередь loss-sensitive отчётов (алерты ИБ, аудит прав).
	// Диспетчер по виду записи вызывает нужный unary-RPC; временный сбой → запись
	// остаётся и до-сылается, неизвестный/битый вид → дроп (см. outbox.Dispatcher).
	ob, err := outbox.New(cfg.OutboxDir, cfg.OutboxMax, cfg.OutboxFlush, log,
		func(ctx context.Context, kind string, data []byte) error {
			return dispatchReport(ctx, dialer, kind, data, log)
		})
	if err != nil {
		return err
	}
	ob.SetMaxAge(cfg.OutboxMaxAge) // ретеншен по возрасту (0=выключен)
	go ob.Run(ctx)

	// Data Collector: периодическая инвентаризация, отдельно от heartbeat (ADR-5).
	// Через outbox НЕ идёт: это полный снапшот состояния, самовосстанавливается
	// на следующем тике (буферизация промежуточных снапшотов бессмысленна).
	reporter := &inventory.Reporter{
		Interval: cfg.InventoryInterval,
		Dialer:   dialer,
		Log:      log,
		Version:  version,
	}
	go reporter.Run(ctx)

	// Command Listener: выполняет задачи, пришедшие в Connect-стриме.
	executor := command.NewExecutor(dialer, log, cfg.TaskStateFile)
	// Блокировка устройства: состояние переживает рестарт/ребут (Load на старте
	// поднимет замок). Команды lock/unlock приходят в Task.lock и применяются через
	// executor. На Windows локер службы (NewPlatformLocker → SessionLocker) сам
	// поднимает полноэкранный оверлей в активной сессии (CreateProcessAsUser), не
	// завися от трея; вне Windows — лог-заглушка (состояние пишется в lock.json).
	lockPath := lockStatePath(cfg)
	// Каталог состояния должен быть доступен на запись юзер-сессии (лок-экран
	// снимает блокировку, трей кладёт заявку на права) — служба под SYSTEM ставит ACL.
	if err := lock.EnsureUserWritableDir(filepath.Dir(lockPath)); err != nil {
		log.Warn("lock: не удалось открыть каталог состояния на запись пользователю", slog.Any("error", err))
	}
	self, _ := os.Executable()
	locker := lock.New(lockPath, lock.NewPlatformLocker(self, log), log)
	if err := locker.Load(); err != nil {
		log.Error("lock: загрузка состояния блокировки", slog.Any("error", err))
	}
	executor.SetLocker(locker)
	// Реконсиляция блокировки (pull, FetchLockStatus): переживает потерю push-
	// команды и ребут — см. package lock, Reconciler. OnLocalUnlock тем же
	// движением durably (через outbox) отчитывается о ЛОКАЛЬНОМ снятии блокировки
	// (верный пароль на экране/оффлайн-обнаружение), заменяя прежний best-effort
	// прямой вызов ReportLockStatus.
	lockReconciler := lock.NewReconciler(locker, dialer, ob.Enqueue, cfg.LockPollInterval, log)
	// Следим за офлайн-разблокировкой и отчитываемся серверу. Интервал короче, чем
	// keep-alive SessionLocker (3с, см. lock.go) — иначе разблокированный лок-экран
	// мигнёт заново, пока демон не успел среагировать.
	go locker.Run(ctx, time.Second, lockReconciler.OnLocalUnlock)
	go lockReconciler.Run(ctx)

	// FileVault dynamic-lock chaining (G1/G2/G3): nil на не-darwin/сборках без
	// вшитого escrow recipient — executor/reconciler в этом случае отклоняют
	// lock_mode=FILEVAULT с ошибкой вместо тихой деградации в overlay (см.
	// FileVaultRevoker doc в command/executor.go и lock/reconcile.go).
	if fv := wireFileVaultChain(cfg, deviceID, dialer, log); fv != nil {
		executor.SetFileVaultRevoker(fv.chain)
		lockReconciler.SetFileVaultRevoker(fv.chain)
		// Фоновый добор недоставленных escrow-записей (enroll.go пишет их
		// write-ahead на диск ДО сети; если сервер был недоступен дольше
		// enroll-foreground-окна, доставка продолжается здесь неограниченно
		// долго, пока агент жив).
		go func() {
			t := time.NewTicker(cfg.OutboxFlush)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := fv.escrow.FlushPending(ctx); err != nil {
						log.Debug("filevault: фоновый FlushPending", slog.Any("error", err))
					}
				}
			}
		}()
	}

	// Заявки на временные админ-права из трея (кнопка) → RequestAdminAccess.
	go admin.WatchUserRequests(ctx, dialer, adminRequestPath(cfg), 5*time.Second, log)

	// Policy Syncer: тянет политику ПО с сервера (FetchPolicy) в локальный кэш-файл.
	syncer := &policy.Syncer{
		Interval: cfg.PolicySyncInterval,
		File:     cfg.ForbiddenListFile,
		Dialer:   dialer,
		Log:      log,
	}
	go syncer.Run(ctx)

	// Security Monitor: мониторинг запрещённого ПО (из кэша политики) →
	// ReportSecurityEvent через outbox (ADR-5, отдельно от стрима).
	monitor := security.NewMonitor(cfg.SecurityScanInterval, cfg.ForbiddenListFile, ob.Enqueue, log)
	go monitor.Run(ctx)

	// Admin Manager: поллит статус прав (FetchAdminStatus), применяет/снимает их
	// и отчитывается (ReportAdminAccess через outbox); сброс при логауте/истечении.
	adminMgr := admin.NewManager(dialer, ob.Enqueue, cfg.AdminPollInterval, log, cfg.AdminDryRun)
	go adminMgr.Run(ctx)

	// Script Manager: поллит скрипт-политики (FetchScriptPolicies), исполняет их по
	// триггерам (cron/событие/on_connect) и шлёт результат через outbox (Этап 5).
	scriptMgr := scripts.NewManager(dialer, ob.Enqueue, cfg.ScriptPollInterval, cfg.ScriptDedupFile, log)
	go scriptMgr.Run(ctx)
	// Детектор событий ОС (login/logout/network_change) для EVENT-политик.
	eventWatcher := scripts.NewEventWatcher(cfg.EventScanInterval, scriptMgr, collector.LocalIP, log)
	go eventWatcher.Run(ctx)

	// Self-Updater: проверка/применение подписанных обновлений (Этап 7-8). Включён
	// только если задан URL manifest и публичный ключ релиза; иначе не запускаем.
	if cfg.UpdateCheckURL != "" {
		// Состояние ключа пишем в лог службы ЯВНО, и Error — если ключа нет. Мёртвый
		// self-update иначе невидим: агент жив, хартбиты идут, версия просто не растёт.
		// Единственным следом был WARN внутри loadUpdatePubKey — его никто не читал.
		if ok, detail := updateKeyStatus(cfg); ok {
			log.Info("selfupdate: включён",
				slog.String("manifest", cfg.UpdateCheckURL), slog.String("key", detail))
		} else {
			log.Error("selfupdate: ВЫКЛЮЧЕН — агент НИКОГДА не обновится",
				slog.String("manifest", cfg.UpdateCheckURL), slog.String("причина", detail))
		}
		if pub := loadUpdatePubKey(resolveUpdatePubKeyB64(cfg.UpdatePubKey, releaseKeyCandidates(cfg)...), log); pub != nil {
			restart := func() { updating.Store(true); cancel() } // graceful → перезапуск супервизором
			updater := selfupdate.New(version, cfg.UpdateInterval, pub, cfg.UpdateCheckURL, cfg.CAFile, cfg.UpdateFloorFile, restart, log)
			// Windows: провал замены бинаря оставляет трей убитым (taskkill в
			// replaceExecutable), а рестарта службы при ошибке не будет — поднимаем
			// иконку обратно. Вне Windows/SCM — no-op (см. relaunchTrayAtServiceStart).
			updater.OnReplaceFail = func() { relaunchTrayAtServiceStart(log) }
			go updater.Run(ctx)
		}
	}

	// Heartbeat: постоянный Connect-стрим с автопереподключением (блокирует до ctx).
	client := transport.New(dialer, log)
	client.SetBlockedRetry(cfg.BlockedRetry)
	hb := &heartbeat.Heartbeater{
		Interval:  cfg.HeartbeatInterval,
		OnConnect: scriptMgr.OnConnect, // on_connect-триггер скрипт-политик (Этап 5)
		IPFunc:    collector.LocalIP,
		OnTask:    executor.Submit,
		OnBeat:    writeStatus, // индикатор статуса в трее (status-файл)
		Log:       log,
	}

	// client.Run блокирует до отмены ctx (SIGTERM/SIGINT). После — graceful:
	// перестаём принимать задачи и дожидаемся завершения текущих, потом выходим.
	err = client.Run(ctx, hb.Session)
	log.Info("останавливаюсь — дожидаюсь завершения текущих задач")
	executor.Shutdown()
	// Последняя попытка до-доставить очередь отчётов перед выходом (best-effort,
	// со свежим коротким контекстом — основной ctx уже отменён сигналом).
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
	ob.FlushOnce(flushCtx)
	flushCancel()
	// Перезапуск ради применения обновления: возвращаем ошибку → ненулевой выход,
	// чтобы супервизор (launchd KeepAlive / Windows recovery action) поднял новый
	// бинарь. Чистая остановка по сигналу (context.Canceled) — не ошибка.
	if updating.Load() {
		if runtime.GOOS == "darwin" {
			// На macOS убиваем процесс трея, чтобы LaunchAgent (KeepAlive=true)
			// моментально его перезапустил уже с новым бинарным файлом.
			_ = exec.Command("pkill", "-f", "RoutineOps-agent tray").Run()
		}
		return errors.New("перезапуск для применения самообновления")
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// releaseKeyFile — имя файла с base64 release-pubkey. Файл всегда лежит РЯДОМ С CA:
// при enroll'е — в каталоге, переданном флагом -ca, а после раскладки службы — в
// CertDir. Это два РАЗНЫХ каталога (PKG зовёт enroll с -ca /usr/local/etc/mdm/ca.crt,
// служба живёт с -ca /var/lib/RoutineOps-agent/certs/ca.crt), поэтому имя вынесено в
// константу и переезд ключа делается явно, см. relocateForService.
const releaseKeyFile = "release_pubkey"

// installedCertDir — CertDir установленной службы. Вынесен в переменную (а не зовётся
// service.InstallLayout() по месту), чтобы тесты не зависели от реального
// /var/lib/RoutineOps-agent на машине разработчика/CI. На Windows пуст (MSI, Relocate=false).
var installedCertDir = service.InstallLayout().CertDir

// resolveUpdatePubKeyB64 решает, какой ключ проверки подписи самообновления
// использовать. Вшитый при сборке releasePubKey — АВТОРИТЕТНЫЙ и в релизной
// сборке НИКОГДА не обходится: cfgKey (-update-pubkey/ROUTINEOPS_UPDATE_PUBKEY) — это
// dev-override для сборок БЕЗ вшитого ключа (releasePubKey == ""), а не способ
// подменить его в проде. Раньше было наоборот (cfgKey имел приоритет) — root/
// скомпрометированный юзер мог задать свой ключ+свой -update-url и накатить
// произвольный бинарь как «подписанное обновление» (SEC-2, аудит 2026-07-01).
func resolveUpdatePubKeyB64(cfgKey string, storedPaths ...string) string {
	if releasePubKey != "" {
		return releasePubKey
	}
	// Универсальный агент (PKG/MSI, собран БЕЗ вшитого ключа): ключ сохранён при
	// enroll'е из доверенного enroll-ответа (пин CA) в файл рядом с CA. Кандидатов
	// несколько, потому что enroll-каталог CA и CertDir службы — разные каталоги;
	// см. releaseKeyCandidates. Пустые пути пропускаем — вызов с одним "" остаётся
	// валидным (так его зовут тесты SEC-2).
	for _, p := range storedPaths {
		if p == "" {
			continue
		}
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return cfgKey
}

// releasePubKeyPath — путь файла release-pubkey рядом с ТЕКУЩИМ cfg.CAFile. Внимание:
// значение зависит от момента вызова — до раскладки это enroll-каталог CA, после неё
// CertDir. Сюда пишет enroll (ReleaseKeyOut), отсюда же читает служба.
func releasePubKeyPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.CAFile), releaseKeyFile)
}

// releaseKeyCandidates — где служба ищет сохранённый release-pubkey. Первый кандидат —
// рядом с текущим CA (норма после фикса раскладки). Второй — CertDir установленной
// службы: он спасает агентов, которые энроллились ДО фикса и у которых ключ так и
// остался в enroll-каталоге, а также любые будущие расхождения enroll-каталога и
// CertDir. На Windows installedCertDir пуст (MSI, Relocate=false) → список сводится к
// одному кандидату, поведение ровно прежнее.
func releaseKeyCandidates(cfg *config.Config) []string {
	paths := []string{releasePubKeyPath(cfg)}
	if installedCertDir != "" {
		if p := filepath.Join(installedCertDir, releaseKeyFile); p != paths[0] {
			paths = append(paths, p)
		}
	}
	return paths
}

// updateKeyStatus — поедут ли обновления и почему. Решение о ЗНАЧЕНИИ ключа берётся у
// resolveUpdatePubKeyB64 (единственный источник истины, чтобы диагностика не разъехалась
// с рантаймом), здесь добавляется валидация и человекочитаемый источник. Нужен потому,
// что мёртвый self-update ничем себя не проявляет: агент жив, отчёты идут, версия просто
// не растёт — и раньше единственным признаком был один WARN в логе службы.
func updateKeyStatus(cfg *config.Config) (bool, string) {
	cands := releaseKeyCandidates(cfg)
	b64 := strings.TrimSpace(resolveUpdatePubKeyB64(cfg.UpdatePubKey, cands...))
	if b64 == "" {
		return false, "релизный ключ не вшит и не найден на диске (искали: " +
			strings.Join(cands, ", ") + ")"
	}
	if raw, err := base64.StdEncoding.DecodeString(b64); err != nil || len(raw) != ed25519.PublicKeySize {
		return false, "релизный ключ есть, но повреждён (не base64 ed25519)"
	}
	if releasePubKey != "" {
		return true, "ключ вшит в бинарь при сборке релиза"
	}
	for _, p := range cands {
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
			return true, "ключ сохранён при enroll'е: " + p
		}
	}
	return true, "ключ задан флагом -update-pubkey (dev-override)"
}

// loadUpdatePubKey декодирует base64 ed25519 публичный ключ релиза. Возвращает nil
// (с предупреждением) при пустом/битом ключе — тогда самообновление не включается.
func loadUpdatePubKey(b64 string, log *slog.Logger) ed25519.PublicKey {
	if b64 == "" {
		log.Warn("selfupdate: задан update-url, но не задан update-pubkey — автообновление выключено")
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		log.Warn("selfupdate: некорректный update-pubkey — автообновление выключено", slog.Any("error", err))
		return nil
	}
	return ed25519.PublicKey(raw)
}
