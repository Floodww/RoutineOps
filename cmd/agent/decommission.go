package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Floodww/RoutineOps/internal/agent/config"
	"github.com/Floodww/RoutineOps/internal/agent/decommission"
	"github.com/Floodww/RoutineOps/internal/agent/keystore"
	"github.com/Floodww/RoutineOps/internal/agent/service"
	"github.com/Floodww/RoutineOps/internal/agent/tamper"
)

// runDecommission сносит агента с устройства по команде сервера. Вызывается из
// runAgent уже после graceful-остановки рабочего цикла (executor подтвердил
// приём серверу, пока серт был жив). Пути состояния берутся из cfg (после
// applyStatePaths они указывают в фактические каталоги службы).
func runDecommission(cfg *config.Config, reason string, log *slog.Logger) {
	plan := buildDecommissionPlan(cfg)
	hooks := decommission.Hooks{
		// service.Uninstall снимает службу из SCM/launchd/systemd (на macOS заодно
		// снимает schg с plist/бинаря).
		StopService: service.Uninstall,
		// DisarmTamper без build-тегов: на Windows Cleanup снимает SafeBoot-ключи и
		// флаги реестра (Enforce-сторож уже остановлен вместе с ctx, перевзвода не
		// будет); на macOS Disarm снимает schg со всех targets; на Linux оба no-op.
		// Авторизованный серверный путь сознательно обходит требование Safe Mode —
		// команда пришла по mTLS от доверенного сервера (см. пакет decommission).
		DisarmTamper: func() {
			tamper.Cleanup()
			_ = tamper.Disarm()
		},
	}
	if cfg.CertSource == keystore.SourceKeystore {
		// В режиме keystore идентичность живёт НЕ в файлах (cfg.CertFile/KeyFile —
		// нетронутые дефолты в никуда), а в Keychain/Cert Store — файловый план её
		// не достаёт, и приватный ключ пережил бы снос. Хуком, а не полем плана,
		// чтобы пакет decommission не тянул keystore (та же развязка, что service/
		// tamper). ProvisionTarget: тот же keychain/scope, куда клал Import при
		// энролле (под root/LocalSystem — системное хранилище).
		hooks.PurgeKeystore = func() error {
			return keystore.Purge(cfg.KeystoreLabel, keystore.ProvisionTarget())
		}
	}
	log.Warn("decommission: начинаю снос агента", slog.String("reason", reason))
	if err := decommission.Run(plan, hooks, log); err != nil {
		log.Error("decommission: снос завершился с ошибкой", slog.Any("error", err))
	}
}

// buildDecommissionPlan собирает список того, что удалить: mTLS-материал, конфиги,
// всё изменяемое состояние и каталоги службы. Пустые/повторяющиеся пути отсеивает
// сам decommission.Run (removeFile/removeDirSafe игнорируют отсутствие).
func buildDecommissionPlan(cfg *config.Config) decommission.Plan {
	lay := service.InstallLayout()

	files := []string{
		cfg.CertFile, cfg.KeyFile, cfg.CAFile,
		releasePubKeyPath(cfg),
		lockStatePath(cfg), statusFilePath(cfg), adminRequestPath(cfg),
		cfg.TaskStateFile, cfg.ScriptDedupFile,
		cfg.ForbiddenListFile, cfg.UpdateFloorFile,
		// Материалы авто-энролла, положенные оператором (упаковочные скрипты их
		// только читают): enroll.env несёт multi-use ENROLL_TOKEN — живой креденшл,
		// по которому переустановка пакета молча вернула бы списанную машину в
		// парк; bootstrap-CA — гигиена того же каталога. Именно Files, а не Dirs:
		// /etc/routineops не наш каталог целиком, и /etc в чёрном списке
		// isDangerousDir. На Windows пути пусты (MSI env-файлом не пользуется).
		lay.EnrollEnvPath, lay.BootstrapCAPath,
	}

	// release_pubkey оседает РЯДОМ с CA. Служба читает/пишет его в CertDir — это уже
	// releasePubKeyPath(cfg) выше. Но enroll из пакета шёл с -ca <bootstrap CA>, и
	// ВТОРАЯ копия осела рядом с bootstrap-CA (напр. /etc/routineops/release_pubkey).
	// Сам ca.crt оттуда сносит BootstrapCAPath, а сосед оставался бы — это пин-
	// материал проверки подписей релизов: при реэнролле машины на ДРУГОЙ сервер
	// releaseKeyCandidates взял бы первым путь рядом с новым CA, подхватил старый
	// ключ, и self-update молча отклонял бы подписи нового сервера (fail-closed, но
	// вслепую). Пустой BootstrapCAPath (Windows) НЕ трогаем: filepath.Dir("") дал бы
	// относительный "release_pubkey".
	if lay.BootstrapCAPath != "" {
		files = append(files, filepath.Join(filepath.Dir(lay.BootstrapCAPath), releaseKeyFile))
	}

	dirs := dedupNonEmpty([]string{
		cfg.OutboxDir,
		cfg.FilevaultEscrowDir,
		lay.DataDir,
		lay.CertDir,
		// Каталог логов демона: на macOS (/Library/Logs/RoutineOps) и Linux он вне
		// DataDir и без этой строки переживал снос. На Windows пуст (логи под
		// ProgramData, её сносит windowsLockDir/делетер).
		lay.LogDir,
		// Windows: общий машинный каталог ProgramData\RoutineOps (lock/status/
		// admin-request + подкаталог state). На unix каталог lock.json может быть
		// разделяемым temp — там его целиком не сносим, ограничиваемся файлами выше.
		windowsLockDir(cfg),
	})

	return decommission.Plan{
		Files:   files,
		Dirs:    dirs,
		BinPath: selfBinaryPath(lay),
	}
}

// windowsLockDir — каталог lock.json только на Windows (ProgramData\RoutineOps);
// на прочих ОС "" (не сносим потенциально разделяемый каталог целиком).
func windowsLockDir(cfg *config.Config) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	return filepath.Dir(lockStatePath(cfg))
}

// selfBinaryPath — стабильный путь к бинарю службы (macOS/Linux — lay.BinPath;
// Windows — Relocate=false, BinPath пуст, берём фактический os.Executable).
func selfBinaryPath(lay service.Layout) string {
	if lay.BinPath != "" {
		return lay.BinPath
	}
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, rerr := filepath.EvalSymlinks(self); rerr == nil {
		self = resolved
	}
	return self
}

func dedupNonEmpty(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
