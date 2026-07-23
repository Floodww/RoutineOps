//go:build darwin

package service

// InstallLayout — стабильная раскладка службы на macOS. Скачанный пользователем
// бинарь и выданные enroll серты лежат во временном каталоге (часто /tmp, который
// macOS чистит при ребуте) — служба должна жить в постоянных путях, иначе после
// перезагрузки демон стартует с несуществующим бинарём/сертами.
func InstallLayout() Layout {
	return Layout{
		Relocate:        true,
		BinPath:         "/usr/local/bin/RoutineOps-agent",
		DataDir:         "/var/lib/RoutineOps-agent",
		CertDir:         "/var/lib/RoutineOps-agent/certs",
		LogDir:          "/Library/Logs/RoutineOps",
		EnrollEnvPath:   darwinEnrollEnvPath,
		BootstrapCAPath: darwinBootstrapCAPath,
	}
}
