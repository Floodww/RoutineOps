//go:build linux

package service

// InstallLayout — стабильная раскладка службы на Linux. systemd-юнит и так задаёт
// WorkingDirectory=/var/lib/RoutineOps-agent + StateDirectory, но скачанный бинарь и
// выданные серты остаются во временном каталоге запуска enroll — их нужно
// переложить в постоянные пути, иначе ExecStart укажет на бинарь из /tmp.
func InstallLayout() Layout {
	return Layout{
		Relocate:        true,
		BinPath:         "/usr/local/bin/RoutineOps-agent",
		DataDir:         "/var/lib/RoutineOps-agent",
		CertDir:         "/var/lib/RoutineOps-agent/certs",
		LogDir:          "/var/log/RoutineOps-agent",
		EnrollEnvPath:   linuxEnrollEnvPath,
		BootstrapCAPath: linuxBootstrapCAPath,
	}
}
