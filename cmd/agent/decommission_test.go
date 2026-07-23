package main

import (
	"runtime"
	"slices"
	"testing"

	"github.com/Floodww/RoutineOps/internal/agent/config"
	"github.com/Floodww/RoutineOps/internal/agent/service"
)

// buildDecommissionPlan обязан покрывать материалы авто-энролла и каталог логов.
// До фикса /etc/routineops/enroll.env (multi-use ENROLL_TOKEN) переживал снос:
// пакет оставался зарегистрирован в dpkg/rpm, и `apt install --reinstall` по
// уцелевшему env молча возвращал списанную машину в парк. Дрейф самих путей
// относительно упаковочных скриптов ловит TestEnrollArtifactsContract (пакет
// service); здесь — что Layout-пути реально попадают в план. У плана раньше не
// было НИ ОДНОГО теста состава — пропуск enroll.env потому и прожил до поля.
func TestBuildDecommissionPlan_CoversEnrollArtifactsAndLogs(t *testing.T) {
	cfg := &config.Config{
		CertFile: "certs/agent.crt",
		KeyFile:  "certs/agent.key",
		CAFile:   "certs/ca.crt",
	}
	plan := buildDecommissionPlan(cfg)
	lay := service.InstallLayout()

	// На linux/darwin контрактные пути обязаны быть непустыми — иначе проверки
	// ниже выродились бы в вакуумно-зелёные.
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if lay.EnrollEnvPath == "" || lay.BootstrapCAPath == "" {
			t.Fatalf("Layout без путей энролл-материала (env=%q, ca=%q) — план сноса их не закроет",
				lay.EnrollEnvPath, lay.BootstrapCAPath)
		}
		if lay.LogDir == "" {
			t.Fatal("Layout без LogDir — каталог логов пережил бы снос")
		}
	}

	for _, f := range []string{lay.EnrollEnvPath, lay.BootstrapCAPath} {
		if f == "" {
			continue
		}
		if !slices.Contains(plan.Files, f) {
			t.Errorf("plan.Files не содержит %q — материал энролла пережил бы снос", f)
		}
	}
	if lay.LogDir != "" && !slices.Contains(plan.Dirs, lay.LogDir) {
		t.Errorf("plan.Dirs не содержит LogDir %q — логи пережили бы снос", lay.LogDir)
	}
}
