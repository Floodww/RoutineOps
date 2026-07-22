package main

import (
	"path/filepath"
	"testing"

	"github.com/Floodww/RoutineOps/internal/agent/config"
	"github.com/Floodww/RoutineOps/internal/agent/service"
)

// durableUnlockDir: durable-память лока живёт ТОЛЬКО в машинном DataDir; любой
// увод task-state из него (дев-дефолт, явный -task-state оператора, отказ
// EnsureDataDir) отключает её (""), а не тащит durable-файл за оператором в
// возможное user-writable место (ревью #7, п. 2.3).
func TestDurableUnlockDir(t *testing.T) {
	dataDir := filepath.Join(string(filepath.Separator)+"machine", "state")
	lay := service.Layout{DataDir: dataDir}
	cases := []struct {
		name      string
		taskState string
		lay       service.Layout
		want      string
	}{
		{"служба: task-state в DataDir", filepath.Join(dataDir, "tasks.seen"), lay, dataDir},
		{"дев: относительный дефолт", config.DefaultTaskStateFile, lay, ""},
		{"оператор увёл -task-state", filepath.Join(string(filepath.Separator)+"tmp", "x", "tasks.seen"), lay, ""},
		{"платформа без раскладки", config.DefaultTaskStateFile, service.Layout{}, "."},
	}
	for _, c := range cases {
		cfg := &config.Config{TaskStateFile: c.taskState}
		if got := durableUnlockDir(cfg, c.lay); got != c.want {
			t.Errorf("%s: durableUnlockDir(%q) = %q, want %q", c.name, c.taskState, got, c.want)
		}
	}
}
