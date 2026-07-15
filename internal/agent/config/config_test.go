package config

import (
	"flag"
	"testing"
	"time"
)

func load(t *testing.T, args ...string) *Config {
	t.Helper()
	c, err := Load(flag.NewFlagSet("test", flag.ContinueOnError), args)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func TestDefaults(t *testing.T) {
	c := load(t)
	if c.ServerName != "routineops-server" {
		t.Errorf("ServerName=%q", c.ServerName)
	}
	if c.HeartbeatInterval != 30*time.Second {
		t.Errorf("HeartbeatInterval=%v", c.HeartbeatInterval)
	}
	if c.InventoryInterval != 5*time.Minute {
		t.Errorf("InventoryInterval=%v", c.InventoryInterval)
	}
}

func TestFlagsOverride(t *testing.T) {
	c := load(t, "-server", "host:1", "-heartbeat", "2s")
	if c.ServerAddr != "host:1" {
		t.Errorf("ServerAddr=%q", c.ServerAddr)
	}
	if c.HeartbeatInterval != 2*time.Second {
		t.Errorf("HeartbeatInterval=%v", c.HeartbeatInterval)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("ROUTINEOPS_SERVER_ADDR", "envhost:9")
	if c := load(t); c.ServerAddr != "envhost:9" {
		t.Errorf("env не применился: ServerAddr=%q", c.ServerAddr)
	}
}

func TestValidationRejectsBadInterval(t *testing.T) {
	if _, err := Load(flag.NewFlagSet("t", flag.ContinueOnError), []string{"-heartbeat", "0s"}); err == nil {
		t.Fatal("ожидали ошибку при heartbeat=0")
	}
}
