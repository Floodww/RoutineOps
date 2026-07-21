package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/config"
	"github.com/Floodww/RoutineOps/internal/agent/keystore"
	"github.com/Floodww/RoutineOps/internal/agent/service"
)

// copyTestFile — вспомогательная копия файла в тестах retarget.
func copyTestFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Возврат полевого бага v22 на relocate-платформах: первая установка сносит
// приватный ключ по pre-relocate пути (relocateForService [B3]), повторный
// прогон установщика видел cert без key → reusableIdentity проваливалась →
// полный enroll погашенным токеном (HTTP 401). retargetIdentityToCertDir
// обязан перенацелить cfg на пару в CertDir, куда мы её сами переложили.
func TestRetargetIdentityToCertDir(t *testing.T) {
	now := time.Now()

	// makeRelocatedInstall моделирует состояние после первой установки:
	// в исходном каталоге остался только cert (ключ снесён), в CertDir — целая пара.
	makeRelocatedInstall := func(t *testing.T) (cfg *config.Config, lay service.Layout) {
		t.Helper()
		srcCert, srcKey := writeIdentity(t, "device-relocated", now.Add(-time.Hour), now.Add(24*time.Hour))
		certDir := t.TempDir()
		copyTestFile(t, srcCert, filepath.Join(certDir, "agent.crt"))
		copyTestFile(t, srcKey, filepath.Join(certDir, "agent.key"))
		if err := os.Remove(srcKey); err != nil { // как relocateForService [B3]
			t.Fatal(err)
		}
		cfg = &config.Config{CertSource: "file", CertFile: srcCert, KeyFile: srcKey}
		lay = service.Layout{Relocate: true, CertDir: certDir}
		return cfg, lay
	}

	t.Run("ключ снесён relocate'ом → cfg перенацелен, идентичность снова видна", func(t *testing.T) {
		cfg, lay := makeRelocatedInstall(t)
		retargetIdentityToCertDir(cfg, lay, discardLogger())

		if cfg.CertFile != filepath.Join(lay.CertDir, "agent.crt") ||
			cfg.KeyFile != filepath.Join(lay.CertDir, "agent.key") {
			t.Fatalf("cfg не перенацелен: cert=%q key=%q", cfg.CertFile, cfg.KeyFile)
		}
		// Ради чего всё: идемпотентный гейт снова видит идентичность.
		if id, ok := existingDeviceID(cfg, now); !ok || id != "device-relocated" {
			t.Fatalf("existingDeviceID = (%q, %v), хотим (device-relocated, true) — иначе повторный enroll погашенным токеном (401, баг v22)", id, ok)
		}
	})

	t.Run("исходная пара цела → не трогаем", func(t *testing.T) {
		cert, key := writeIdentity(t, "device-intact", now.Add(-time.Hour), now.Add(24*time.Hour))
		cfg := &config.Config{CertSource: "file", CertFile: cert, KeyFile: key}
		lay := service.Layout{Relocate: true, CertDir: t.TempDir()}
		retargetIdentityToCertDir(cfg, lay, discardLogger())
		if cfg.CertFile != cert || cfg.KeyFile != key {
			t.Fatalf("цела исходная пара, но cfg перенацелен: cert=%q key=%q", cfg.CertFile, cfg.KeyFile)
		}
	})

	t.Run("Relocate=false (Windows/MSI) → не трогаем", func(t *testing.T) {
		cfg, lay := makeRelocatedInstall(t)
		lay.Relocate = false
		orig := cfg.CertFile
		retargetIdentityToCertDir(cfg, lay, discardLogger())
		if cfg.CertFile != orig {
			t.Fatalf("Relocate=false, но cfg перенацелен: %q", cfg.CertFile)
		}
	})

	t.Run("keystore-режим → не трогаем (идентичность не в файлах)", func(t *testing.T) {
		cfg, lay := makeRelocatedInstall(t)
		cfg.CertSource = keystore.SourceKeystore
		orig := cfg.CertFile
		retargetIdentityToCertDir(cfg, lay, discardLogger())
		if cfg.CertFile != orig {
			t.Fatalf("keystore-режим, но cfg перенацелен: %q", cfg.CertFile)
		}
	})

	t.Run("в CertDir нет целой пары → не трогаем (обычный enroll-поток)", func(t *testing.T) {
		cfg, lay := makeRelocatedInstall(t)
		if err := os.Remove(filepath.Join(lay.CertDir, "agent.key")); err != nil {
			t.Fatal(err)
		}
		orig := cfg.CertFile
		retargetIdentityToCertDir(cfg, lay, discardLogger())
		if cfg.CertFile != orig {
			t.Fatalf("в CertDir нет пары, но cfg перенацелен: %q", cfg.CertFile)
		}
	})

	t.Run("CA нет по исходному пути → целимся в ca.crt из CertDir", func(t *testing.T) {
		cfg, lay := makeRelocatedInstall(t)
		caDst := filepath.Join(lay.CertDir, "ca.crt")
		copyTestFile(t, cfg.CertFile, caDst) // содержимое неважно, важен файл
		cfg.CAFile = filepath.Join(t.TempDir(), "missing-ca.crt")
		retargetIdentityToCertDir(cfg, lay, discardLogger())
		if cfg.CAFile != caDst {
			t.Fatalf("CAFile = %q, ожидали %q", cfg.CAFile, caDst)
		}
	})
}
