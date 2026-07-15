package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/config"
)

// genTLSCert делает самоподписанный ECDSA-сертификат с заданными CN и сроком.
func genTLSCert(t *testing.T, cn string, notBefore, notAfter time.Time) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return tls.Certificate{Certificate: [][]byte{der}}, certPEM
}

type fakeProvider struct {
	cert tls.Certificate
	err  error
}

func (f fakeProvider) ClientCertificate() (tls.Certificate, error) { return f.cert, f.err }
func (f fakeProvider) RootCAs() (*x509.CertPool, error)            { return x509.NewCertPool(), nil }

// diagConfig — конфиг с временными путями для diag.
func diagConfig(t *testing.T, caPEM []byte) *config.Config {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		ServerAddr:        "routineops.example:55443",
		ServerName:        "routineops-server",
		CertSource:        "file",
		CAFile:            caFile,
		OutboxDir:         filepath.Join(dir, "outbox"),
		TaskStateFile:     filepath.Join(dir, "tasks.seen"),
		ScriptDedupFile:   filepath.Join(dir, "scripts.seen"),
		ForbiddenListFile: filepath.Join(dir, "forbidden.txt"),
	}
}

func TestDaysUntilExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ci := certInfo{notAfter: now.Add(10 * 24 * time.Hour)}
	if d := ci.daysUntilExpiry(now); d != 10 {
		t.Errorf("daysUntilExpiry = %d, ожидалось 10", d)
	}
	past := certInfo{notAfter: now.Add(-3 * 24 * time.Hour)}
	if d := past.daysUntilExpiry(now); d != -3 {
		t.Errorf("daysUntilExpiry (истёкший) = %d, ожидалось -3", d)
	}
}

func TestLeafInfo(t *testing.T) {
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	cert, _ := genTLSCert(t, "device-abc", time.Now().Add(-time.Hour), notAfter)
	ci, err := leafInfo(cert)
	if err != nil {
		t.Fatalf("leafInfo: %v", err)
	}
	if ci.subjectCN != "device-abc" {
		t.Errorf("subjectCN = %q, ожидалось device-abc", ci.subjectCN)
	}
	// Самоподписанный: issuer = subject (поле Issuer шаблона игнорируется x509).
	if ci.issuerCN != "device-abc" {
		t.Errorf("issuerCN = %q, ожидалось device-abc (self-signed)", ci.issuerCN)
	}
}

func TestLeafInfo_EmptyCert(t *testing.T) {
	if _, err := leafInfo(tls.Certificate{}); err == nil {
		t.Error("ожидалась ошибка для пустого сертификата")
	}
}

func TestCaFileInfo(t *testing.T) {
	_, caPEM := genTLSCert(t, "the-ca", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ci, err := caFileInfo(path)
	if err != nil {
		t.Fatalf("caFileInfo: %v", err)
	}
	if ci.subjectCN != "the-ca" {
		t.Errorf("subjectCN = %q, ожидалось the-ca", ci.subjectCN)
	}
}

func TestExpiryNote(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		days int
		want string
	}{
		{100, "через"},
		{certExpiryWarnDays - 1, "ВНИМАНИЕ"},
		{-5, "ИСТЁК"},
	}
	for _, c := range cases {
		ci := certInfo{notAfter: now.Add(time.Duration(c.days) * 24 * time.Hour)}
		if note := expiryNote(ci, now); !strings.Contains(note, c.want) {
			t.Errorf("days=%d: note=%q, ожидали подстроку %q", c.days, note, c.want)
		}
	}
}

func TestRunDiag_HealthyCert(t *testing.T) {
	cert, caPEM := genTLSCert(t, "device-ok", time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	cfg := diagConfig(t, caPEM)

	var buf bytes.Buffer
	code := runDiag(&buf, cfg, fakeProvider{cert: cert}, time.Now(), nil)
	if code != 0 {
		t.Errorf("exit code = %d, ожидался 0; вывод:\n%s", code, buf.String())
	}
	out := buf.String()
	for _, want := range []string{"device-ok", "client cert", "server:", "outbox:"} {
		if !strings.Contains(out, want) {
			t.Errorf("в выводе нет %q:\n%s", want, out)
		}
	}
}

func TestRunDiag_ExpiredCert_Exit1(t *testing.T) {
	cert, caPEM := genTLSCert(t, "device-old", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	cfg := diagConfig(t, caPEM)

	var buf bytes.Buffer
	code := runDiag(&buf, cfg, fakeProvider{cert: cert}, time.Now(), nil)
	if code != 1 {
		t.Errorf("истёкший серт: exit code = %d, ожидался 1", code)
	}
	if !strings.Contains(buf.String(), "ИСТЁК") {
		t.Errorf("нет пометки ИСТЁК:\n%s", buf.String())
	}
}

func TestRunDiag_CertLoadError_Exit1(t *testing.T) {
	_, caPEM := genTLSCert(t, "ca", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cfg := diagConfig(t, caPEM)

	var buf bytes.Buffer
	code := runDiag(&buf, cfg, fakeProvider{err: errors.New("keystore locked")}, time.Now(), nil)
	if code != 1 {
		t.Errorf("ошибка загрузки серта: exit code = %d, ожидался 1", code)
	}
	if !strings.Contains(buf.String(), "keystore locked") {
		t.Errorf("нет текста ошибки:\n%s", buf.String())
	}
}

// logCertHealth должен выбирать уровень/сообщение по сроку серта.
func TestLogCertHealth(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		loadErr   error
		wantLevel string
		wantText  string
	}{
		{"healthy", now.Add(-time.Hour), now.Add(60 * 24 * time.Hour), nil, "INFO", "в порядке"},
		{"near_expiry", now.Add(-time.Hour), now.Add(5 * 24 * time.Hour), nil, "WARN", "скоро истекает"},
		{"expired", now.Add(-48 * time.Hour), now.Add(-time.Hour), nil, "ERROR", "ИСТЁК"},
		{"not_yet_valid", now.Add(24 * time.Hour), now.Add(60 * 24 * time.Hour), nil, "WARN", "ещё не действителен"},
		{"load_error", time.Time{}, time.Time{}, errors.New("keystore locked"), "ERROR", "не удалось загрузить"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			var provider fakeProvider
			if c.loadErr != nil {
				provider = fakeProvider{err: c.loadErr}
			} else {
				cert, _ := genTLSCert(t, "device-x", c.notBefore, c.notAfter)
				provider = fakeProvider{cert: cert}
			}
			logCertHealth(log, provider, now)
			out := buf.String()
			if !strings.Contains(out, "level="+c.wantLevel) {
				t.Errorf("ожидался уровень %s; вывод: %s", c.wantLevel, out)
			}
			if !strings.Contains(out, c.wantText) {
				t.Errorf("ожидался текст %q; вывод: %s", c.wantText, out)
			}
		})
	}
}

// TestRunDiag_SelfUpdateDead_Exit1 — самый ценный тест правки: -update-url прописан,
// ключа нет → diag обязан отдать 1 и напечатать причину. Иначе мёртвое обновление
// на флоте так и остаётся невидимым.
func TestRunDiag_SelfUpdateDead_Exit1(t *testing.T) {
	oldK, oldDir := releasePubKey, installedCertDir
	defer func() { releasePubKey, installedCertDir = oldK, oldDir }()
	releasePubKey = ""
	installedCertDir = t.TempDir()

	cert, caPEM := genTLSCert(t, "device-ok", time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	cfg := diagConfig(t, caPEM)
	cfg.UpdateCheckURL = "https://routineops.example/api/v1/agent/version"

	var buf bytes.Buffer
	if code := runDiag(&buf, cfg, fakeProvider{cert: cert}, time.Now(), nil); code != 1 {
		t.Errorf("мёртвый self-update: exit=%d, ждали 1; вывод:\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "обновления НЕ ставятся") {
		t.Errorf("нет явной пометки о мёртвом self-update:\n%s", buf.String())
	}
}

func TestRunDiag_Probe(t *testing.T) {
	cert, caPEM := genTLSCert(t, "device-ok", time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	cfg := diagConfig(t, caPEM)

	// Успешная проба — exit 0, "OK".
	var ok bytes.Buffer
	if code := runDiag(&ok, cfg, fakeProvider{cert: cert}, time.Now(), func() error { return nil }); code != 0 {
		t.Errorf("успешная проба: exit = %d, ожидался 0", code)
	}
	if !strings.Contains(ok.String(), "OK") {
		t.Errorf("нет OK в выводе пробы:\n%s", ok.String())
	}

	// Неудачная проба — exit 1, текст ошибки.
	var fail bytes.Buffer
	code := runDiag(&fail, cfg, fakeProvider{cert: cert}, time.Now(), func() error { return errors.New("connection refused") })
	if code != 1 {
		t.Errorf("неудачная проба: exit = %d, ожидался 1", code)
	}
	if !strings.Contains(fail.String(), "connection refused") {
		t.Errorf("нет текста ошибки пробы:\n%s", fail.String())
	}
}
