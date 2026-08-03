package selfupdate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedCAPEM генерирует валидный самоподписанный CA-сертификат в PEM.
func selfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("создание сертификата: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestNewHTTPClient(t *testing.T) {
	// Пустой caFile → системные корни (DefaultClient), ok=true.
	if c, ok := NewHTTPClient(""); !ok || c != http.DefaultClient {
		t.Fatalf("пустой caFile: ожидали (DefaultClient, true), got (%v, %v)", c, ok)
	}

	// Несуществующий путь → ok=false, fallback на DefaultClient.
	if c, ok := NewHTTPClient(filepath.Join(t.TempDir(), "нет.pem")); ok || c != http.DefaultClient {
		t.Fatalf("отсутствующий caFile: ожидали (DefaultClient, false), got (%v, %v)", c, ok)
	}

	// Файл есть, но не валидный PEM → ok=false.
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("это не сертификат"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, ok := NewHTTPClient(junk); ok || c != http.DefaultClient {
		t.Fatalf("битый PEM: ожидали (DefaultClient, false), got (%v, %v)", c, ok)
	}

	// Валидный CA → кастомный клиент с заданным RootCAs, ok=true.
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, selfSignedCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	c, ok := NewHTTPClient(caPath)
	if !ok {
		t.Fatal("валидный CA: ожидали ok=true")
	}
	if c == http.DefaultClient || c.Transport == nil {
		t.Fatal("валидный CA: ожидали кастомный клиент с Transport")
	}
	tr, isHTTP := c.Transport.(*http.Transport)
	if !isHTTP || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("валидный CA: RootCAs не сконфигурирован в Transport")
	}
}

// CleanupOld на unix — безопасный no-op (старый inode освобождается сам).
func TestCleanupOldNoop(t *testing.T) {
	CleanupOld() // не должен паниковать
}
