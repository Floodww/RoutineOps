package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genCertFiles пишет валидную пару cert/key + CA (самоподписанный, годен и как
// клиентский серт, и как CA) во временные файлы.
func genCertFiles(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-device"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	caFile = filepath.Join(dir, "ca.pem")
	for f, b := range map[string][]byte{certFile: certPEM, keyFile: keyPEM, caFile: certPEM} {
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile, caFile
}

func TestFileCertProviderLoadsIdentity(t *testing.T) {
	cert, key, ca := genCertFiles(t)
	p := FileCertProvider{CertFile: cert, KeyFile: key, CAFile: ca}

	tlsCert, err := p.ClientCertificate()
	if err != nil {
		t.Fatalf("ClientCertificate: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("пустой клиентский сертификат")
	}

	pool, err := p.RootCAs()
	if err != nil {
		t.Fatalf("RootCAs: %v", err)
	}
	if pool == nil {
		t.Fatal("nil пул CA")
	}
}

func TestFileCertProviderClientCertMissing(t *testing.T) {
	p := FileCertProvider{CertFile: "/nope/cert.pem", KeyFile: "/nope/key.pem"}
	if _, err := p.ClientCertificate(); err == nil {
		t.Fatal("ожидали ошибку на отсутствующих cert/key")
	}
}

func TestFileCertProviderRootCAsMissing(t *testing.T) {
	p := FileCertProvider{CAFile: "/nope/ca.pem"}
	if _, err := p.RootCAs(); err == nil {
		t.Fatal("ожидали ошибку на отсутствующем CA-файле")
	}
}

func TestFileCertProviderRootCAsInvalid(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(bad, []byte("это не PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := FileCertProvider{CAFile: bad}
	if _, err := p.RootCAs(); err == nil {
		t.Fatal("ожидали ошибку на файле без валидных сертификатов")
	}
}

func TestNewDialerOK(t *testing.T) {
	cert, key, ca := genCertFiles(t)
	d, err := NewDialer("routineops.example:50051", "routineops.example", FileCertProvider{CertFile: cert, KeyFile: key, CAFile: ca})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	if d.Addr() != "routineops.example:50051" {
		t.Fatalf("Addr()=%q, want routineops.example:50051", d.Addr())
	}
}

func TestNewDialerPropagatesCertError(t *testing.T) {
	// Битые пути → ClientCertificate падает → NewDialer возвращает ошибку.
	_, err := NewDialer("h:1", "h", FileCertProvider{CertFile: "/nope", KeyFile: "/nope", CAFile: "/nope"})
	if err == nil {
		t.Fatal("ожидали ошибку от NewDialer при недоступных сертификатах")
	}
}
