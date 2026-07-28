//go:build windows

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestCertStoreProviderRoundTrip создаёт самоподписанный серт с CNG-ключом в
// CurrentUser\My, достаёт идентичность провайдером и проверяет, что подпись через
// NCryptSignHash валидируется публичным ключом серта. Чистит за собой. Skip, если
// PowerShell/New-SelfSignedCertificate недоступны.
func TestCertStoreProviderRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("powershell"); err != nil {
		t.Skip("нет powershell")
	}
	label := fmt.Sprintf("MDM-CI-%d", randSuffix())

	// Создаём серт с ПЕРСИСТЕНТНЫМ CNG-ключом и кладём в CurrentUser\My через
	// .NET X509Store — без зависимости от PSDrive Cert: (его нет в pwsh на runner).
	// Персистентный ключ + KeyProvInfo нужны, чтобы CryptAcquireCertificatePrivateKey
	// его нашёл (как у реального серта после энроллмента).
	create := fmt.Sprintf(`$ErrorActionPreference='Stop'
$kp = New-Object System.Security.Cryptography.CngKeyCreationParameters
$kp.Provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
$kp.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
$key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::ECDsaP256, "%s-key", $kp)
$ecdsa = New-Object System.Security.Cryptography.ECDsaCng($key)
$req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest("CN=%s", $ecdsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
$cert = $req.CreateSelfSigned([DateTimeOffset]::Now.AddMinutes(-5), [DateTimeOffset]::Now.AddDays(1))
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","CurrentUser")
$store.Open("ReadWrite"); $store.Add($cert); $store.Close()
$cert.Thumbprint`, label, label)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", create).CombinedOutput()
	if err != nil {
		t.Skipf("создание серта в сторе не удалось: %v\n%s", err, out)
	}
	thumb := strings.TrimSpace(string(out))
	if thumb == "" {
		t.Skipf("пустой thumbprint, вывод: %s", out)
	}
	t.Cleanup(func() {
		cleanup := fmt.Sprintf(`$ErrorActionPreference='SilentlyContinue'
$s = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","CurrentUser")
$s.Open("ReadWrite")
$c = $s.Certificates | Where-Object { $_.Thumbprint -eq "%s" }
if ($c) { $s.Remove($c) }
$s.Close()
try { [System.Security.Cryptography.CngKey]::Open("%s-key").Delete() } catch {}`, thumb, label)
		_ = exec.Command("powershell", "-NoProfile", "-Command", cleanup).Run()
	})

	p := &certStoreProvider{label: label}
	cert, err := p.ClientCertificate()
	if err != nil {
		t.Fatalf("ClientCertificate: %v", err)
	}
	if cert.Leaf == nil || cert.Leaf.Subject.CommonName != label {
		t.Fatalf("CN = %q, want %q", cert.Leaf.Subject.CommonName, label)
	}

	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("PrivateKey не crypto.Signer: %T", cert.PrivateKey)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("публичный ключ не ECDSA: %T", signer.Public())
	}

	digest := sha256.Sum256([]byte("MDM windows cert store test"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign через NCrypt: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("подпись NCrypt не прошла проверку публичным ключом серта")
	}
}

// TestImportThenProvide прогоняет полный путь провижининга: генерим идентичность,
// keystore.Import (PFX → certutil) кладёт её в CurrentUser\My, провайдер достаёт
// и подписывает через NCrypt. Так проверяется и Import, и провайдер вместе. Skip,
// если certutil недоступен/без прав.
func TestImportThenProvide(t *testing.T) {
	if _, err := exec.LookPath("certutil"); err != nil {
		t.Skip("нет certutil")
	}
	label := fmt.Sprintf("MDM-CI-IMP-%d", randSuffix())
	certPEM, keyPEM := genSelfSignedIdentity(t, label)

	target := testProvisionTarget()
	if err := Import(certPEM, keyPEM, target); err != nil {
		t.Fatalf("Import в %s: %v", target, err)
	}
	t.Cleanup(func() { _ = delstoreCmd(target, label).Run() })

	p := &certStoreProvider{label: label}
	cert, err := p.ClientCertificate()
	if err != nil {
		t.Fatalf("ClientCertificate после Import: %v", err)
	}
	if cert.Leaf == nil || cert.Leaf.Subject.CommonName != label {
		t.Fatalf("CN = %q, want %q", cert.Leaf.Subject.CommonName, label)
	}
	signer := cert.PrivateKey.(crypto.Signer)
	pub := signer.Public().(*ecdsa.PublicKey)
	digest := sha256.Sum256([]byte("import-then-provide"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("подпись после Import не прошла проверку")
	}
}

// genSelfSignedIdentity создаёт самоподписанный ECDSA-серт (CN=label) и
// возвращает cert PEM + ключ в PKCS8 PEM (как выдаёт enroll).
func genSelfSignedIdentity(t *testing.T, label string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: label},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return certPEM, keyPEM
}

func randSuffix() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// testProvisionTarget выбирает стор ТАК ЖЕ, как продакшн (ProvisionTarget):
// под повышенными правами — LocalMachine\My, иначе CurrentUser\My.
//
// Раньше тесты жёстко били в CurrentUser, и из-за этого ветка LocalMachine —
// та самая, в которой живёт служба под LocalSystem, — не проверялась НИКОГДА:
// под SYSTEM импорт в CurrentUser вообще не поддерживается (certutil отдаёт
// 0x80070032 ERROR_NOT_SUPPORTED), и тест уходил в skip. Пропущенная проверка
// привилегированного пути неотличима от пройденной — ровно так у нас уже
// оставался незакрытым гейт совместимости контракта.
func testProvisionTarget() string { return ProvisionTarget() }

// certutilScopeArgs — ключ области для certutil, парный выбранному стору.
func certutilScopeArgs(target string) []string {
	if target == "CurrentUser" {
		return []string{"-user"}
	}
	return nil
}

// delstoreCmd собирает команду подчистки в той же области, куда клали.
func delstoreCmd(target, label string) *exec.Cmd {
	args := append(certutilScopeArgs(target), "-delstore", "My", label)
	return exec.Command("certutil", args...)
}
