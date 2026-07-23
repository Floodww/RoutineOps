//go:build windows

package keystore

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// TestPurgeRemovesIdentityAndKey — round-trip Import → Purge в CurrentUser\My:
// после Purge провайдер обязан НЕ находить идентичность, а персистентный CNG-ключ
// обязан исчезнуть из KSP. Второе — главное: удаление одного серта (semantics
// certutil -delstore) ОСИРОТИЛО бы приватный ключ, и тест обязан это поймать.
func TestPurgeRemovesIdentityAndKey(t *testing.T) {
	for _, bin := range []string{"certutil", "powershell"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("нет %s", bin)
		}
	}
	label := fmt.Sprintf("MDM-CI-PURGE-%d", randSuffix())
	certPEM, keyPEM := genSelfSignedIdentity(t, label)

	if err := Import(certPEM, keyPEM, "CurrentUser"); err != nil {
		t.Skipf("Import в CurrentUser не удался (окружение): %v", err)
	}
	// Подстраховочная чистка, если Purge не дойдёт/сломается — не мусорим в сторе.
	t.Cleanup(func() {
		_ = exec.Command("certutil", "-user", "-delstore", "My", label).Run()
	})

	p := &certStoreProvider{label: label}
	if _, err := p.ClientCertificate(); err != nil {
		t.Fatalf("до Purge идентичность должна находиться: %v", err)
	}

	// Имя CNG-контейнера — ДО Purge (после серта уже нет, имя не узнать).
	// certutil -importpfx генерит его сам, поэтому только через сам серт.
	keyName := cngKeyName(t, label)

	if err := Purge(label, "CurrentUser"); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if _, err := p.ClientCertificate(); err == nil {
		t.Fatal("после Purge идентичность всё ещё находится в сторе")
	}
	exists := strings.TrimSpace(psOut(t, fmt.Sprintf(
		`[System.Security.Cryptography.CngKey]::Exists("%s")`, keyName)))
	if !strings.EqualFold(exists, "False") {
		t.Errorf("CNG-ключ %q пережил Purge (Exists=%s) — приватный ключ осиротел", keyName, exists)
	}
	if err := Purge(label, "CurrentUser"); err == nil {
		t.Fatal("повторный Purge обязан вернуть ошибку «не найдено», а не тихий успех")
	}
}

// cngKeyName достаёт имя персистентного CNG-контейнера приватного ключа серта с
// CN=label из CurrentUser\My. Сбой — Fatalf, а не тихий пропуск: проверка
// выживания ключа (CngKey::Exists ниже) — ГЛАВНЫЙ ассерт теста, ради которого
// Purge удаляет ключ перед сертом; молча выключенной она делала бы тест зелёным
// при регрессии «серт снят, ключ осиротел». Import через certutil уже прошёл —
// ключ существует и обязан быть читаем.
func cngKeyName(t *testing.T, label string) string {
	t.Helper()
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'
$s = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","CurrentUser")
$s.Open("ReadOnly")
$c = $s.Certificates | Where-Object { $_.Subject -eq "CN=%s" } | Select-Object -First 1
if ($c -eq $null) { $s.Close(); throw "cert not found" }
$k = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($c)
$k.Key.KeyName
$k.Dispose()
$s.Close()`, label)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		t.Fatalf("имя CNG-контейнера не получено — граница удаления ключа непроверяема: %v\n%s", err, out)
	}
	name := strings.TrimSpace(string(out))
	if name == "" {
		t.Fatal("пустое имя CNG-контейнера — граница удаления ключа непроверяема")
	}
	return name
}

func psOut(t *testing.T, command string) string {
	t.Helper()
	out, err := exec.Command("powershell", "-NoProfile", "-Command", command).CombinedOutput()
	if err != nil {
		t.Fatalf("powershell %q: %v\n%s", command, err, out)
	}
	return string(out)
}
