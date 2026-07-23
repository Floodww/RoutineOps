//go:build darwin && cgo

package keystore

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPurgeRemovesIdentity — round-trip Import → Purge в изолированном keychain:
// после Purge провайдер обязан НЕ находить идентичность (серт и приватный ключ
// сняты), повторный Purge — честно вернуть «не найдено». Ровно та граница, через
// которую жил баг: decommission удалял файлы, а Keychain оставался нетронут.
func TestPurgeRemovesIdentity(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("keychain-интеграция пропускается в CI (нет доступа к Security-сервисам)")
	}
	for _, bin := range []string{"openssl", "security"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("нет %s: %v", bin, err)
		}
	}

	dir := t.TempDir()
	const label = "mdm-test-purge-2c9d"
	keyPath := filepath.Join(dir, "k.pem")
	certPath := filepath.Join(dir, "c.pem")
	run(t, "openssl", "genpkey", "-algorithm", "EC",
		"-pkeyopt", "ec_paramgen_curve:P-256", "-out", keyPath)
	run(t, "openssl", "req", "-x509", "-key", keyPath, "-days", "1",
		"-subj", "/CN="+label, "-out", certPath)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	kc := filepath.Join(dir, "mdm-test-purge.keychain")
	run(t, "security", "create-keychain", "-p", "test", kc)
	t.Cleanup(func() { _ = exec.Command("/usr/bin/security", "delete-keychain", kc).Run() })
	run(t, "security", "unlock-keychain", "-p", "test", kc)

	if err := Import(certPEM, keyPEM, kc); err != nil {
		t.Skipf("Import в keychain не удался (вероятно ограничения окружения): %v", err)
	}

	p := &keychainProvider{label: label, caFile: certPath, keychain: kc}
	if _, err := p.ClientCertificate(); err != nil {
		t.Fatalf("до Purge идентичность должна находиться: %v", err)
	}
	// Гард от вакуумной проверки ключа ниже: до Purge экспорт приватных ключей из
	// изолированного keychain ОБЯЗАН удаваться (ключ там ровно один — наш).
	if out, err := exportPrivKeys(kc, filepath.Join(dir, "pre.p12")); err != nil {
		t.Fatalf("до Purge экспорт приватного ключа обязан удаваться: %v\n%s", err, out)
	}

	if err := Purge(label, kc); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if _, err := p.ClientCertificate(); err == nil {
		t.Fatal("после Purge идентичность всё ещё находится в keychain")
	}
	// Граница именно ПРИВАТНОГО КЛЮЧА, не только идентичности: kSecClassIdentity
	// перестаёт резолвиться уже при удалении одного серта, и осиротевший ключ
	// провайдер не увидел бы. Экспорт privKeys видит ровно ключи: после Purge в
	// изолированном keychain их быть не должно — экспорт обязан падать.
	if out, err := exportPrivKeys(kc, filepath.Join(dir, "post.p12")); err == nil {
		t.Errorf("после Purge в keychain остались приватные ключи (экспорт удался) — ключ осиротел:\n%s", out)
	}
	if err := Purge(label, kc); err == nil {
		t.Fatal("повторный Purge обязан вернуть ошибку «не найдено», а не тихий успех")
	}
}

// exportPrivKeys — `security export -t privKeys` из изолированного keychain: код
// возврата и есть индикатор «остались ли в keychain приватные ключи».
func exportPrivKeys(keychain, outPath string) ([]byte, error) {
	return exec.Command("/usr/bin/security", "export", "-k", keychain,
		"-t", "privKeys", "-f", "pkcs12", "-P", "test", "-o", outPath).CombinedOutput()
}
