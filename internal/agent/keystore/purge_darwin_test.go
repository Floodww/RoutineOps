//go:build darwin && cgo

package keystore

import (
	"bytes"
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

// TestPurgeExactCNBoundary — граница ТОЧНОГО матча CN: соседняя идентичность,
// чей CN содержит метку как ПОДСТРОКУ, обязана пережить Purge вместе со своим
// приватным ключом. Ровно та дыра, что жила в `delete-identity -c` (подстрочный
// case-insensitive матч): Purge по device_id снёс бы чужую идентичность. Тест
// пересекает живую границу Keychain — та же привилегированная граница, что у бага.
func TestPurgeExactCNBoundary(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("keychain-интеграция пропускается в CI (нет доступа к Security-сервисам)")
	}
	for _, bin := range []string{"openssl", "security"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("нет %s: %v", bin, err)
		}
	}

	dir := t.TempDir()
	const label = "mdm-test-exact-7f31"
	const neighbor = label + "-neighbor" // содержит label как подстроку
	mkIdentity := func(cn string) (certPEM, keyPEM []byte) {
		t.Helper()
		keyPath := filepath.Join(dir, cn+"-k.pem")
		certPath := filepath.Join(dir, cn+"-c.pem")
		run(t, "openssl", "genpkey", "-algorithm", "EC",
			"-pkeyopt", "ec_paramgen_curve:P-256", "-out", keyPath)
		run(t, "openssl", "req", "-x509", "-key", keyPath, "-days", "1",
			"-subj", "/CN="+cn, "-out", certPath)
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM, err = os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		return certPEM, keyPEM
	}

	kc := filepath.Join(dir, "mdm-test-exact.keychain")
	run(t, "security", "create-keychain", "-p", "test", kc)
	t.Cleanup(func() { _ = exec.Command("/usr/bin/security", "delete-keychain", kc).Run() })
	run(t, "security", "unlock-keychain", "-p", "test", kc)

	ourCert, ourKey := mkIdentity(label)
	nbCert, nbKey := mkIdentity(neighbor)
	if err := Import(ourCert, ourKey, kc); err != nil {
		t.Skipf("Import в keychain не удался (вероятно ограничения окружения): %v", err)
	}
	if err := Import(nbCert, nbKey, kc); err != nil {
		t.Skipf("Import соседа не удался: %v", err)
	}

	// Гард от вырождения теста: подстрочный поиск security ОБЯЗАН видеть под
	// меткой label оба серта (наш + сосед) — иначе тест ничего не доказывает
	// про старую дыру. И ровно один из них — точное совпадение.
	out, err := exec.Command("/usr/bin/security",
		"find-certificate", "-a", "-c", label, "-p", kc).CombinedOutput()
	if err != nil {
		t.Fatalf("find-certificate: %v\n%s", err, out)
	}
	if n := bytes.Count(out, []byte("-----BEGIN CERTIFICATE-----")); n != 2 {
		t.Fatalf("прекондиция: подстрочный поиск обязан видеть 2 серта (наш+сосед), видит %d", n)
	}
	if got, err := findExactCertHashes(label, kc); err != nil || len(got) != 1 {
		t.Fatalf("прекондиция: ровно 1 точная идентичность %q, получено %d, err=%v", label, len(got), err)
	}

	// С двумя идентичностями в keychain каждая метка обязана резолвиться в СВОЙ
	// серт. kSecAttrLabel для identity-запросов file-keychain игнорируется
	// (живьём: запрос с любой меткой отдавал первую попавшуюся идентичность) —
	// точный отбор по CN делает mdmCopyIdentity; без него агент на System.keychain
	// парка мог бы схватить чужую идентичность (VPN/Wi-Fi/сторонний MDM).
	p := &keychainProvider{label: label, caFile: filepath.Join(dir, label+"-c.pem"), keychain: kc}
	pn := &keychainProvider{label: neighbor, caFile: filepath.Join(dir, neighbor+"-c.pem"), keychain: kc}
	for _, tc := range []struct {
		pr   *keychainProvider
		want string
	}{{p, label}, {pn, neighbor}} {
		crt, err := tc.pr.ClientCertificate()
		if err != nil {
			t.Fatalf("до Purge идентичность %q обязана находиться: %v", tc.want, err)
		}
		if cn := crt.Leaf.Subject.CommonName; cn != tc.want {
			t.Fatalf("провайдер по метке %q вернул чужой серт CN=%q", tc.want, cn)
		}
	}

	if err := Purge(label, kc); err != nil {
		t.Fatalf("Purge: %v", err)
	}

	// Наша идентичность снята…
	if _, err := p.ClientCertificate(); err == nil {
		t.Fatal("после Purge идентичность агента всё ещё в keychain")
	}
	// …а сосед жив целиком: идентичность резолвится И приватный ключ физически на месте.
	if _, err := pn.ClientCertificate(); err != nil {
		t.Fatalf("сосед %q обязан пережить Purge(%q): %v", neighbor, label, err)
	}
	if out, err := exportPrivKeys(kc, filepath.Join(dir, "mid.p12")); err != nil {
		t.Fatalf("приватный ключ соседа обязан пережить Purge: %v\n%s", err, out)
	}

	// Повторный Purge по label — «не найдено»: подстрочный сосед не в счёт.
	if err := Purge(label, kc); err == nil {
		t.Fatal("повторный Purge обязан вернуть «не найдено», а не удалять соседа")
	}
	if _, err := pn.ClientCertificate(); err != nil {
		t.Fatalf("сосед пропал после повторного Purge: %v", err)
	}

	// Симметрия: Purge по метке соседа добивает keychain дочиста — и серт, и ключ.
	if err := Purge(neighbor, kc); err != nil {
		t.Fatalf("Purge(%q): %v", neighbor, err)
	}
	if out, err := exportPrivKeys(kc, filepath.Join(dir, "post.p12")); err == nil {
		t.Errorf("после обоих Purge в keychain остались приватные ключи:\n%s", out)
	}
}

// exportPrivKeys — `security export -t privKeys` из изолированного keychain: код
// возврата и есть индикатор «остались ли в keychain приватные ключи».
func exportPrivKeys(keychain, outPath string) ([]byte, error) {
	return exec.Command("/usr/bin/security", "export", "-k", keychain,
		"-t", "privKeys", "-f", "pkcs12", "-P", "test", "-o", outPath).CombinedOutput()
}
