//go:build darwin

package keystore

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os/exec"
)

// maxPurgeIdentities — потолок правдоподобного числа дубликатов идентичности под
// одной меткой (повторные энроллы под тем же device_id). Точных совпадений больше
// потолка — что-то фундаментально не так, честно останавливаемся с ошибкой ДО
// какого-либо удаления.
const maxPurgeIdentities = 8

// Purge удаляет идентичность агента (cert + приватный ключ) из Keychain по метке
// (CN = device_id). Файловый план decommission Keychain не достаёт — без Purge
// ключевой материал списанной машины оставался бы в хранилище навсегда.
//
// keychain — путь к файлу keychain: тот же, куда клал Import (ProvisionTarget();
// "" — список поиска по умолчанию, при удалении на него полагаться не стоит).
//
// Матч СТРОГО точный, зеркало certSubjectCN в purge_windows.go: `security
// delete-identity -c` матчит CN подстрочно и case-insensitive (как
// CERT_FIND_SUBJECT_STR у CryptoAPI) — чужая идентичность, чей CN содержит
// device_id как подстроку, уехала бы вместе с приватным ключом. Поэтому
// кандидатов перечисляем сами (findExactCertHashes), сверяем CN разобранного
// серта на равенство и удаляем адресно по SHA-1 — родному идентификатору
// элемента Keychain (`delete-identity -Z`); он снимает серт вместе с приватным
// ключом. Завершающий проход, не нашедший ни одного точного совпадения,
// ПОДТВЕРЖДАЕТ, что вычищено всё. CGO не нужен — работает и в CGO-free сборке
// (симметрично Import).
func Purge(label, keychain string) error {
	if label == "" {
		return fmt.Errorf("keystore: пустая метка идентичности — purge невозможен")
	}
	deleted := 0
	for {
		hashes, err := findExactCertHashes(label, keychain)
		if err != nil {
			if deleted > 0 {
				return nil // «больше не найдено» после ≥1 снятой — вычищено
			}
			// security(1) не различает «не найдено» и прочие отказы кодом
			// возврата — отдаём вывод в ошибке, решает вызывающий (decommission
			// логирует Warn).
			return err
		}
		if len(hashes) == 0 {
			if deleted > 0 {
				return nil
			}
			return fmt.Errorf("keystore: идентичность с CN РОВНО %q в keychain не найдена (подстрочные совпадения не в счёт)", label)
		}
		if deleted+len(hashes) > maxPurgeIdentities {
			return fmt.Errorf("keystore: под меткой %q найдено уже %d точных идентичностей — потолок %d, остановлено до удаления",
				label, deleted+len(hashes), maxPurgeIdentities)
		}
		for _, h := range hashes {
			args := []string{"delete-identity", "-Z", h}
			if keychain != "" {
				args = append(args, keychain)
			}
			out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("security delete-identity -Z %s (метка %q): %w: %s", h, label, err, out)
			}
			deleted++
		}
	}
}

// findExactCertHashes перечисляет сертификаты keychain, чей Subject CN РАВЕН
// метке, и возвращает их SHA-1 (идентификатор элемента для delete-identity -Z;
// не криптографическая гарантия — адресация внутри локального Keychain).
// `security find-certificate -c` матчит подстрочно тем же правилом, что и
// delete-identity -c, поэтому перечисление полно: точное совпадение всегда
// содержит метку как подстроку. Точный отбор — по CN разобранного серта.
// Серт, который не разбирается x509, нашим быть не может (Import клал валидный) —
// пропускаем, не трогаем.
func findExactCertHashes(label, keychain string) ([]string, error) {
	args := []string{"find-certificate", "-a", "-c", label, "-p"}
	if keychain != "" {
		args = append(args, keychain)
	}
	out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("security find-certificate %q: %w: %s", label, err, out)
	}
	var hashes []string
	seen := make(map[string]bool)
	for rest := out; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || cert.Subject.CommonName != label {
			continue
		}
		h := fmt.Sprintf("%X", sha1.Sum(block.Bytes))
		if !seen[h] {
			seen[h] = true
			hashes = append(hashes, h)
		}
	}
	return hashes, nil
}
