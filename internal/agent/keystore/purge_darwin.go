//go:build darwin

package keystore

import (
	"fmt"
	"os/exec"
)

// maxPurgeIdentities — потолок правдоподобного числа дубликатов идентичности под
// одной меткой (повторные энроллы под тем же device_id). Снято больше потолка и
// конца не видно — метка матчит не то, честно останавливаемся с ошибкой.
const maxPurgeIdentities = 8

// Purge удаляет идентичность агента (cert + приватный ключ) из Keychain по метке
// (CN = device_id). Файловый план decommission Keychain не достаёт — без Purge
// ключевой материал списанной машины оставался бы в хранилище навсегда.
//
// keychain — путь к файлу keychain: тот же, куда клал Import (ProvisionTarget();
// "" — список поиска по умолчанию, при удалении на него полагаться не стоит).
// `security delete-identity -c` матчит по CN и снимает серт вместе с приватным
// ключом; дубликаты выметаются циклом — каждый успешный вызов удаляет одну
// идентичность, а завершающий отказ «не найдено» ПОДТВЕРЖДАЕТ, что вычищено всё
// (в т.ч. когда дубликатов ровно maxPurgeIdentities). CGO не нужен — работает и
// в CGO-free сборке (симметрично Import).
func Purge(label, keychain string) error {
	if label == "" {
		return fmt.Errorf("keystore: пустая метка идентичности — purge невозможен")
	}
	args := []string{"delete-identity", "-c", label}
	if keychain != "" {
		args = append(args, keychain)
	}
	deleted := 0
	for {
		out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
		if err != nil {
			if deleted > 0 {
				return nil // «больше не найдено» после ≥1 снятой — вычищено
			}
			// security(1) не различает «не найдено» и прочие отказы кодом
			// возврата — отдаём вывод в ошибке, решает вызывающий (decommission
			// логирует Warn).
			return fmt.Errorf("security delete-identity %q: %w: %s", label, err, out)
		}
		deleted++
		if deleted > maxPurgeIdentities {
			return fmt.Errorf("keystore: снято уже %d идентичностей %q и это не конец — метка матчит не то", deleted, label)
		}
	}
}
