// Package secretbox — симметричное шифрование секретов at-rest, которые серверу
// ОБЯЗАНО быть можно расшифровать.
//
// Почему не internal/server/crypto: там seal-only, приватный ключ живёт офлайн, и
// сервер принципиально не умеет открывать заэскроенное. Здесь ровно наоборот —
// без плейнтекста нечем подписать webhook и нечем обменять code на токен у IdP.
// Общий примитив для этих двух задач был бы ошибкой: он либо сломал бы работу, либо
// утащил бы приват эскроу на прод.
//
// Пакет появился, когда одну и ту же схему конверта потребовалось читать из ДВУХ
// процессов-потребителей: HTTP-слой пишет секрет приёмника SIEM, фоновый воркер его
// читает. До этого схема жила копиями в api и oidc, и четвёртая копия в worker
// означала бы, что формат конверта больше никто не держит в одном месте.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// EnvelopeV1 — префикс формата. Версия хранится В САМОМ значении: без неё
// legacy-плейнтекст неотличим от шифртекста, и «расшифровать» мусор молча удавалось бы.
const EnvelopeV1 = "v1:"

// ErrUndecryptable — значение не открывается текущим ключом.
//
// Единая ошибка на все причины (не тот префикс, битый base64, не сошёлся тег)
// намеренно: снаружи разница между ними не значит ничего, а подробность подсказывала
// бы, на каком шаге остановилась попытка подбора.
var ErrUndecryptable = errors.New("секрет не расшифровывается: сменился JWT_SECRET либо запись повреждена")

// Box — AES-256-GCM на ключе, выведенном HKDF из корневого секрета инсталляции.
type Box struct{ aead cipher.AEAD }

// New выводит ключ из root под меткой info.
//
// Метка обязательна и разделяет назначения: один и тот же JWT-секрет не должен
// давать одинаковый ключевой материал секрету MFA, приватнику SP и подписи webhook'а
// — иначе утечка одного открывает остальные.
//
// Корень — JWT-секрет, а не отдельная переменная окружения. У него уже есть проверки
// на пустоту, дефолт и длину при старте сервера; у нового секрета их пришлось бы
// заводить заново, и на практике он оказался бы дефолтным.
func New(root []byte, info string) (*Box, error) {
	if len(strings.TrimSpace(string(root))) == 0 {
		return nil, errors.New("secretbox: пустой корневой секрет")
	}
	if info == "" {
		return nil, errors.New("secretbox: пустая метка назначения")
	}
	key, err := hkdf.Key(sha256.New, root, nil, info, 32)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return &Box{aead: aead}, nil
}

// Seal шифрует: "v1:" + base64(nonce ‖ ciphertext‖tag).
func (b *Box) Seal(plain string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	return EnvelopeV1 + base64.StdEncoding.EncodeToString(b.aead.Seal(nonce, nonce, []byte(plain), nil)), nil
}

// Open расшифровывает. Любая непонятная форма — ошибка, а не попытка истолковать
// значение как плейнтекст: молчаливый фолбэк «наверное, это и есть секрет» и есть
// та дыра, ради которой конверт вводился.
func (b *Box) Open(enc string) (string, error) {
	rest, ok := strings.CutPrefix(enc, EnvelopeV1)
	if !ok {
		return "", ErrUndecryptable
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return "", ErrUndecryptable
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return "", ErrUndecryptable
	}
	pt, err := b.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", ErrUndecryptable
	}
	return string(pt), nil
}
