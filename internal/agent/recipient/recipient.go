// Package recipient — подписанный получатель эскроу, который агент берёт у сервера
// вместо вшитого в бинарь пина.
//
// Зачем вообще подпись. Получатель — публичный ключ, но НЕ произвольный: кто
// подменит его, тот перешифрует на себя всё будущее эскроу. Поэтому рантайм-выдача
// «как есть» запрещена (аудит FileVault, Р3), и раньше единственным способом был
// пиннинг в бинарь через -ldflags. Ценой того, что смена получателя = пересборка и
// раскатка агента, то есть операция уровня релиза.
//
// Здесь пиннинг не отдаётся, а переносится на уровень выше: агент пинит РЕЛИЗНЫЙ
// ключ (тот же, которым проверяются обновления, приезжает при enroll), а получатель
// приезжает подписанным этим ключом. Приватника релиза на сервере нет, поэтому
// скомпрометированный сервер не может подсунуть свой ключ — ровно как не может
// подсунуть свой бинарь. Плюс epoch как anti-rollback floor: старую, но настоящую
// публикацию не переиграть.
//
// Пакет намеренно ничего не знает про age и про FileVault: получатель для него —
// непрозрачная строка. Поэтому его можно держать без build-тега и тестировать
// везде, а импортируется он только из enterprise-обвязки.
package recipient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Path — путь ручки на сервере (docs/self-update.md, ручка без аутентификации:
// доверие держит подпись, а не то, кто спросил).
const Path = "/api/v1/agent/escrow-recipient"

// maxBody — потолок на ответ ручки: запись крошечная, всё остальное — аномалия.
const maxBody = 64 << 10

// Signed — опубликованная запись. Имена полей JSON совпадают с серверными
// (storage.SignedRecipient) — это контракт провода, менять нельзя.
type Signed struct {
	Epoch     int64  `json:"epoch"`
	Recipient string `json:"recipient"`
	FPR       string `json:"fpr"`
	Signature string `json:"signature"` // base64, ed25519 над Canon
}

// Canon — то, что подписывает релизный ключ: epoch\nrecipient\nfpr, фиксированный
// порядок, разделитель '\n'. Подписывается ВСЯ тройка (тот же приём, что у манифеста
// обновления): подпись только над получателем позволяла бы переставить его под чужой
// epoch и так обойти anti-rollback.
func Canon(s Signed) []byte {
	return []byte(strconv.FormatInt(s.Epoch, 10) + "\n" + s.Recipient + "\n" + s.FPR)
}

// Verify проверяет подпись и полноту записи. Fail-closed: любая неполнота — отказ,
// а не «примем как есть».
func Verify(s Signed, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("получатель: нет релизного ключа для проверки подписи")
	}
	if s.Epoch <= 0 {
		return fmt.Errorf("получатель: epoch=%d, ожидался положительный", s.Epoch)
	}
	if s.Recipient == "" || s.FPR == "" {
		return errors.New("получатель: пустой recipient или fpr")
	}
	if s.Signature == "" {
		return errors.New("получатель: запись без подписи — отклонена")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return fmt.Errorf("получатель: битая подпись: %w", err)
	}
	if !ed25519.Verify(pub, Canon(s), sig) {
		return errors.New("получатель: подпись невалидна — запись не от релиза, отклонена")
	}
	return nil
}

// Fetch забирает запись с сервера. (nil, nil) — сервер отвечает 404: получателя ещё
// не публиковали, и это НЕ ошибка (парк, раскатанный до появления схемы, обязан
// продолжать работать по вшитому пину).
func Fetch(ctx context.Context, client *http.Client, endpoint string) (*Signed, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("получатель: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var s Signed
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&s); err != nil {
		return nil, fmt.Errorf("получатель: разбор ответа: %w", err)
	}
	return &s, nil
}

// EndpointFrom выводит адрес ручки из update-url: обе раздаёт один и тот же сервер,
// и другого HTTPS-адреса у агента нет (gRPC-адрес — это другой порт и другой
// протокол). Отдельный флаг не заводим: лишняя ручка настройки, которую придётся
// держать согласованной с update-url.
func EndpointFrom(updateCheckURL string) (string, error) {
	if updateCheckURL == "" {
		return "", errors.New("получатель: update-url не задан — неоткуда узнать адрес сервера")
	}
	u, err := url.Parse(updateCheckURL)
	if err != nil {
		return "", fmt.Errorf("получатель: разбор update-url: %w", err)
	}
	u.Path = Path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// Load читает закешированную запись и ПЕРЕПРОВЕРЯЕТ её подпись. Кеш нужен, чтобы
// эскроу работало при недоступном сервере (энролл на объекте без связи, отчёт
// доедет позже через pending-очередь); перепроверка — чтобы правка файла на диске
// не подменяла получателя тише, чем это сделал бы сервер.
func Load(path string, pub ed25519.PublicKey) (*Signed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var s Signed
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("получатель: разбор кеша %s: %w", path, err)
	}
	if err := Verify(s, pub); err != nil {
		return nil, fmt.Errorf("кеш %s: %w", path, err)
	}
	return &s, nil
}

// Store сохраняет проверенную запись атомарно (temp+rename): оборванная запись не
// должна оставлять полуфайл, который потом не разберётся.
func Store(path string, s Signed) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".recipient-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op после успешного rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Choose решает, какую запись считать действующей: свежескачанную или кешированную.
// Единственное правило — epoch не убывает.
//
// Возвращает (действующая, надо ли перезаписать кеш, ошибка). Ошибка означает
// попытку отката: сервер отдал epoch НИЖЕ уже виденного. Это не «сеть моргнула» —
// это либо откат публикации (сервер обязан отбивать его сам), либо подсунутая
// старая настоящая запись. Молча брать кеш в таком случае нельзя: оператор должен
// увидеть расхождение.
func Choose(fetched, cached *Signed) (*Signed, bool, error) {
	switch {
	case fetched == nil && cached == nil:
		return nil, false, nil
	case fetched == nil:
		return cached, false, nil
	case cached == nil:
		return fetched, true, nil
	case fetched.Epoch < cached.Epoch:
		return cached, false, fmt.Errorf("получатель: сервер отдал epoch=%d, а уже видели %d — откат отклонён",
			fetched.Epoch, cached.Epoch)
	case fetched.Epoch == cached.Epoch:
		// Тот же epoch — оставляем уже принятую запись (первая увиденная выигрывает).
		// Две РАЗНЫЕ валидно подписанные записи с одним epoch означают ошибку
		// публикации у деплойера (сервер такую вторую публикацию отбивает сам);
		// брать вторую в этом случае — значит молча разъехаться с теми агентами,
		// кто успел взять первую.
		return cached, false, nil
	default:
		return fetched, true, nil
	}
}

// Resolve — полный путь: кеш → сеть → выбор → сохранение кеша.
//
// Контракт возврата нестандартный и намеренный: действующая запись и проблема
// возвращаются ВМЕСТЕ. Недоступный сервер при живом кеше — это деградация, а не
// отказ (эскроу обязано работать без связи), но она обязана быть видна в журнале.
// Поэтому вызывающий смотрит так: запись != nil → работаем, проблема != nil →
// пишем в лог (Warn, если запись есть; Error, если нет).
func Resolve(ctx context.Context, client *http.Client, endpoint, cachePath string, pub ed25519.PublicKey) (*Signed, error) {
	cached, cacheErr := Load(cachePath, pub)

	fetched, fetchErr := Fetch(ctx, client, endpoint)
	if fetchErr == nil && fetched != nil {
		if err := Verify(*fetched, pub); err != nil {
			fetched, fetchErr = nil, err
		}
	}

	active, save, chooseErr := Choose(fetched, cached)
	if save {
		if err := Store(cachePath, *active); err != nil {
			return active, fmt.Errorf("получатель: кеш не сохранён (в следующий раз пойдём в сеть заново): %w", err)
		}
	}
	return active, errors.Join(cacheErr, fetchErr, chooseErr)
}
