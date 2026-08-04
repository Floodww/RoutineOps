package secretbox_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/secretbox"
)

const (
	root = "jwt-секрет-инсталляции-достаточной-длины"
	info = "siem-webhook-secret"
)

func mustNew(t *testing.T, root []byte, info string) *secretbox.Box {
	t.Helper()
	b, err := secretbox.New(root, info)
	if err != nil {
		t.Fatalf("New(%q) = %v", info, err)
	}
	return b
}

// Инвариант, ради которого пакет вообще появился: секрет пишет HTTP-слой, а читает
// его ДРУГОЙ процесс (фоновый воркер). Оба выводят ключ сами из root+info, общего
// состояния между ними нет — если вывод ключа перестанет быть детерминированным,
// выгрузка в SIEM отвалится в проде, а не в тестах.
func TestOpenAcrossProcesses(t *testing.T) {
	writer := mustNew(t, []byte(root), info)
	reader := mustNew(t, []byte(root), info)

	enc, err := writer.Seal("s3cret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !strings.HasPrefix(enc, secretbox.EnvelopeV1) {
		t.Errorf("конверт без версии: %q", enc)
	}
	if strings.Contains(enc, "s3cret") {
		t.Errorf("плейнтекст виден в конверте: %q", enc)
	}

	got, err := reader.Open(enc)
	if err != nil || got != "s3cret" {
		t.Fatalf("Open = %q, %v; want \"s3cret\", nil", got, err)
	}
}

// Nonce обязан быть свежим на каждый Seal: повтор nonce на одном ключе в GCM
// вскрывает не одну запись, а обе сразу.
func TestSealNonceIsFresh(t *testing.T) {
	b := mustNew(t, []byte(root), info)
	first, err := b.Seal("одно и то же")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := b.Seal("одно и то же")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if first == second {
		t.Fatalf("два Seal одного плейнтекста совпали — nonce переиспользован: %q", first)
	}
}

func TestOpenRejects(t *testing.T) {
	b := mustNew(t, []byte(root), info)
	enc, err := b.Seal("s3cret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	body := strings.TrimPrefix(enc, secretbox.EnvelopeV1)

	// Порча последнего байта бьёт по тегу GCM: конверт остаётся валидным base64
	// нужной длины, то есть до сверки тега доходят все проверки формы.
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("тело конверта не base64: %v", err)
	}
	raw[len(raw)-1] ^= 0xFF
	tampered := secretbox.EnvelopeV1 + base64.StdEncoding.EncodeToString(raw)

	cases := map[string]string{
		// Главная причина версии в самом значении: до конверта секреты лежали
		// плейнтекстом, и «наверное, это и есть секрет» — та самая дыра.
		"legacy-плейнтекст без префикса": "просто-секрет-как-до-конверта",
		"legacy-base64 без префикса":     body,
		"пустая строка":                  "",
		"только префикс":                 secretbox.EnvelopeV1,
		"не base64 после префикса":       secretbox.EnvelopeV1 + "!!!не base64!!!",
		"короче nonce":                   secretbox.EnvelopeV1 + "AAAA",
		"испорченный тег":                tampered,
	}
	for name, enc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := b.Open(enc); !errors.Is(err, secretbox.ErrUndecryptable) {
				t.Fatalf("Open(%q) err = %v, want ErrUndecryptable", enc, err)
			}
		})
	}
}

// Метка разделяет назначения: утечка ключа MFA не должна открывать приватник SP
// и подпись webhook'а. Проверяется тем, что конверт одной метки не открывается другой.
func TestInfoSeparatesPurposes(t *testing.T) {
	enc, err := mustNew(t, []byte(root), "mfa-secret").Seal("s3cret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := mustNew(t, []byte(root), "siem-webhook-secret").Open(enc); !errors.Is(err, secretbox.ErrUndecryptable) {
		t.Fatalf("конверт открылся ключом ДРУГОГО назначения (err = %v)", err)
	}
}

// Смена JWT_SECRET делает старые записи нечитаемыми — это заявленная цена (Q-19),
// и она должна выглядеть как явная ошибка, а не как пустой секрет.
func TestRootRotationMakesUndecryptable(t *testing.T) {
	enc, err := mustNew(t, []byte(root), info).Seal("s3cret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := mustNew(t, []byte("другой-jwt-секрет-инсталляции"), info).Open(enc); !errors.Is(err, secretbox.ErrUndecryptable) {
		t.Fatalf("конверт открылся ПОСЛЕ смены корня (err = %v)", err)
	}
}

func TestNewRejectsEmptyArgs(t *testing.T) {
	cases := map[string]struct {
		root []byte
		info string
	}{
		"пустой корень":        {nil, info},
		"корень из пробелов":   {[]byte("   \t\n"), info},
		"пустая метка":         {[]byte(root), ""},
		"пустые оба аргумента": {nil, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := secretbox.New(c.root, c.info); err == nil {
				t.Fatal("New прошёл на пустом аргументе — ключ вывелся бы из ничего")
			}
		})
	}
}
