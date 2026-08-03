package main

import (
	"strings"
	"testing"
)

func TestResolveFingerprint(t *testing.T) {
	const derived = "c084718664d4b118b29b739c01137ff0"

	// Флаг не задан — берём посчитанный, это штатный путь.
	got, err := resolveFingerprint("", derived, true)
	if err != nil || got != derived {
		t.Fatalf("без флага: got=%q err=%v", got, err)
	}

	// Совпадающий флаг допустим (привычка оператора), регистр не важен.
	if got, err := resolveFingerprint(strings.ToUpper(derived), derived, true); err != nil || got != derived {
		t.Errorf("совпадающий флаг: got=%q err=%v", got, err)
	}
	if got, err := resolveFingerprint("  "+derived+"  ", derived, true); err != nil || got != derived {
		t.Errorf("флаг с пробелами: got=%q err=%v", got, err)
	}

	// Опечатка — отказ. Именно она давала корректно подписанную запись с чужим
	// отпечатком: агент её отвергал и оставался на прежнем получателе, а публикация
	// выглядела успешной.
	_, err = resolveFingerprint("deadbeef", derived, true)
	if err == nil {
		t.Fatal("расхождение флага и посчитанного отпечатка принято")
	}
	if !strings.Contains(err.Error(), derived) {
		t.Errorf("в ошибке нет правильного отпечатка: %v", err)
	}

	// Сборка без тега считать не умеет — публиковать «на слово» запрещено.
	if _, err := resolveFingerprint(derived, "", false); err == nil {
		t.Error("публикация без проверки отпечатка разрешена")
	}
}
