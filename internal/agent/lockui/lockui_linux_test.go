//go:build linux

package lockui

import "testing"

// Проверки подбора шрифта и двухбайтовой кодировки переехали в internal/agent/x11ui
// вместе с самим кодом: ту же задачу решает плашка наблюдения за экраном, и две копии
// расходятся молча. Здесь остаётся то, что специфично именно для замка.

func TestReasonText_ЛатинскийЗапасной(t *testing.T) {
	if got := reasonText(""); got != defaultReason {
		t.Errorf("пустая причина должна давать текст по умолчанию, получили %+v", got)
	}
	// У причины с сервера латинского перевода нет: в fallback-режиме показываем общий
	// текст, а не строку из «?».
	ru := reasonText("Утечка данных")
	if ru.ru != "Утечка данных" || ru.en != defaultReason.en {
		t.Errorf("кириллическая причина: %+v", ru)
	}
	// Латинская причина понятна в обоих режимах — оставляем как есть.
	en := reasonText("Security incident")
	if en.ru != "Security incident" || en.en != "Security incident" {
		t.Errorf("латинская причина: %+v", en)
	}
}
