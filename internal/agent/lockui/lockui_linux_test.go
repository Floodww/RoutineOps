//go:build linux

package lockui

import (
	"testing"

	"github.com/jezek/xgb/xproto"
)

// fontReply собирает ответ QueryFont для двухбайтового шрифта, у которого есть глифы
// только для перечисленных кодовых точек. Остальные ячейки — пустой Charinfo, ровно
// как их отдаёт X-сервер для отсутствующих символов.
func fontReply(t *testing.T, min, max rune, present ...rune) *xproto.QueryFontReply {
	t.Helper()
	qf := &xproto.QueryFontReply{
		MinByte1:       byte(min >> 8),
		MaxByte1:       byte(max >> 8),
		MinCharOrByte2: uint16(byte(min)),
		MaxCharOrByte2: uint16(byte(max)),
	}
	rowLen := int(qf.MaxCharOrByte2-qf.MinCharOrByte2) + 1
	rows := int(qf.MaxByte1-qf.MinByte1) + 1
	qf.CharInfos = make([]xproto.Charinfo, rows*rowLen)
	for _, r := range present {
		idx := (int(byte(r>>8))-int(qf.MinByte1))*rowLen + (int(byte(r)) - int(qf.MinCharOrByte2))
		qf.CharInfos[idx] = xproto.Charinfo{CharacterWidth: 7, Ascent: 10, Descent: 2}
	}
	return qf
}

func TestGlyphExists(t *testing.T) {
	// Диапазон покрывает и латиницу, и кириллицу, но реальные глифы — только у 'A':
	// это в точности случай шрифтов из наборов 100dpi, на которых заголовок замка
	// вышел рядом пустых квадратов при ненулевой измеренной ширине.
	qf := fontReply(t, 0x0000, 0x04ff, 'A')

	if !glyphExists(qf, 'A') {
		t.Error("латинская A объявлена отсутствующей, хотя глиф есть")
	}
	if glyphExists(qf, 'У') {
		t.Error("кириллическая У признана существующей — именно так и появлялись квадраты")
	}
}

func TestGlyphExists_ВнеДиапазонаШрифта(t *testing.T) {
	qf := fontReply(t, 0x0000, 0x00ff, 'A') // только латиница-1
	if glyphExists(qf, 'У') {
		t.Error("символ вне диапазона шрифта признан существующим")
	}
	if glyphExists(qf, 0x1F600) {
		t.Error("символ вне BMP не может существовать в двухбайтовом шрифте")
	}
}

// AllCharsExist — ответ сервера «в объявленном диапазоне есть всё»; таблица метрик
// при этом может не приезжать вовсе, и отсутствие CharInfos не повод считать шрифт
// пустым (иначе замок отверг бы исправные шрифты и ушёл на латиницу).
func TestGlyphExists_AllCharsExist(t *testing.T) {
	qf := &xproto.QueryFontReply{
		MinByte1: 0x00, MaxByte1: 0x04,
		MinCharOrByte2: 0x00, MaxCharOrByte2: 0xff,
		AllCharsExist: true,
	}
	if !glyphExists(qf, 'У') {
		t.Error("при AllCharsExist символ из диапазона обязан считаться существующим")
	}
	if glyphExists(qf, 0x9999) {
		t.Error("символ вне диапазона не спасает даже AllCharsExist")
	}
}

func TestToChar2b(t *testing.T) {
	got := toChar2b("Aй")
	want := []xproto.Char2b{{Byte1: 0x00, Byte2: 'A'}, {Byte1: 0x04, Byte2: 0x39}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("char2b = %+v, want %+v", got, want)
	}
	// Вне BMP двухбайтовой кодировки не существует — подставляем «?», а не мусор.
	if q := toChar2b("😀"); len(q) != 1 || q[0] != (xproto.Char2b{Byte1: 0, Byte2: '?'}) {
		t.Fatalf("символ вне BMP = %+v, want '?'", q)
	}
}

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
