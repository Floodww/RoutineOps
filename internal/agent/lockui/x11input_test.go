package lockui

import "testing"

func TestDecodeKeysym(t *testing.T) {
	cases := []struct {
		name string
		ks   uint32
		want KeyAction
		char rune
	}{
		{"латиница", 0x0061, KeyChar, 'a'},                    // XK_a
		{"цифра", 0x0035, KeyChar, '5'},                       // XK_5
		{"пробел", 0x0020, KeyChar, ' '},                      // XK_space
		{"латиница-1 умляут", 0x00fc, KeyChar, 'ü'},           // XK_udiaeresis
		{"кириллица через Unicode", 0x01000439, KeyChar, 'й'}, // U+0439
		{"Return", 0xff0d, KeySubmit, 0},
		{"KP_Enter", 0xff8d, KeySubmit, 0},
		{"BackSpace", 0xff08, KeyErase, 0},
		{"Delete", 0xffff, KeyErase, 0},
		{"Shift_L не символ", 0xffe1, KeyIgnore, 0},
		{"F1 не символ", 0xffbe, KeyIgnore, 0},
		{"Caps_Lock не символ", 0xffe5, KeyIgnore, 0},
		{"NoSymbol", 0x0000, KeyIgnore, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			act, r := DecodeKeysym(c.ks)
			if act != c.want {
				t.Fatalf("действие = %v, want %v", act, c.want)
			}
			if act == KeyChar && r != c.char {
				t.Fatalf("символ = %q, want %q", r, c.char)
			}
		})
	}
}

// Модификаторы и функциональные клавиши НЕ должны попадать в пароль: они лежат в том
// же диапазоне 0xff00-0xffff, что Return и BackSpace, и наивная проверка «меньше
// 0xff00 — значит символ» дописывала бы по символу на каждый Shift.
func TestDecodeKeysym_ФункциональныйДиапазонНеПечатает(t *testing.T) {
	for ks := uint32(0xff00); ks <= 0xffff; ks++ {
		act, _ := DecodeKeysym(ks)
		switch ks {
		case keysymReturn, keysymKPEnter, keysymBackSpace, keysymDelete:
			continue // обрабатываются отдельно
		}
		if act == KeyChar {
			t.Fatalf("keysym %#x распознан как печатный символ", ks)
		}
	}
}

func TestMaskPassword(t *testing.T) {
	if got := MaskPassword(0); got != "" {
		t.Fatalf("пустой пароль = %q", got)
	}
	if got := MaskPassword(3); got != "•••" {
		t.Fatalf("маска = %q", got)
	}
	if got := []rune(MaskPassword(5)); len(got) != 5 {
		t.Fatalf("длина маски = %d, want 5", len(got))
	}
}
