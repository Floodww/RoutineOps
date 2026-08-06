//go:build linux

package x11ui

import (
	"fmt"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/xproto"
)

// Раскладка X-сервера: перевод кода клавиши в keysym.
//
// В X11 событие несёт КОД клавиши (позицию на клавиатуре), а не символ. Сравнивать код с
// числом нельзя: у Enter он разный на разных серверах и раскладках, и «диалог не
// принимает Enter» на чужой машине выглядел бы как зависший диалог.

// Keysym'ы, которые нам нужны по именам, а не по номерам (X11 keysymdef.h).
const (
	KeyReturn  = 0xff0d
	KeyKPEnter = 0xff8d
	KeyEscape  = 0xff1b
)

// Keyboard — снимок раскладки на момент открытия окна.
type Keyboard struct {
	keysyms []xproto.Keysym
	min     xproto.Keycode
	per     byte
}

// NewKeyboard читает таблицу раскладки у сервера.
func NewKeyboard(conn *xgb.Conn) (Keyboard, error) {
	setup := xproto.Setup(conn)
	count := byte(setup.MaxKeycode - setup.MinKeycode + 1)
	km, err := xproto.GetKeyboardMapping(conn, setup.MinKeycode, count).Reply()
	if err != nil {
		return Keyboard{}, fmt.Errorf("x11: таблица раскладки: %w", err)
	}
	return Keyboard{keysyms: km.Keysyms, min: setup.MinKeycode, per: km.KeysymsPerKeycode}, nil
}

// Keysym переводит код клавиши в keysym указанного столбца раскладки. Столбец 0 —
// обычное нажатие, 1 — с Shift; групповые раскладки (столбцы 2-3) сознательно не
// трогаем, чтобы не гадать о состоянии группы.
func (k Keyboard) Keysym(code xproto.Keycode, column int) uint32 {
	if len(k.keysyms) == 0 || k.per == 0 {
		return 0
	}
	idx := int(code-k.min)*int(k.per) + column
	if idx < 0 || idx >= len(k.keysyms) {
		return 0
	}
	return uint32(k.keysyms[idx])
}
