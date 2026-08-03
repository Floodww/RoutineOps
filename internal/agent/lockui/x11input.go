// Разбор ввода и выбор графического бэкенда для замка блокировки — чистые функции
// без X11 и без синтаксиса, зависящего от ОС. Вынесены из lockui_linux.go намеренно:
// протокольную часть без X-сервера не проверить, а именно эти таблицы и решения
// ошибиться легче всего, поэтому они обязаны тестироваться на любой машине.
package lockui

// Keysym'ы X11, которые обрабатывает замок. Полной таблицы не держим: замку нужны
// ввод пароля, подтверждение и стирание — остальное игнорируется, чтобы случайная
// клавиша не «проваливалась» в систему.
const (
	keysymBackSpace = 0xff08
	keysymReturn    = 0xff0d
	keysymKPEnter   = 0xff8d
	keysymDelete    = 0xffff

	// Диапазон Latin-1: keysym численно равен коду символа (X11 spec, Appendix A).
	keysymLatin1Lo = 0x20
	keysymLatin1Hi = 0xff

	// Unicode-keysym'ы: 0x01000000 | codepoint (соглашение X11 для всего, что вне
	// Latin-1). Кириллическая раскладка в современных драйверах приезжает именно так.
	keysymUnicodeFlag = 0x01000000
	keysymUnicodeMax  = 0x0110ffff
)

// KeyAction — что замок делает с нажатием.
type KeyAction int

const (
	KeyIgnore KeyAction = iota // клавиша замку не интересна (модификаторы, F1…)
	KeyChar                    // печатный символ — дописать в пароль
	KeyErase                   // стереть последний символ
	KeySubmit                  // отправить пароль на проверку
)

// DecodeKeysym переводит keysym в действие замка. Второе значение осмысленно только
// при KeyChar.
//
// Почему не «всё, что не спец-клавиша, — символ»: keysym'ы модификаторов и функциональных
// клавиш лежат в 0xff00-0xffff вперемешку с BackSpace/Return, и наивная проверка
// «ks < 0xff00 → символ» дописывала бы в пароль мусор при каждом Shift.
func DecodeKeysym(ks uint32) (KeyAction, rune) {
	switch ks {
	case keysymReturn, keysymKPEnter:
		return KeySubmit, 0
	case keysymBackSpace, keysymDelete:
		return KeyErase, 0
	}
	if ks >= keysymLatin1Lo && ks <= keysymLatin1Hi {
		return KeyChar, rune(ks)
	}
	if ks > keysymUnicodeFlag && ks <= keysymUnicodeMax {
		return KeyChar, rune(ks &^ keysymUnicodeFlag)
	}
	return KeyIgnore, 0
}

// MaskPassword — то, что рисуется вместо пароля. Длина видна намеренно: без неё
// сотрудник не понимает, дошло ли нажатие, и лупит по клавишам вслепую.
func MaskPassword(n int) string {
	const bullet = '•'
	out := make([]rune, n)
	for i := range out {
		out[i] = bullet
	}
	return string(out)
}
