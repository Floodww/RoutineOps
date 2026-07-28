package uninstall

import "strings"

// Валидаторы значений, которые уезжают в argv деинсталлятора. Живут БЕЗ
// build-тега специально: это чистые строковые проверки без платформенных
// зависимостей, а гоняться они обязаны на каждом прогоне тестов, а не только на
// той ОС, к которой относятся. Иначе проверка, стоящая последней перед запуском
// msiexec на Windows, испытывалась бы ровно там, где тесты запускают реже всего.

// looksLikeProductCode — форма {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}.
// Проверка независима от одноимённой в коллекторе ОСОЗНАННО: это последний
// рубеж перед передачей строки в msiexec, и он не должен зависеть от
// корректности другого пакета — ошибка в общем хелпере разоружила бы обе
// проверки разом.
func looksLikeProductCode(s string) bool {
	const n = 38 // 36 символов GUID + две фигурные скобки
	if len(s) != n || s[0] != '{' || s[n-1] != '}' {
		return false
	}
	for i := 0; i < len(s)-2; i++ {
		c := s[i+1]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHexDigit(c) {
				return false
			}
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// validRegistryKeyName — имя подключа ARP, которое агент собирается открыть.
// Разделители пути означали бы выход в произвольную ветку реестра: имя приезжает
// из инвентаря, но инвентарь на сервере мог быть отредактирован, а ключ
// подставляется в путь конкатенацией.
func validRegistryKeyName(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && !strings.ContainsAny(s, `\/`)
}

// validPackageName пропускает знаки, реально встречающиеся в именах пакетов
// Debian/RPM/Arch/Alpine. Первый символ — буква или цифра, чтобы имя не могло
// быть прочитано пакетным менеджером как опция (`-y`, `--assume-yes`), а
// спецификаторы версии (`имя>=1.2`) и подстановки не проходили вовсе.
func validPackageName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case (c == '.' || c == '+' || c == '-' || c == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}
