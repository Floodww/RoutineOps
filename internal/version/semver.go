// Package version — сравнение версий агента. Общий для агента и сервера ровно
// потому, что сравнивают они одно и то же число: агент решает, качать ли релиз,
// сервер — можно ли вообще ставить устройству задачу этого типа. Два парсера
// разъехались бы молча и в разные стороны.
package version

import (
	"fmt"
	"strconv"
	"strings"
)

// IsNewer возвращает true, если want строго новее have (semver MAJOR.MINOR.PATCH,
// необязательный префикс "v", pre-release/build-метаданные отбрасываются).
func IsNewer(have, want string) (bool, error) {
	h, err := parseSemver(have)
	if err != nil {
		return false, fmt.Errorf("текущая версия: %w", err)
	}
	w, err := parseSemver(want)
	if err != nil {
		return false, fmt.Errorf("предлагаемая версия: %w", err)
	}
	for i := 0; i < 3; i++ {
		if w[i] != h[i] {
			return w[i] > h[i], nil
		}
	}
	return false, nil
}

func parseSemver(s string) ([3]int, error) {
	var v [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	// Отбрасываем pre-release (-) и build (+) метаданные.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("ожидался MAJOR.MINOR.PATCH, got %q", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("некорректная компонента %q", p)
		}
		v[i] = n
	}
	return v, nil
}
