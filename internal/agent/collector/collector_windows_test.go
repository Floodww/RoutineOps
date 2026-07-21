//go:build windows

package collector

import "testing"

func TestParseBool3(t *testing.T) {
	cases := []struct{ in, want string }{
		{"True\r\n", "true"},
		{"False", "false"},
		{" true ", "true"},
		{"", ""},
		{"Access denied", ""}, // текст ошибки — «не знаю», не выдуманный false
	}
	for _, c := range cases {
		if got := parseBool3(c.in); got != c.want {
			t.Errorf("parseBool3(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
