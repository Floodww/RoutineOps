package collector

import (
	"net"
	"testing"
)

func TestNormalizeOS(t *testing.T) {
	cases := map[string]string{
		"darwin":  "macOS",
		"windows": "Windows",
		"linux":   "linux",
	}
	for in, want := range cases {
		if got := normalizeOS(in); got != want {
			t.Errorf("normalizeOS(%q)=%q want %q", in, got, want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{
		0:          "0 B",
		500:        "500 B",
		1024:       "1 KB",
		1048576:    "1 MB",
		1073741824: "1 GB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d)=%q want %q", in, got, want)
		}
	}
}

func TestHumanBytesBucketed(t *testing.T) {
	const gib = uint64(1024 * 1024 * 1024)
	cases := map[uint64]string{
		0:             "0 B",
		512 * 1024:    "512 KB", // меньше корзины — как есть
		5 * gib:       "5 GB",   // меньше корзины — как есть
		230*gib + 900: "230 GB", // дрейф внутри корзины не меняет строку...
		237 * gib:     "230 GB",
		241 * gib:     "240 GB", // ...а переход через границу корзины — меняет
	}
	for in, want := range cases {
		if got := humanBytesBucketed(in); got != want {
			t.Errorf("humanBytesBucketed(%d)=%q want %q", in, got, want)
		}
	}
}

func TestLocalIPValid(t *testing.T) {
	ip := LocalIP()
	if ip == "" {
		t.Skip("нет не-loopback IPv4 в этом окружении")
	}
	if net.ParseIP(ip) == nil {
		t.Errorf("LocalIP()=%q — не валидный IP", ip)
	}
}

func TestSelectNetwork(t *testing.T) {
	ip := func(s string) net.IP { return net.ParseIP(s) }
	cases := []struct {
		name         string
		in           []netEntry
		wantIP, wMAC string
	}{
		{"link-local без MAC пропускается, берём реальный",
			[]netEntry{{ip("169.254.83.107"), ""}, {ip("192.168.1.10"), "aa:bb:cc:dd:ee:ff"}},
			"192.168.1.10", "aa:bb:cc:dd:ee:ff"},
		{"реальный MAC приоритетнее, даже если идёт позже виртуального без MAC",
			[]netEntry{{ip("172.20.0.1"), ""}, {ip("203.0.113.5"), "11:22:33:44:55:66"}},
			"203.0.113.5", "11:22:33:44:55:66"},
		{"нет MAC ни у кого — первый не-link-local IP как фолбэк",
			[]netEntry{{ip("169.254.1.1"), ""}, {ip("192.168.0.2"), ""}},
			"192.168.0.2", ""},
		{"только loopback и link-local — пусто",
			[]netEntry{{ip("127.0.0.1"), ""}, {ip("169.254.9.9"), ""}},
			"", ""},
	}
	for _, c := range cases {
		gotIP, gotMAC := selectNetwork(c.in)
		if gotIP != c.wantIP || gotMAC != c.wMAC {
			t.Errorf("%s: got (%q,%q), want (%q,%q)", c.name, gotIP, gotMAC, c.wantIP, c.wMAC)
		}
	}
}
