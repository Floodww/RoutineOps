package version

import "testing"

func TestIsNewer(t *testing.T) {
	cases := []struct {
		have, want string
		newer      bool
	}{
		{"v1.0.0", "v1.0.1", true},
		{"v1.0.0", "v1.1.0", true},
		{"v1.0.0", "v2.0.0", true},
		{"1.2.3", "1.2.3", false},
		{"v1.2.3", "v1.2.2", false},
		{"v2.0.0", "v1.9.9", false},
		{"v1.0.1", "v1.0.1-rc1", false}, // метаданные отброшены → 1.0.1 == 1.0.1, не новее
		{"v1.0.0", "v1.0.1-rc1", true},  // 1.0.0 < 1.0.1
	}
	for _, c := range cases {
		got, err := IsNewer(c.have, c.want)
		if err != nil {
			t.Fatalf("IsNewer(%q,%q): %v", c.have, c.want, err)
		}
		if got != c.newer {
			t.Errorf("IsNewer(%q,%q)=%v, want %v", c.have, c.want, got, c.newer)
		}
	}
	if _, err := IsNewer("dev", "v1.0.0"); err == nil {
		t.Error("ожидали ошибку на непарсибельной текущей версии")
	}
}
