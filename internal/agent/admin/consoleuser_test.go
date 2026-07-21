package admin

import "testing"

// Сценарий транзиентного сбоя пробы: last-known-значение НЕ затирается (сервер
// записал бы "" как факт «за консолью никого»), а настоящий логаут — успешная
// проба с пустым результатом — по-прежнему чистит поле. Шаги зависимы по
// состоянию кэша, поэтому прогоняются последовательно, не как подтесты.
func TestConsoleUserCached(t *testing.T) {
	consoleUserMu.Lock()
	lastConsoleUser = ""
	consoleUserMu.Unlock()

	steps := []struct {
		name string
		val  string
		ok   bool
		want string
	}{
		{"успешная проба сохраняет значение", `CORP\alice`, true, `CORP\alice`},
		{"сбой пробы отдаёт last-known, не пустоту", "", false, `CORP\alice`},
		{"логаут (успешная проба, никого) чистит поле", "", true, ""},
		{"сбой после логаута оставляет пустоту", "", false, ""},
		{"новый логин перезаписывает", "bob", true, "bob"},
	}
	for _, s := range steps {
		if got := consoleUserCached(func() (string, bool) { return s.val, s.ok }); got != s.want {
			t.Errorf("%s: consoleUserCached = %q, want %q", s.name, got, s.want)
		}
	}
}
