package admin

import "testing"

// Сценарий транзиентного сбоя пробы: last-known-ПАРА (логин, SID) не затирается
// (сервер записал бы "" как факт «за консолью никого»), а настоящий логаут —
// успешная проба с пустым результатом — чистит оба поля. SID дерифится строго
// от доложенного логина и только при успешной пробе. Шаги зависимы по
// состоянию кэша, поэтому прогоняются последовательно, не как подтесты.
func TestConsoleIdentityCached(t *testing.T) {
	consoleUserMu.Lock()
	lastConsoleUser, lastConsoleSID = "", ""
	consoleUserMu.Unlock()

	sids := map[string]string{
		`CORP\alice`: "S-1-5-21-1-1-1-1001",
		// bob отсутствует: резолв SID отказал — уходит best-effort ("").
	}
	sidCalls := 0
	sidOf := func(u string) string { sidCalls++; return sids[u] }

	steps := []struct {
		name     string
		val      string
		ok       bool
		wantU    string
		wantSID  string
		wantCall bool // ожидается ли вызов sidOf на этом шаге
	}{
		{"успешная проба сохраняет пару", `CORP\alice`, true, `CORP\alice`, "S-1-5-21-1-1-1-1001", true},
		{"сбой пробы отдаёт last-known-пару, sidOf не зовётся", "", false, `CORP\alice`, "S-1-5-21-1-1-1-1001", false},
		// Мотивирующий сценарий всей пары (fast user switching): живой свитч
		// A→B без логаута между ними, у B резолв SID отказал. SID обязан
		// СЛЕДОВАТЬ за логином — (bob, ""), а не отстать как (bob, SID Алисы).
		{"прямой свитч на другого юзера: SID не отстаёт от логина", "bob", true, "bob", "", true},
		{"сбой после свитча отдаёт пару свитча целиком", "", false, "bob", "", false},
		{"логаут (успешная проба, никого) чистит оба поля", "", true, "", "", false},
		{"сбой после логаута оставляет пустую пару", "", false, "", "", false},
		{"возврат юзера восстанавливает пару резолвом заново", `CORP\alice`, true, `CORP\alice`, "S-1-5-21-1-1-1-1001", true},
	}
	for _, s := range steps {
		before := sidCalls
		u, sid := consoleIdentityCached(func() (string, bool) { return s.val, s.ok }, sidOf)
		if u != s.wantU || sid != s.wantSID {
			t.Errorf("%s: consoleIdentityCached = (%q, %q), want (%q, %q)", s.name, u, sid, s.wantU, s.wantSID)
		}
		if called := sidCalls > before; called != s.wantCall {
			t.Errorf("%s: вызов sidOf = %v, want %v", s.name, called, s.wantCall)
		}
	}
}
