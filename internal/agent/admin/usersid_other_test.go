//go:build !windows

package admin

import "testing"

// Контракт хендоффа LDAP Phase 1: вне Windows console_user_sid всегда пуст —
// сервер по "" деградирует на резолв логина/ручную привязку. Стаб тривиален,
// но контракт серверный: регрессия (непустой возврат) прошла бы все остальные
// тесты молча — инжектированный sidOf в TestConsoleIdentityCached стаб не
// трогает.
func TestOSUserSID_AlwaysEmptyOffWindows(t *testing.T) {
	for _, in := range []string{"", "alice", `CORP\alice`, "root"} {
		if got := osUserSID(in); got != "" {
			t.Errorf("osUserSID(%q) = %q, want «» вне Windows", in, got)
		}
	}
}
