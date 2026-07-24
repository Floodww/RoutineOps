//go:build windows

package admin

import (
	"os/user"
	"testing"

	"golang.org/x/sys/windows"
)

// Живая граница LSA (LookupAccountName), не мок: SID, отрезолвленный по имени
// текущего пользователя процесса, обязан совпасть с SID из его же токена —
// независимый источник истины. Ровно тот путь, которым инвентарь дерифит
// console_user_sid из console_user (форма DOMAIN\user).
func TestOSUserSID_MatchesProcessToken(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	got := osUserSID(me.Username)
	if got == "" {
		t.Fatalf("osUserSID(%q) = «неизвестно» для заведомо существующей учётки", me.Username)
	}
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	if want := tu.User.Sid.String(); got != want {
		t.Fatalf("osUserSID(%q) = %s, токен процесса говорит %s", me.Username, got, want)
	}
}

// Гейт по типу учётки: группа (локализованное имя встроенных администраторов —
// SidTypeAlias) и несуществующее имя обязаны давать «неизвестно», а не SID
// не-пользователя.
func TestOSUserSID_NonUserAccounts(t *testing.T) {
	group, err := adminGroupName()
	if err != nil {
		t.Fatalf("adminGroupName: %v", err)
	}
	if got := osUserSID(group); got != "" {
		t.Errorf("osUserSID(группа %q) = %q, want «» — алиас не пользователь", group, got)
	}
	if got := osUserSID(`NO-SUCH-DOMAIN\no-such-user-2f91`); got != "" {
		t.Errorf("osUserSID(несуществующая учётка) = %q, want «»", got)
	}
	if got := osUserSID(""); got != "" {
		t.Errorf("osUserSID(«») = %q, want «»", got)
	}
}
