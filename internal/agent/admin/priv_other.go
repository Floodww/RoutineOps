//go:build !darwin && !windows && !linux

package admin

import "errors"

// Прочие unix (freebsd и др.) — не целевые платформы; права не применяем.
// Linux живёт в priv_linux.go и поддержан полноценно.

type osPriv struct{}

func newOSPrivilegeManager() PrivilegeManager { return osPriv{} }

func (osPriv) Grant(string) error {
	return errors.New("admin privileges не поддерживаются на этой ОС")
}
func (osPriv) Revoke(string) error {
	return errors.New("admin privileges не поддерживаются на этой ОС")
}
func (osPriv) IsAdmin(string) (bool, error) { return false, nil }

func osConsoleUser() string { return "" }

// osConsoleUserFull: консольного пользователя тут не собираем; проба «успешна»
// тривиально, чтобы ConsoleUser не залипал на last-known-значении.
func osConsoleUserFull() (string, bool) { return "", true }
