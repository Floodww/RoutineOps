//go:build !windows

package inventory

import "testing"

// Замок на два контракта разом (вне Windows):
//  1. платформенный — console_user_sid пуст, SID есть только на Windows
//     (сервер по "" деградирует на резолв логина);
//  2. проводка build(): ConsoleUser и ConsoleUserSid — два соседних строковых
//     присваивания из одной пары, их своп прошёл бы рефлексионный хэш-тест
//     молча. При свопе на машине с живым консольным пользователем логин уехал
//     бы в SID-поле — здесь это ловится: SID обязан быть пуст НЕЗАВИСИМО от
//     того, нашёлся ли консольный пользователь.
func TestBuild_ConsoleUserSIDEmptyOffWindows(t *testing.T) {
	di := build("1.2.3").GetDeviceInfo()
	if got := di.GetConsoleUserSid(); got != "" {
		t.Errorf("console_user_sid = %q вне Windows, want «» (console_user = %q — своп полей?)",
			got, di.GetConsoleUser())
	}
}
