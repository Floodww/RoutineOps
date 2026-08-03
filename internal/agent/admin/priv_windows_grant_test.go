//go:build windows

package admin

import (
	"errors"
	"fmt"
	"testing"
)

// Распознавание «пользователь уже в группе» по реальному выводу `net`.
//
// Строки не выдуманы: английская — стандартный вывод net localgroup /add,
// русская снята с живой Windows этого билд-бокса (`net helpmsg 1378`,
// локаль ru-RU). Прежний вариант «уже является членом» не встречается ни в
// одной локали — тест на нём и падал бы.
func TestIsAlreadyLocalGroupMember(t *testing.T) {
	wrap := func(out string) error {
		// Формат ровно как у runNet: обёртка + вывод команды в скобках.
		return fmt.Errorf("net localgroup Администраторы user /add: %w (%s)",
			errors.New("exit status 2"), out)
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"английская Windows", wrap("System error 1378 has occurred.\n\nThe specified account name is already a member of the group."), true},
		{"русская Windows", wrap("Системная ошибка 1378.\n\nУказанная учетная запись уже входит в эту группу."), true},
		{"локаль без номера в выводе", wrap("The specified account name is already a member of the group."), true},
		{"русский текст без номера", wrap("Указанная учетная запись уже входит в эту группу."), true},
		// Отказ в правах обязан остаться отказом: посчитать его успехом значит
		// отрапортовать серверу выданный грант, которого на машине нет.
		{"отказано в доступе", wrap("System error 5 has occurred.\n\nAccess is denied."), false},
		{"группа не существует", wrap("Системная ошибка 1376."), false},
		{"нет ошибки", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAlreadyLocalGroupMember(tc.err); got != tc.want {
				t.Fatalf("isAlreadyLocalGroupMember = %v, ожидали %v (%v)", got, tc.want, tc.err)
			}
		})
	}
}
