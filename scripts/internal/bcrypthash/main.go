// Печатает bcrypt-хеш пароля. Нужен стенду экрана блокировки
// (scripts/test-lock-linux.sh): состояние замка хранит только хеш, а стенду нужно
// подготовить «заблокированное» устройство и знать пароль, которым оно отпирается.
// Отдельной утилитой, чтобы в репозитории не лежал вкомпилированный тестовый хеш,
// который со стороны неотличим от настоящего секрета.
package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "использование: bcrypthash <пароль>")
		os.Exit(2)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(os.Args[1]), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bcrypt:", err)
		os.Exit(1)
	}
	fmt.Print(string(h))
}
