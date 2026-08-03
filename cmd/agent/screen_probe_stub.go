//go:build !enterprise

package main

import (
	"fmt"
	"io"
)

// Open-core-агент: удалённое подключение к рабочему столу — enterprise-фича (роадмап,
// Этап 2). Пакета screen в этой сборке нет вовсе, поэтому подкоманда отвечает внятным
// отказом, а не «unknown command»: разница между «команды не существует» и «фича не в
// этой редакции» — это разница между багрепортом и обращением в продажи.
func runScreenProbe(_, stderr io.Writer, _ []string) int {
	fmt.Fprintln(stderr, "screen-probe: enterprise feature not built")
	return 1
}

// runScreenWorker — то же самое для процесса захвата. Своими руками его не запускают: он
// поднимается службой в сессии пользователя, и без неё подключаться некуда.
func runScreenWorker(stderr io.Writer, _ []string) int {
	fmt.Fprintln(stderr, "screen-worker: enterprise feature not built")
	return 1
}
