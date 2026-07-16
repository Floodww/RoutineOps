//go:build !enterprise

// Open-core: вендор-тулинг лицензий отсутствует. Стаб, чтобы `go build ./...` без
// -tags enterprise компилировался; export-free оставляет только этот файл. Реальный
// CLI — main.go (//go:build enterprise), собирается вендором.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "routineops-license доступен только в enterprise-сборке (go build -tags enterprise ./cmd/routineops-license)")
	os.Exit(2)
}
