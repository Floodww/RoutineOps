//go:build !enterprise

package main

import (
	"fmt"
	"os"
)

// routineops-unseal — офлайн enterprise-инструмент (в open-core недоступен).
// Open-core-сборка даёт заглушку, чтобы `go build ./...` был зелёным.
func main() {
	fmt.Fprintln(os.Stderr, "routineops-unseal — enterprise-инструмент; соберите с -tags enterprise")
	os.Exit(1)
}
