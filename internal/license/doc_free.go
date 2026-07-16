//go:build !enterprise

// Open-core: enterprise-лицензирование отсутствует физически. Пакет пуст в free-сборке,
// чтобы `go build ./...` компилировался; реальная реализация — в license.go/argon2.go
// (//go:build enterprise). export-free оставляет только этот файл. Ungate-ить нечего:
// enterprise-фичи build-tag'ом вырезаны из open-core, лицензии тут нечего проверять.
package license
