//go:build !windows && !darwin && !linux

package collector

// Платформа без поддерживаемого механизма служб. Отдаём именно Unsupported, а не
// Failed: «мы не умеем смотреть здесь» и «мы посмотрели и сломались» для аудита
// сессии разные ответы — первый не должен выглядеть как утраченные улики.
func osServices() ([]Service, Health) { return nil, HealthUnsupported }
