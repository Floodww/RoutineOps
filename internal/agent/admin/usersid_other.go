//go:build !windows

package admin

// osUserSID: стабильный идентификатор учётки есть только на Windows (SID).
// На macOS/Linux (и прочих юниксах) привязка user↔каталог идёт серверным
// резолвом логина или вручную — отдаём «неизвестно». Тег !windows покрывает
// все не-Windows платформы разом, в отличие от priv_other.go (там свой слой
// на каждую ОС).
func osUserSID(string) string { return "" }
