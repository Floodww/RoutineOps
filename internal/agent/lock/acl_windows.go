//go:build windows

package lock

import "github.com/Floodww/RoutineOps/internal/agent/service"

// EnsureUserWritableDir делает общий каталог состояния (ProgramData\RoutineOps)
// доступным юзер-сессии на файловые операции. Реализация — в
// service.EnsureUserWritableDir, рядом с EnsureDataDir: у них общий
// no-follow/owner/DACL-инструментарий, а прежняя локальная версия здесь ставила
// цельный BU-Modify (включая DELETE на сам каталог) path-based вызовом — обе
// дыры закрыты там (разнесённые ACE + владелец + хэндл, ревью #7 п. 2.2).
// Обёртка сохраняет call-site в cmd/agent и симметрию с acl_other.go.
func EnsureUserWritableDir(dir string) error {
	return service.EnsureUserWritableDir(dir)
}
