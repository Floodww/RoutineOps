//go:build windows

package service

import "path/filepath"

// InstallLayout — Windows. Бинарь и серты кладёт MSI (Relocate=false — перекладка
// из кода сломала бы рабочий MSI-поток), но изменяемое состояние службы обязано
// жить в машинном каталоге данных, а не в CWD службы (C:\Windows\System32, куда
// оно уезжало при относительных дефолтах путей).
//
// DataDir — ЗАЩИЩЁННЫЙ подкаталог state, а не корень ProgramData\RoutineOps:
// корень намеренно user-writable (lock.json/status.json/admin-request.json пишут
// и процессы юзер-сессии — лок-экран и трей, см. lock.EnsureUserWritableDir), и
// класть туда forbidden-list/outbox/seen нельзя — непривилегированный пользователь
// мог бы подменить политику ИБ и заглушить алерты на своей машине. DACL подкаталога
// ставит EnsureDataDir (SYSTEM/Администраторы, protected — наследование от
// user-writable корня разорвано).
func InstallLayout() Layout {
	return Layout{
		Relocate: false,
		DataDir:  filepath.Join(ProgramDataDir(), "RoutineOps", "state"),
	}
}
