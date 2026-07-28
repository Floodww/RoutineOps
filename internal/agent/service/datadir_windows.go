//go:build windows

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/windows"
)

// dataDirSDDL — DACL каталога состояния службы: полный доступ ТОЛЬКО SYSTEM и
// Администраторам, обычным пользователям — ничего (в outbox лежат результаты
// admin-скриптов и security-события, читать их с машины сотрудника не нужно, а
// запись дала бы подмену forbidden-list). OICI — наследуется на файлы и
// подкаталоги: НОВЫЕ объекты внутри state (каталог outbox, перенесённые
// миграцией файлы) получают тот же admin-only ACL.
const dataDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// childDirSDDL — DACL, который ставится уже существовавшим детям state.
//
// Тот же admin-only, что и на самом state, и ЯВНЫМИ ACE — не пустым DACL в
// расчёте на наследование. Прежняя реализация ставила детям `"D:"` (пустой DACL)
// с флагом UNPROTECTED_DACL_SECURITY_INFORMATION, рассчитывая, что система
// подтянет унаследованные ACE от защищённого родителя. На деле это давало
// каталогу пустой И protected DACL — доступ запрещён ВСЕМ, включая SYSTEM, а
// P отрезает наследование, так что само не чинится.
//
// Полевое следствие (2.5.1, полевая Windows-машина): после ПЕРВОГО же рестарта службы
// (на свежей установке outbox ещё не существует, на втором старте — уже да)
// C:\ProgramData\RoutineOps\state\outbox получал O:BA D:P, и служба под SYSTEM
// теряла и запись, и чтение собственной очереди. Молча для сервера: outbox и
// есть канал доставки, поэтому умирали разом отчёты задач, security-события и
// статусы лока, а снаружи это выглядело только залипшим статусом в панели.
//
// Механизм проверен на Windows-боксе, а не выведен из документации:
//   - SecurityDescriptorFromString("D:") даёт DACL PRESENT с нулём ACE
//     (не NULL-DACL) — то есть «запрещено всем», а не «доступ по умолчанию»;
//   - SetSecurityInfo по ХЭНДЛУ (SE_KERNEL_OBJECT) наследование от родителя не
//     пересчитывает и отдаёт объекту ровно этот пустой DACL, выставляя при этом
//     protected. Тот же вызов через SetNamedSecurityInfo (path-based) наследование
//     подтягивает — но path-based API мы здесь не используем осознанно: он молча
//     проходит сквозь подсунутый junction, ради чего вся эта функция и открывает
//     объекты no-follow по хэндлу.
//
// Явные ACE снимают зависимость от семантики наследования целиком: результат
// один и тот же независимо от того, что унаследовалось бы от родителя. Проверено
// под NT AUTHORITY\SYSTEM: со старым DACL — Access denied на чтение и запись,
// с этим — обе операции проходят.
const childDirSDDL = dataDirSDDL

// userWritableDirSDDL — PROTECTED DACL общего каталога ProgramData\RoutineOps
// (lock.json, status.json, unlock-request-*; пишут и служба, и юзер-сессия).
// ACE для BU (Пользователи) разнесены (ревью #7, п. 2.2):
//   - на САМ каталог — только 0x1200ab (list + traverse + add-file + чтение
//     атрибутов/EA): БЕЗ DELETE, БЕЗ FILE_ADD_SUBDIRECTORY и БЕЗ
//     FILE_DELETE_CHILD;
//   - Modify (0x1301bf, включая DELETE) — inherit-only на детей (OICIIO).
//
// Прежний единый (A;OICI;0x1301bf;;;BU) давал BU DELETE на сам каталог, а
// DELETE + дефолтное право Users создавать каталоги в ProgramData = при
// остановленной службе обычный пользователь переименовывал ВЕСЬ RoutineOps и
// подкладывал свой каталог с поддельными state\lock.last_unlocked и lock.json:
// EnsureDataDir на старте возвращал ACL, но не инвалидировал содержимое —
// пере-запирание подавлялось. Файловые операции юзер-сессии живы: создание
// файла — add-file на каталоге, замена/удаление файлов (включая rename поверх
// lock.json) — унаследованный Modify с DELETE на самих файлах.
// P (protected): наследование от ProgramData отрезано, иначе поверх явных ACE
// доезжали бы дефолтные ACE корня (Users add-subdirectory, CREATOR OWNER FA).
const userWritableDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200ab;;;BU)(A;OICIIO;0x1301bf;;;BU)"

// EnsureUserWritableDir создаёт общий каталог состояния (родитель защищённого
// state) и ставит владельца Администраторы + userWritableDirSDDL — по хэндлу,
// открытому no-follow, тем же путём, что EnsureDataDir для state: path-based
// SetNamedSecurityInfo молча прошёл бы сквозь подсунутый junction и переставил
// DACL его цели. Смена владельца обязательна: прежний код ставил только DACL,
// и pre-creator каталога оставался владельцем — implicit WRITE_DAC вернул бы
// ему любые права поверх наших. Вызывает служба (под SYSTEM) на каждом старте.
// От локального админа не защищает (вне объёма).
func EnsureUserWritableDir(dir string) error {
	return ensureRealDir(dir, userWritableDirSDDL)
}

// maxSecureDepth — потолок рекурсии зачистки прав детей state (защита от
// патологически вложенного pre-seed; наши каталоги — outbox/escrow — плоские).
const maxSecureDepth = 8

// EnsureDataDir создаёт каталог состояния службы и жёстко его защищает
// admin-only. Учитывает, что родитель ProgramData\RoutineOps намеренно
// user-writable (lock.EnsureUserWritableDir), поэтому непривилегированный
// пользователь может заранее подсунуть junction ИЛИ настоящий каталог на месте
// любого звена пути (`mklink /J` привилегии не требует; создатель каталога
// становится его владельцем). Защита строится по всей цепочке:
//
//  1. Каждое звено под ProgramData создаётся Mkdir (не материализует подсунутый
//     junction) и проверяется на reparse-атрибут через ХЭНДЛ, открытый
//     no-follow (FILE_FLAG_OPEN_REPARSE_POINT) — path-based API молча следует
//     через junction. Junction на любом звене → отказ.
//  2. На сам state ставится PROTECTED admin-only DACL И владелец = Администраторы
//     (иначе pre-creator остаётся владельцем и через implicit WRITE_DAC вернул бы
//     себе доступ поверх нашего DACL). DACL/owner ставятся по хэндлу
//     (SE_KERNEL_OBJECT), не по пути.
//  3. Уже существовавшие дети state (pre-seeded forbidden-list/outbox) лишаются
//     своих ACE и владельца, вложенные reparse-точки удаляются — иначе
//     сотрудник читал/подменял бы «защищённый» forbidden-list на своей машине.
//
// Родительский RoutineOps остаётся user-writable (его DACL ставит
// EnsureUserWritableDir) — здесь он только reparse-проверяется, не переопределяется.
func EnsureDataDir(dir string) error {
	parent := filepath.Dir(dir)
	// Прародитель (ProgramData) — доверенный системный корень (пользователь не
	// владеет им и не может подменить непустой каталог junction'ом). Просто
	// гарантируем существование.
	if gp := filepath.Dir(parent); gp != "" && gp != parent {
		if err := os.MkdirAll(gp, 0o755); err != nil {
			return fmt.Errorf("создание корня каталога состояния %s: %w", gp, err)
		}
	}
	// Родитель RoutineOps: создать при отсутствии и проверить на reparse, НО не
	// трогать его DACL здесь (его владельца и user-writable DACL ставит
	// EnsureUserWritableDir на том же старте службы, см. cmd/agent runAgent).
	if err := ensureRealDir(parent, ""); err != nil {
		return fmt.Errorf("родитель каталога состояния %s: %w", parent, err)
	}
	// state: создать/проверить + владелец Администраторы + protected admin-only DACL.
	if err := ensureRealDir(dir, dataDirSDDL); err != nil {
		return err
	}
	// Зачистить права уже существовавших детей (pre-seed).
	return secureExistingChildren(dir)
}

// ensureRealDir создаёт каталог (если отсутствует) и убеждается, что это НЕ
// reparse point. При непустом sddl дополнительно ставит на него владельца
// Администраторы и заданный protected DACL по хэндлу. Возвращает ошибку, если
// на месте каталога обнаружен junction (возможная подмена).
func ensureRealDir(dir string, sddl string) error {
	secure := sddl != ""
	// Mkdir (не MkdirAll): CreateDirectory не создаёт объект поверх занятого
	// имени, а даёт ERROR_ALREADY_EXISTS — подсунутый junction не материализуется.
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("создание %s: %w", dir, err)
	}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	if secure {
		access |= windows.WRITE_DAC | windows.WRITE_OWNER
	}
	h, err := openNoFollow(dir, access)
	if err != nil {
		return fmt.Errorf("открытие %s: %w", dir, err)
	}
	defer windows.CloseHandle(h)

	info, err := fileInfo(h)
	if err != nil {
		return fmt.Errorf("атрибуты %s: %w", dir, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s — reparse point (возможная подмена junction), отказ", dir)
	}
	// Подсунут файл вместо каталога: не проходим дальше (иначе DACL лёг бы на файл,
	// а создание outbox/подкаталогов упало бы → креш-луп службы). Отказ → гейт в
	// runAgent оставит состояние на прежних путях, служба продолжит работать.
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s не является каталогом (возможная подмена файлом), отказ", dir)
	}
	if !secure {
		return nil
	}

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("SID Администраторов: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("разбор SDDL каталога состояния: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("извлечение DACL: %w", err)
	}
	// Владелец + DACL одним вызовом по хэндлу (не по пути): смена владельца на
	// Администраторов снимает implicit-права pre-creator'а.
	if err := windows.SetSecurityInfo(
		h, windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("установка владельца/DACL %s: %w", dir, err)
	}
	runtime.KeepAlive(sd)
	return nil
}

// secureExistingChildren рекурсивно переустанавливает уже существующим детям dir
// владельца и admin-only DACL (снимая ACE, которые мог оставить pre-seed), а
// вложенные reparse-точки удаляет. dir к этому моменту подтверждён настоящим и
// защищён, поэтому чтение его содержимого безопасно. Best-effort: непрочитанное
// пропускаем (в худшем случае объект просто не пере-защищён — не хуже прежнего).
func secureExistingChildren(dir string) error {
	return secureChildrenWith(dir, childDirSDDL)
}

// secureChildrenWith — тело secureExistingChildren с явным SDDL. Вынесено
// параметром РАДИ ТЕСТА: гард пустого DACL ниже иначе непроверяем, а он —
// единственное, что стоит между опечаткой в константе и повторением полевого
// бага, который сервер не видит.
func secureChildrenWith(dir, sddl string) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	// Пустой DACL сюда не должен попасть НИКОГДА: именно он и лишал SYSTEM
	// доступа к собственной очереди в 2.5.1. Проверка дешёвая и стоит прямо
	// перед применением — опечатка в константе иначе повторила бы полевой баг
	// молча, а увидели бы мы её снова только по залипшему статусу в панели.
	if dacl == nil || dacl.AceCount == 0 {
		return fmt.Errorf("DACL детей каталога состояния пуст — применение запрещено (запретило бы доступ всем, включая SYSTEM)")
	}
	secureTree(dir, admins, dacl, 0)
	runtime.KeepAlive(sd)
	return nil
}

// secureTree обходит содержимое dir на один уровень и рекурсивно углубляется в
// подтверждённые настоящие каталоги. Каждый объект открывается no-follow, чтобы
// авторитетно (по хэндлу) отличить reparse от настоящего и не пройти по junction.
func secureTree(dir string, owner *windows.SID, childDACL *windows.ACL, depth int) {
	if depth >= maxSecureDepth {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		h, err := openNoFollow(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES)
		if err != nil {
			continue
		}
		info, ierr := fileInfo(h)
		if ierr != nil {
			windows.CloseHandle(h)
			continue
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			// Вложенная reparse-точка не может быть нашей (мы junction'ов не
			// создаём) — снимаем, чтобы запись через неё не редиректилась.
			windows.CloseHandle(h)
			_ = os.Remove(path)
			continue
		}
		// PROTECTED, а не UNPROTECTED: DACL здесь явный и самодостаточный, и
		// пересчёт наследования нам не нужен. Прежний UNPROTECTED в паре с
		// пустым DACL и давал протекший наружу O:BA D:P — см. childDirSDDL.
		_ = windows.SetSecurityInfo(
			h, windows.SE_KERNEL_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			owner, nil, childDACL, nil,
		)
		isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
		windows.CloseHandle(h)
		if isDir {
			secureTree(path, owner, childDACL, depth+1)
		}
	}
}

// openNoFollow открывает хэндл файла или каталога БЕЗ следования через reparse
// point. FILE_FLAG_BACKUP_SEMANTICS нужен для открытия каталога (и безвреден для
// файла), FILE_FLAG_OPEN_REPARSE_POINT адресует сам объект, а не цель junction'а.
func openNoFollow(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(
		p,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

func fileInfo(h windows.Handle) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	err := windows.GetFileInformationByHandle(h, &info)
	return info, err
}
