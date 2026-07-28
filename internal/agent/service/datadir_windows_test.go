//go:build windows

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Регрессия полевого бага 2.5.1 (полевая Windows-машина): после рестарта службы каталог
// state\outbox получал пустой protected DACL, и служба под SYSTEM теряла доступ
// к собственной durable-очереди. Наружу это не выходило вообще — outbox и есть
// канал доставки, — единственным признаком был залипший статус в панели.
//
// Тест проверяет РЕЗУЛЬТАТ на диске, а не намерение кода: читает фактический
// дескриптор объекта после EnsureDataDir и убеждается, что SYSTEM имеет полный
// доступ. Проверка «вызвали ли мы нужный API с нужными флагами» этот баг НЕ
// поймала бы: флаги были ровно те, что задумывались, — неверным оказалось
// поведение самого вызова.
//
// Тесту нужна повышенная сессия: смена владельца на BUILTIN\Администраторы
// требует прав. Он намеренно НЕ скипается при их отсутствии — пропущенная
// проверка привилегированного поведения неотличима от пройденной, а именно так
// этот баг и доехал до поля.

// systemFullAccess ищет в DACL объекта разрешающую запись для NT AUTHORITY\SYSTEM
// с полным доступом. Возвращает также число ACE — ноль означает пустой DACL,
// то есть «запрещено всем», ровно как в полевом баге.
func systemFullAccess(t *testing.T, path string) (granted bool, aceCount uint32, sddl string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("чтение дескриптора %s: %v", path, err)
	}
	sddl = sd.String()
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL %s: %v", path, err)
	}
	if dacl == nil {
		return false, 0, sddl
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("SID SYSTEM: %v", err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(system) {
			continue
		}
		const fileAllAccess = 0x1F01FF
		if uint32(ace.Mask)&fileAllAccess == fileAllAccess {
			return true, uint32(dacl.AceCount), sddl
		}
	}
	return false, uint32(dacl.AceCount), sddl
}

// Главный регрессионный сценарий: дети state СУЩЕСТВУЮТ до вызова — это второй
// и все последующие старты службы. На свежей установке outbox ещё нет, поэтому
// баг не проявлялся при установке и вылезал только после первой перезагрузки.
func TestEnsureDataDir_ExistingChildrenRemainAccessibleToSystem(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "RoutineOps", "state")
	outbox := filepath.Join(state, "outbox")
	if err := os.MkdirAll(outbox, 0o700); err != nil {
		t.Fatalf("подготовка каталогов: %v", err)
	}
	seen := filepath.Join(state, "tasks.seen")
	if err := os.WriteFile(seen, []byte("t-1\n"), 0o600); err != nil {
		t.Fatalf("подготовка файла: %v", err)
	}
	// Вложенный уровень: зачистка рекурсивная, и регрессия обязана покрывать
	// не только первый уровень.
	nested := filepath.Join(outbox, "sub")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("подготовка вложенного каталога: %v", err)
	}

	if err := EnsureDataDir(state); err != nil {
		t.Fatalf("EnsureDataDir: %v\n(нужна сессия с правами администратора — смена владельца на BUILTIN\\Администраторы)", err)
	}

	for _, p := range []string{state, outbox, seen, nested} {
		granted, aceCount, sddl := systemFullAccess(t, p)
		if aceCount == 0 {
			t.Errorf("%s: DACL ПУСТ (%s) — это и есть полевой баг: доступ запрещён всем, включая SYSTEM", p, sddl)
			continue
		}
		if !granted {
			t.Errorf("%s: у SYSTEM нет полного доступа (%s)", p, sddl)
		}
	}
}

// Фактическая операция, а не только разбор дескриптора: очередь и создаётся, и
// читается на каждом старте.
func TestEnsureDataDir_ChildStaysWritable(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "RoutineOps", "state")
	outbox := filepath.Join(state, "outbox")
	if err := os.MkdirAll(outbox, 0o700); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	if err := EnsureDataDir(state); err != nil {
		t.Fatalf("EnsureDataDir: %v (нужна сессия администратора)", err)
	}

	probe := filepath.Join(outbox, "0001.rec")
	if err := os.WriteFile(probe, []byte("payload"), 0o600); err != nil {
		t.Fatalf("запись в очередь после EnsureDataDir: %v", err)
	}
	if _, err := os.ReadDir(outbox); err != nil {
		t.Fatalf("чтение очереди после EnsureDataDir: %v", err)
	}
	if _, err := os.ReadFile(probe); err != nil {
		t.Fatalf("чтение записи очереди: %v", err)
	}
}

// Инвариант константы: DACL детей обязан содержать хотя бы один ACE. Пустой
// DACL — не «права по умолчанию», а «запрещено всем»; именно подмена этой
// константы на "D:" и стоила нам полевого бага. Тест дешёвый и держит границу
// на уровне константы, до всякого ввода-вывода.
func TestChildDirSDDL_IsNotEmptyDACL(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(childDirSDDL)
	if err != nil {
		t.Fatalf("разбор childDirSDDL: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL childDirSDDL: %v", err)
	}
	if dacl == nil || dacl.AceCount == 0 {
		t.Fatalf("childDirSDDL = %q даёт DACL без единого ACE — это запрет доступа ВСЕМ, включая SYSTEM", childDirSDDL)
	}
	// SYSTEM обязан быть в самой строке: служба работает под ним.
	if !strings.Contains(childDirSDDL, ";SY)") {
		t.Errorf("childDirSDDL = %q не содержит ACE для SYSTEM", childDirSDDL)
	}
}

// Гард пустого DACL: даже если константа снова станет "D:", применение обязано
// отказать ДО записи прав, а не воспроизвести полевой баг молча.
//
// Проверяем и последствие отказа: права ребёнка остаются прежними, то есть
// доступными, — гард не должен «на всякий случай» оставить объект запертым.
func TestSecureChildrenWith_RefusesEmptyDACL(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "RoutineOps", "state")
	outbox := filepath.Join(state, "outbox")
	if err := os.MkdirAll(outbox, 0o700); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	err := secureChildrenWith(state, "D:")
	if err == nil {
		t.Fatal(`применение пустого DACL ("D:") к детям каталога состояния должно быть ОТКЛОНЕНО — это запрет доступа всем, включая SYSTEM`)
	}
	if !strings.Contains(err.Error(), "пуст") {
		t.Errorf("причина отказа непонятна для разбора в поле: %v", err)
	}

	// Отказ — до применения: очередь осталась рабочей.
	if err := os.WriteFile(filepath.Join(outbox, "probe"), []byte("x"), 0o600); err != nil {
		t.Errorf("после отказа гарда очередь оказалась недоступна: %v", err)
	}
}
