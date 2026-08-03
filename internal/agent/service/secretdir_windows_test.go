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

// EnsureSecretDir закрывает каталог приватного ключа от обычных пользователей.
//
// Проверка идёт по SID, а НЕ по выводу icacls: имена групп локализованы
// («BUILTIN\Пользователи»), консоль печатает их в OEM-кодировке, и сравнение с
// UTF-8 строкой в тесте не совпало бы никогда — красный на здоровом коде. Ровно
// эту ошибку сегодня чинили в тестах uninstall; здесь она бы вернулась.
//
// Наследуемое право (Пользователи; ReadAndExecute; OI CI) приходит от
// C:\Program Files само — проверено чтением Get-Acl на живой машине. Поэтому
// «нет ACE для Пользователей» и означает, что защита перекрыла наследование.
func TestEnsureSecretDir_ClosesInheritedUserAccess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := EnsureSecretDir(dir); err != nil {
		t.Fatalf("EnsureSecretDir: %v", err)
	}

	granted, aceCount, sddl := systemFullAccess(t, dir)
	// Пустой DACL — не «права по умолчанию», а «запрещено всем», включая SYSTEM.
	// Это реальный полевой исход неверной реализации (см. childDirSDDL), и
	// отличить его от правильного можно только счётчиком ACE.
	if aceCount == 0 {
		t.Fatalf("DACL ПУСТ (%s) — доступ запрещён всем, включая службу", sddl)
	}
	if !granted {
		t.Errorf("SYSTEM не имеет полного доступа — служба не прочитает собственный ключ (%s)", sddl)
	}
	// PROTECTED: наследование от каталога установки отрезано. Без P доезжали бы
	// ACE родителя поверх наших — ровно то, из-за чего ключ и был читаем.
	if !strings.Contains(sddl, "D:P") {
		t.Errorf("DACL не PROTECTED — наследование не отрезано (%s)", sddl)
	}
	for _, w := range []struct {
		name string
		sid  windows.WELL_KNOWN_SID_TYPE
	}{
		{"Пользователи", windows.WinBuiltinUsersSid},
		{"Everyone", windows.WinWorldSid},
		{"Прошедшие проверку", windows.WinAuthenticatedUserSid},
	} {
		if hasAnyAccess(t, dir, w.sid) {
			t.Errorf("у группы %q остался доступ к каталогу приватного ключа (%s)", w.name, sddl)
		}
	}
}

// Повторный вызов не падает и не ослабляет права: он идёт на каждом старте службы.
func TestEnsureSecretDir_Idempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := EnsureSecretDir(dir); err != nil {
		t.Fatalf("первый вызов: %v", err)
	}
	_, _, first := systemFullAccess(t, dir)
	if err := EnsureSecretDir(dir); err != nil {
		t.Fatalf("повторный вызов: %v", err)
	}
	if _, _, second := systemFullAccess(t, dir); second != first {
		t.Errorf("повторный вызов изменил права:\nбыло:  %s\nстало: %s", first, second)
	}
}

// Каталог с уже лежащим ключом закрывается, содержимое переживает: enroll
// вызывает функцию ПОСЛЕ записи ключа, и потеря файла здесь означала бы
// устройство без идентичности сразу после установки.
func TestEnsureSecretDir_KeepsExistingContent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(key, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSecretDir(dir); err != nil {
		t.Fatalf("EnsureSecretDir: %v", err)
	}
	got, err := os.ReadFile(key)
	if err != nil {
		t.Fatalf("ключ пропал после защиты каталога: %v", err)
	}
	if string(got) != "PRIVATE KEY" {
		t.Errorf("содержимое ключа изменилось: %q", got)
	}
}

// Уже лежащий ключ тоже лишается Users RX: одного DACL на каталоге мало
// (SeChangeNotifyPrivilege / bypass traverse → открытие по полному пути).
func TestEnsureSecretDir_ClosesExistingKeyFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "agent.key")
	if err := os.WriteFile(key, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Имитируем унаследованный Users RX на файле (как после MSI до фикса).
	inheritSDDL := "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	sd, err := windows.SecurityDescriptorFromString(inheritSDDL)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(key, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("подготовка Users RX на ключе: %v", err)
	}
	if !hasAnyAccess(t, key, windows.WinBuiltinUsersSid) {
		t.Fatal("подготовка не удалась: Users нет на ключе до EnsureSecretDir")
	}

	if err := EnsureSecretDir(dir); err != nil {
		t.Fatalf("EnsureSecretDir: %v", err)
	}
	if hasAnyAccess(t, key, windows.WinBuiltinUsersSid) {
		_, _, sddl := systemFullAccess(t, key)
		t.Fatalf("у Пользователей остался доступ к agent.key после защиты (%s)", sddl)
	}
	granted, aceCount, sddl := systemFullAccess(t, key)
	if aceCount == 0 {
		t.Fatalf("DACL ключа ПУСТ — SYSTEM потерял бы доступ (%s)", sddl)
	}
	if !granted {
		t.Errorf("SYSTEM не имеет полного доступа к ключу (%s)", sddl)
	}
}

// hasAnyAccess — есть ли в DACL объекта хоть один разрешающий ACE для группы.
// Именно «хоть один», а не «полный доступ»: чтение — это уже утечка ключа.
func hasAnyAccess(t *testing.T, path string, wellKnown windows.WELL_KNOWN_SID_TYPE) bool {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("чтение дескриптора %s: %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}
	want, err := windows.CreateWellKnownSid(wellKnown)
	if err != nil {
		t.Fatalf("SID: %v", err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(want) && ace.Mask != 0 {
			return true
		}
	}
	return false
}
