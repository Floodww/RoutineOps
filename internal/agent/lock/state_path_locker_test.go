package lock

import (
	"path/filepath"
	"testing"
)

// pathAwareLocker — локер, который принимает путь состояния (так устроен Linux:
// оверлей поднимается ОТДЕЛЬНЫМ процессом в сессии пользователя).
type pathAwareLocker struct {
	fakeLocker
	got string
}

func (l *pathAwareLocker) SetStatePath(p string) { l.got = p }

// Без передачи пути дочерний процесс замка вычислил бы СВОЙ путь по умолчанию (у него
// другой пользователь и другой рабочий каталог), прочитал бы пустоту и молча вышел:
// сервер считает устройство заблокированным, а у сотрудника чистый экран.
func TestNew_ПередаётПутьСостоянияЛокеру(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.json")
	l := &pathAwareLocker{}
	New(path, l, quietLog())
	if l.got != path {
		t.Fatalf("локер получил путь %q, want %q", l.got, path)
	}
}

// Локеры, которым путь не нужен (Windows, macOS), обязаны работать как раньше.
func TestNew_ЛокерБезПутиНеЛомается(t *testing.T) {
	if m := New(filepath.Join(t.TempDir(), "lock.json"), &fakeLocker{}, quietLog()); m == nil {
		t.Fatal("Manager не создан")
	}
}
