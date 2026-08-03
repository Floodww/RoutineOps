package service

import (
	"os"
	"path/filepath"
	"testing"
)

// skipOutsideRepo возвращает корень репозитория, а вне дерева исходников
// пропускает тест.
//
// Контракт сверяет константы кода с упаковочными скриптами по относительному
// пути от каталога пакета — это работает, пока тест идёт внутри репозитория.
// Тест-бинарь, собранный кросс-компиляцией и запущенный на живой Windows
// (go test -c → scp → прогон), стоит вне дерева: сверять там не с чем, и красный
// сообщал бы о способе запуска, а не о дрейфе констант.
func skipOutsideRepo(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Skip("рабочий каталог недоступен")
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("вне дерева исходников (прогон перенесённого тест-бинаря): упаковочных скриптов рядом нет")
		}
		dir = parent
	}
}
