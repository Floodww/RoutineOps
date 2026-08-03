package decommission

import (
	"os"
	"path/filepath"
	"testing"
)

// repoRoot ищет корень репозитория вверх от рабочего каталога и сообщает, нашёлся
// ли он вообще.
//
// Контрактные тесты сверяют константы кода с упаковочными файлами (nfpm.yaml,
// .wxs) по относительному пути от каталога пакета. Это верно ровно до тех пор,
// пока тест идёт внутри дерева исходников. Тест-бинарь, собранный кросс-
// компиляцией и запущенный на живой Windows (go test -c → scp → прогон), стоит
// вне репозитория — сверять там не с чем, и падение сообщало бы не о дрейфе
// констант, а о способе запуска. Такой красный хуже бесполезного: он тратит
// разбор и приучает игнорировать красные контрактные тесты.
func repoRoot(t *testing.T) (string, bool) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// skipOutsideRepo — общая формулировка причины пропуска.
func skipOutsideRepo(t *testing.T) string {
	t.Helper()
	root, ok := repoRoot(t)
	if !ok {
		t.Skip("вне дерева исходников (прогон перенесённого тест-бинаря): упаковочных файлов рядом нет")
	}
	return root
}
