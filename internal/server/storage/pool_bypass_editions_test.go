package storage_test

import (
	"strings"
	"testing"
)

// Разбор записей списка исключений на «протухла» и «этой редакции не касается».
//
// 🔴 Гейт TestPoolBypassesAreDocumented уезжает в публичный срез как есть, а там часть
// кода физически отсутствует: SAML вырезается целиком, а запись
// saml.go:GetSAMLProviderForAuth в списке остаётся. Open-core CI падал на ней по
// построению — каждый прогон, на пустом месте. Тот же класс, что шаг сборки с
// enterprise-тегами в срезе без enterprise-исходников: гейт проверяет не то, что едет.
//
// Проверяются ОБА исхода, потому что односторонняя правка здесь опаснее исходной беды:
// «пропускать всё, чего не нашли» тихо превратило бы список в свалку — а он ровно для
// того и заведён, чтобы решение «под RLS или нет» принималось один раз и записывалось.
func TestStaleEntriesDistinguishAbsentFileFromDeadEntry(t *testing.T) {
	allowed := map[string]string{
		"tx.go:BindTenant":               "живая: файл есть, функция есть",
		"postgres.go:RenamedAwayLongAgo": "протухшая: файл есть, функции нет",
		"saml.go:GetSAMLProviderForAuth": "не в этой редакции: файла нет",
	}
	found := map[string]bool{"tx.go:BindTenant": true}
	present := map[string]bool{"tx.go": true, "postgres.go": true} // saml.go вырезан

	stale, absent := staleEntries(allowed, found, present)

	if got := strings.Join(stale, ","); got != "postgres.go:RenamedAwayLongAgo" {
		t.Errorf("протухшие записи: %q, ожидалась ровно postgres.go:RenamedAwayLongAgo.\n"+
			"Если сюда попала saml.go — гейт снова падает в срезе на пустом месте; "+
			"если НЕ попала postgres.go — список перестал ловить собственный мусор, "+
			"и строгость в суперсете потеряна", got)
	}
	if got := strings.Join(absent, ","); got != "saml.go:GetSAMLProviderForAuth" {
		t.Errorf("пропущенные записи: %q, ожидалась ровно saml.go:GetSAMLProviderForAuth", got)
	}
}

// Запись без разделителя не должна пролезать в «пропущенные» — иначе опечатка в списке
// становится невидимой навсегда.
func TestStaleEntriesTreatMalformedRecordAsStale(t *testing.T) {
	stale, absent := staleEntries(
		map[string]string{"ПростоТекстБезФайла": "опечатка"},
		map[string]bool{},
		map[string]bool{"tx.go": true},
	)
	if len(absent) != 0 {
		t.Fatalf("битая запись ушла в пропущенные: %v", absent)
	}
	if len(stale) != 1 {
		t.Fatalf("битая запись не попала в протухшие: %v", stale)
	}
}
