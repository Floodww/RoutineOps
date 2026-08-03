package collector

import (
	"reflect"
	"strings"
	"testing"
)

// Снимок служб — половина дельты аудита выданных админ-прав. Ошибка здесь не
// «неточные данные в карточке», а либо шум на весь парк (волатильное поле в
// снимке), либо невидимая подмена системной службы (неверная атрибуция).

func TestStartTypeFromDWORD(t *testing.T) {
	cases := []struct {
		name    string
		v       uint64
		delayed bool
		want    string
	}{
		{"драйвер загрузчика", 0, false, StartTypeBoot},
		{"драйвер ядра", 1, false, StartTypeSystem},
		{"автозапуск", 2, false, StartTypeAuto},
		{"отложенный автозапуск", 2, true, StartTypeAutoDelayed},
		{"вручную", 3, false, StartTypeManual},
		{"отключена", 4, false, StartTypeDisabled},
		// Неизвестное значение обязано давать пустую строку, а не «отключена»:
		// иначе новая версия Windows с новым режимом дала бы по всему парку
		// ложное «службу выключили руками» — обвинение на ровном месте.
		{"неизвестное значение", 9, false, StartTypeUnknown},
		// delayed без Start=2 не имеет смысла и не должен подменять режим.
		{"delayed при ручном запуске", 3, true, StartTypeManual},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := startTypeFromDWORD(c.v, c.delayed); got != c.want {
				t.Fatalf("startTypeFromDWORD(%d, %v) = %q, want %q", c.v, c.delayed, got, c.want)
			}
		})
	}
}

func TestKindFromServiceType(t *testing.T) {
	// Драйверы ядра и файловой системы выделяются отдельно: их появление вне
	// системного каталога — сильный сигнал при разборе инцидента.
	for _, v := range []uint64{1, 2} {
		if got := kindFromServiceType(v); got != KindDriver {
			t.Fatalf("Type=%d → %q, want %q", v, got, KindDriver)
		}
	}
	for _, v := range []uint64{0, 16, 32, 272} {
		if got := kindFromServiceType(v); got != KindService {
			t.Fatalf("Type=%d → %q, want %q", v, got, KindService)
		}
	}
}

func TestIsUnderAnyIgnoresCase(t *testing.T) {
	// Реестр отдаёт пути в произвольном регистре. Регистрозависимая проверка
	// объявила бы штатные системные службы «поставленными человеком» — то есть
	// сломала бы атрибуцию ровно наоборот.
	prefixes := []string{`c:\windows\system32`, `%systemroot%\system32`}
	yes := []string{
		`C:\Windows\System32\svchost.exe -k netsvcs`,
		`c:\windows\system32\drivers\foo.sys`,
		`%SystemRoot%\System32\bar.exe`,
	}
	for _, p := range yes {
		if !isUnderAny(p, prefixes) {
			t.Fatalf("путь %q не признан системным", p)
		}
	}
	no := []string{
		`C:\ProgramData\Evil\agent.exe`,
		`D:\tools\svc.exe`,
		"",
		"   ",
	}
	for _, p := range no {
		if isUnderAny(p, prefixes) {
			t.Fatalf("путь %q ошибочно признан системным", p)
		}
	}
}

func TestHashDefinitionStableAndSensitive(t *testing.T) {
	a := hashDefinition([]byte("ExecStart=/usr/bin/foo\n"))
	b := hashDefinition([]byte("ExecStart=/usr/bin/foo\n"))
	c := hashDefinition([]byte("ExecStart=/usr/bin/foo --evil\n"))
	if a != b {
		t.Fatal("хэш одного и того же определения не стабилен")
	}
	if a == c {
		t.Fatal("изменение аргументов запуска не поменяло хэш — подмена определения была бы невидима")
	}
}

func TestSortServicesIsCanonical(t *testing.T) {
	// Порядок обхода каталога и реестра не гарантирован. Без канонической
	// сортировки два одинаковых снимка дали бы «дельту», объяснить которую
	// оператору невозможно.
	in := []Service{{Name: "zeta"}, {Name: "alpha"}, {Name: "mid"}}
	sortServices(in)
	got := []string{in[0].Name, in[1].Name, in[2].Name}
	want := []string{"alpha", "mid", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("порядок %v, want %v", got, want)
	}
}

// TestServiceHasNoVolatileFields — главный инвариант снимка, зафиксированный
// структурно. Любое поле вроде State/PID/StartedAt даст «изменение» на каждом
// ребуте по всему парку, и полезный сигнал утонет в шуме. Тест ловит добавление
// такого поля в момент, когда его добавляют, а не через месяц на проде.
func TestServiceHasNoVolatileFields(t *testing.T) {
	allowed := map[string]bool{
		"Name": true, "Display": true, "StartType": true, "Account": true,
		"ImagePath": true, "DefHash": true, "OSOwned": true, "Kind": true,
	}
	banned := []string{"state", "status", "pid", "running", "started", "uptime", "lastrun"}

	rt := reflect.TypeOf(Service{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i).Name
		if !allowed[f] {
			t.Errorf("новое поле Service.%s: если оно волатильно (меняется между ребутами), "+
				"дельта сессии зашумится по всему парку; если стабильно — добавь его в allowed", f)
		}
		low := strings.ToLower(f)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("поле Service.%s выглядит волатильным (%q): снимок сравнивает ОПРЕДЕЛЕНИЯ, а не runtime", f, b)
			}
		}
	}
}

func TestServicesReturnsHealth(t *testing.T) {
	// Контракт точки входа: здоровье возвращается всегда, и пустой список при
	// неудачном сборе не имеет права выглядеть как «изменений не было».
	svcs, health := Services()
	switch health {
	case HealthOK, HealthPartial, HealthFailed, HealthUnsupported:
	default:
		t.Fatalf("неизвестное здоровье снимка: %q", health)
	}
	if health == HealthUnsupported && len(svcs) != 0 {
		t.Fatalf("unsupported обязан отдавать пустой снимок, получено %d записей", len(svcs))
	}
}
