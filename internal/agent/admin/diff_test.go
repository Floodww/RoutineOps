package admin

import (
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

var t0 = time.Unix(1750000000, 0)

func soft(key, name, version string) SoftFP {
	return SoftFP{Key: key, Name: name, Version: version, Vendor: "ACME", Scope: "machine"}
}

func findChange(t *testing.T, in []Change, kind, subject string) Change {
	t.Helper()
	for _, c := range in {
		if c.Kind == kind && c.Subject == subject {
			return c
		}
	}
	t.Fatalf("нет изменения %s/%s в %+v", kind, subject, in)
	return Change{}
}

func TestDiffSoftwareInstalledRemoved(t *testing.T) {
	before := []SoftFP{soft("k1", "Старое", "1.0")}
	after := []SoftFP{soft("k2", "Новое", "2.0")}

	got := DiffSoftware(before, after, t0)
	if len(got) != 2 {
		t.Fatalf("изменений %d, want 2: %+v", len(got), got)
	}
	ins := findChange(t, got, ChangeSoftwareInstalled, "Новое")
	if ins.Attribution != AttrHumanLikely || ins.AttributionReason != ReasonNewProduct {
		t.Errorf("установка нового продукта атрибутирована как %s/%s", ins.Attribution, ins.AttributionReason)
	}
	rem := findChange(t, got, ChangeSoftwareRemoved, "Старое")
	if rem.Attribution != AttrHumanLikely || rem.OldValue != "1.0" {
		t.Errorf("удаление: %+v", rem)
	}
}

// Главное антишумовое правило: обновление по тому же ключу — фон, а не человек.
// Без него каждая сессия, наложившаяся на автообновление браузера, давала бы
// «сотрудник поставил Chrome» в самом заметном месте карточки.
func TestDiffSoftwareVersionBumpIsBackground(t *testing.T) {
	before := []SoftFP{soft("k1", "Браузер", "141.0")}
	after := []SoftFP{soft("k1", "Браузер", "142.0")}

	got := DiffSoftware(before, after, t0)
	if len(got) != 1 {
		t.Fatalf("изменений %d, want 1: %+v", len(got), got)
	}
	c := got[0]
	if c.Kind != ChangeSoftwareUpdated {
		t.Fatalf("вид %q, want %q", c.Kind, ChangeSoftwareUpdated)
	}
	if c.Attribution != AttrBackgroundLikely || c.AttributionReason != ReasonVersionBumpSameKey {
		t.Errorf("обновление версии атрибутировано как %s/%s — это фон", c.Attribution, c.AttributionReason)
	}
	if c.OldValue != "141.0" || c.NewValue != "142.0" {
		t.Errorf("версии: %q → %q", c.OldValue, c.NewValue)
	}
}

// Обратная сторона того же правила: смена ключа при том же имени и вендоре —
// это переустановка (MSI меняет ProductCode), а не «удалил и поставил».
func TestDiffSoftwareReinstallCollapses(t *testing.T) {
	before := []SoftFP{soft("{OLD-GUID}", "Пакет", "1.0")}
	after := []SoftFP{soft("{NEW-GUID}", "Пакет", "2.0")}

	got := DiffSoftware(before, after, t0)
	if len(got) != 1 {
		t.Fatalf("изменений %d, want 1 (переустановка схлопывается): %+v", len(got), got)
	}
	c := got[0]
	if c.Kind != ChangeSoftwareUpdated || c.AttributionReason != ReasonReinstallSameName {
		t.Fatalf("переустановка не схлопнулась: %+v", c)
	}
	if c.OldValue != "1.0" || c.NewValue != "2.0" {
		t.Errorf("версии переустановки: %q → %q", c.OldValue, c.NewValue)
	}
	if c.Attribution != AttrBackgroundLikely {
		t.Errorf("переустановка атрибутирована человеку (%s) — ложное обвинение", c.Attribution)
	}
}

// А вот РАЗНЫЕ продукты одного вендора схлопываться не должны: иначе удаление
// антивируса спряталось бы за установкой любой другой утилиты того же вендора.
func TestDiffSoftwareDifferentNamesDoNotCollapse(t *testing.T) {
	before := []SoftFP{soft("k1", "Антивирус", "1.0")}
	after := []SoftFP{soft("k2", "Утилита", "1.0")}

	got := DiffSoftware(before, after, t0)
	if len(got) != 2 {
		t.Fatalf("изменений %d, want 2 — разные продукты не схлопываются: %+v", len(got), got)
	}
	findChange(t, got, ChangeSoftwareRemoved, "Антивирус")
	findChange(t, got, ChangeSoftwareInstalled, "Утилита")
}

func TestDiffSoftwareNoChanges(t *testing.T) {
	// Скучная сессия обязана давать ровно пустую дельту, а не «ничего не найдено».
	same := []SoftFP{soft("k1", "Браузер", "141.0"), soft("k2", "Редактор", "3.1")}
	if got := DiffSoftware(same, same, t0); len(got) != 0 {
		t.Fatalf("дельта непуста без изменений: %+v", got)
	}
}

func svc(key string, osOwned bool) SvcFP {
	return SvcFP{
		Key: key, Display: key, StartType: collector.StartTypeAuto,
		Account: "SYSTEM", ImagePath: `C:\Windows\System32\` + key + ".exe",
		DefHash: "h1", OSOwned: osOwned, Kind: collector.KindService,
	}
}

func TestDiffServicesInstallAttribution(t *testing.T) {
	cases := []struct {
		name       string
		s          SvcFP
		wantAttr   string
		wantReason string
	}{
		{"служба в системном каталоге", svc("wuauserv", true), AttrBackgroundLikely, ReasonOSOwnedPath},
		{"служба в админском каталоге", svc("mytool", false), AttrHumanLikely, ReasonAdminOwnedPath},
		{
			// Драйверы Windows Update ставит сама, постоянно. Правило «любой драйвер =
			// человек» дало бы ложные срабатывания в патч-цикл.
			"драйвер в системном каталоге",
			func() SvcFP { s := svc("storahci", true); s.Kind = collector.KindDriver; return s }(),
			AttrBackgroundLikely, ReasonKernelDriverOS,
		},
		{
			// А вот драйвер, положенный мимо системного каталога, — сильный сигнал.
			"драйвер вне системного каталога",
			func() SvcFP { s := svc("weirdrv", false); s.Kind = collector.KindDriver; return s }(),
			AttrHumanLikely, ReasonKernelDriverForeign,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DiffServices(nil, []SvcFP{c.s}, t0)
			if len(got) != 1 {
				t.Fatalf("изменений %d, want 1", len(got))
			}
			if got[0].Attribution != c.wantAttr || got[0].AttributionReason != c.wantReason {
				t.Fatalf("атрибуция %s/%s, want %s/%s",
					got[0].Attribution, got[0].AttributionReason, c.wantAttr, c.wantReason)
			}
		})
	}
}

func TestDiffServicesDisablingIsHuman(t *testing.T) {
	// Отключение службы — в том числе защитной — человеку, даже если сама служба
	// системная: ОС свои службы не выключает.
	before := []SvcFP{svc("defender", true)}
	after := []SvcFP{func() SvcFP { s := svc("defender", true); s.StartType = collector.StartTypeDisabled; return s }()}

	got := DiffServices(before, after, t0)
	if len(got) != 1 {
		t.Fatalf("изменений %d, want 1: %+v", len(got), got)
	}
	if got[0].Kind != ChangeServiceStartTypeChange {
		t.Fatalf("вид %q", got[0].Kind)
	}
	if got[0].Attribution != AttrHumanLikely || got[0].AttributionReason != ReasonDisabledByHand {
		t.Fatalf("отключение системной службы атрибутировано как %s/%s — это действие человека",
			got[0].Attribution, got[0].AttributionReason)
	}
}

func TestDiffServicesAccountChange(t *testing.T) {
	before := []SvcFP{svc("svc", true)}
	after := []SvcFP{func() SvcFP { s := svc("svc", true); s.Account = "Администратор"; return s }()}

	got := DiffServices(before, after, t0)
	c := findChange(t, got, ChangeServiceAccountChange, "svc")
	if c.OldValue != "SYSTEM" || c.NewValue != "Администратор" {
		t.Fatalf("учётка: %q → %q", c.OldValue, c.NewValue)
	}
	if c.Attribution != AttrHumanLikely {
		t.Fatalf("смена учётки запуска атрибутирована как %s", c.Attribution)
	}
}

func TestDiffServicesDefinitionChangeCaughtByHash(t *testing.T) {
	// Явные поля прежние, изменилось только тело определения — ровно то, ради чего
	// в снимке хранится DefHash.
	before := []SvcFP{svc("svc", false)}
	after := []SvcFP{func() SvcFP { s := svc("svc", false); s.DefHash = "h2"; return s }()}

	got := DiffServices(before, after, t0)
	if len(got) != 1 || got[0].Kind != ChangeServiceDefChange {
		t.Fatalf("подмена определения не поймана: %+v", got)
	}
}

func TestDiffServicesNoChanges(t *testing.T) {
	same := []SvcFP{svc("a", true), svc("b", false)}
	if got := DiffServices(same, same, t0); len(got) != 0 {
		t.Fatalf("дельта непуста без изменений: %+v", got)
	}
}

func TestDegradeMarksEverythingUnknown(t *testing.T) {
	// Дельта от неполной базовой линии недостоверна. Показать её как уверенную —
	// худший исход для подотчётности: короткий список читался бы как полная картина.
	changes := DiffSoftware(nil, []SoftFP{soft("k1", "Нечто", "1.0")}, t0)
	if changes[0].Attribution != AttrHumanLikely {
		t.Fatalf("подготовка: %+v", changes[0])
	}

	cases := []struct {
		name    string
		sw, svc string
		lost    bool
		want    bool
	}{
		{"всё исправно", string(collector.HealthOK), string(collector.HealthOK), false, false},
		{"частичный сбор ПО", string(collector.HealthPartial), string(collector.HealthOK), false, true},
		{"сбор служб упал", string(collector.HealthOK), string(collector.HealthFailed), false, true},
		{"базовая линия потеряна", string(collector.HealthOK), string(collector.HealthOK), true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Degrade(changes, c.sw, c.svc, c.lost)
			isUnknown := got[0].Attribution == AttrUnknown
			if isUnknown != c.want {
				t.Fatalf("атрибуция %q, ожидалось unknown=%v", got[0].Attribution, c.want)
			}
			// Исходная дельта не должна мутировать: она уходит и в другие окна.
			if changes[0].Attribution != AttrHumanLikely {
				t.Fatal("Degrade изменил исходный срез на месте")
			}
		})
	}
}

func TestDiffIsDeterministic(t *testing.T) {
	// Дельта строится обходом map, порядок которого Go рандомизирует намеренно.
	// Без канонической сортировки одно и то же окно приезжало бы на сервер каждый
	// раз в новом порядке, а сравнивать отчёты стало бы нечем.
	before := []SoftFP{soft("k1", "A", "1"), soft("k2", "B", "1"), soft("k3", "C", "1")}
	after := []SoftFP{soft("k1", "A", "2"), soft("k4", "D", "1")}

	first := DiffSoftware(before, after, t0)
	for i := 0; i < 20; i++ {
		next := DiffSoftware(before, after, t0)
		if len(next) != len(first) {
			t.Fatalf("длина дельты плавает: %d против %d", len(next), len(first))
		}
		for j := range first {
			if next[j].Kind != first[j].Kind || next[j].Subject != first[j].Subject {
				t.Fatalf("порядок дельты плавает на позиции %d: %s/%s против %s/%s",
					j, next[j].Kind, next[j].Subject, first[j].Kind, first[j].Subject)
			}
		}
	}
}
