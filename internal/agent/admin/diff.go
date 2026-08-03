package admin

import (
	"sort"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

// Дельта сессии админ-прав: что изменилось между базовой линией t0 и текущим
// срезом. Чистые функции без ввода-вывода — вся логика проверяется табличными
// тестами на любой машине, без ОС и без прав администратора.
//
// Сравниваются ОПРЕДЕЛЕНИЯ, не живое состояние (см. collector/services.go).

// Виды изменений. Строки, а не числа: они уходят в БД как есть, и агент новее
// сервера не должен ронять приём неизвестным значением enum.
const (
	ChangeSoftwareInstalled      = "software_installed"
	ChangeSoftwareRemoved        = "software_removed"
	ChangeSoftwareUpdated        = "software_updated"
	ChangeServiceInstalled       = "service_installed"
	ChangeServiceRemoved         = "service_removed"
	ChangeServiceStartTypeChange = "service_start_type_changed"
	ChangeServiceAccountChange   = "service_account_changed"
	ChangeServiceDefChange       = "service_definition_changed"
)

// Атрибуция — ПОДСКАЗКА, а не вердикт. AttrUnknown никогда не молчит: неизвестность
// выражается явно, чтобы её нельзя было спутать с обвинением.
const (
	AttrHumanLikely      = "human_likely"
	AttrBackgroundLikely = "background_likely"
	AttrUnknown          = "unknown"
)

// Причины атрибуции — фиксированный словарь. Не свободный текст: строка уходит в
// БД и в интерфейс, а её сочиняет агент, работающий на машине подотчётного.
const (
	ReasonNewProduct          = "new_product"
	ReasonVersionBumpSameKey  = "version_bump_same_key"
	ReasonRemoved             = "removed"
	ReasonReinstallSameName   = "reinstall_same_name"
	ReasonOSOwnedPath         = "os_owned_path"
	ReasonAdminOwnedPath      = "admin_owned_path"
	ReasonKernelDriverOS      = "kernel_driver_os"
	ReasonKernelDriverForeign = "kernel_driver_foreign"
	ReasonDisabledByHand      = "disabled_by_hand"
	ReasonAccountChanged      = "account_changed"
	ReasonDegradedBaseline    = "degraded_baseline"
)

// Change — одно изменение за сессию.
type Change struct {
	Kind              string
	Subject           string // имя ПО или имя службы
	DisplayName       string
	IdentityKey       string
	OldValue          string
	NewValue          string
	Vendor            string
	Scope             string
	Attribution       string
	AttributionReason string
	ObservedAt        time.Time
}

// DiffSoftware — дельта установленного ПО между базовой линией и текущим срезом.
//
// Ключ записи — UninstallID (см. softwareKey): смена версии по одному и тому же
// ключу это ОБНОВЛЕНИЕ, а не «удалили одно, поставили другое». Без этого любое
// фоновое обновление браузера давало бы две строки в дельте, и в 90% сессий
// оператор видел бы шум вместо сигнала.
func DiffSoftware(before, after []SoftFP, now time.Time) []Change {
	beforeByKey := indexSoft(before)
	afterByKey := indexSoft(after)

	var out []Change
	for key, a := range afterByKey {
		b, existed := beforeByKey[key]
		switch {
		case !existed:
			out = append(out, Change{
				Kind: ChangeSoftwareInstalled, Subject: a.Name, DisplayName: a.Name,
				IdentityKey: key, NewValue: a.Version, Vendor: a.Vendor, Scope: a.Scope,
				Attribution: AttrHumanLikely, AttributionReason: ReasonNewProduct, ObservedAt: now,
			})
		case b.Version != a.Version:
			out = append(out, Change{
				Kind: ChangeSoftwareUpdated, Subject: a.Name, DisplayName: a.Name,
				IdentityKey: key, OldValue: b.Version, NewValue: a.Version,
				Vendor: a.Vendor, Scope: a.Scope,
				Attribution: AttrBackgroundLikely, AttributionReason: ReasonVersionBumpSameKey,
				ObservedAt: now,
			})
		}
	}
	for key, b := range beforeByKey {
		if _, still := afterByKey[key]; !still {
			out = append(out, Change{
				Kind: ChangeSoftwareRemoved, Subject: b.Name, DisplayName: b.Name,
				IdentityKey: key, OldValue: b.Version, Vendor: b.Vendor, Scope: b.Scope,
				Attribution: AttrHumanLikely, AttributionReason: ReasonRemoved, ObservedAt: now,
			})
		}
	}

	out = collapseReinstalls(out, now)
	sortChanges(out)
	return out
}

// collapseReinstalls схлопывает пару «удалено + установлено» с одинаковым именем и
// вендором, но разными ключами, в одно обновление.
//
// Так выглядит переустановка пакета, у которого инсталлятор меняет ProductCode от
// версии к версии (типовое поведение MSI). Без схлопывания каждое такое фоновое
// обновление давало бы в карточке заявки строку «удалил» с атрибуцией на человека —
// то есть ложное обвинение в самом заметном месте интерфейса.
func collapseReinstalls(in []Change, now time.Time) []Change {
	type nameVendor struct{ name, vendor string }
	removedAt := map[nameVendor]int{}
	for i, c := range in {
		if c.Kind == ChangeSoftwareRemoved {
			removedAt[nameVendor{c.Subject, c.Vendor}] = i
		}
	}
	drop := make(map[int]bool)
	out := make([]Change, 0, len(in))
	for i, c := range in {
		if c.Kind != ChangeSoftwareInstalled {
			continue
		}
		j, ok := removedAt[nameVendor{c.Subject, c.Vendor}]
		if !ok || drop[j] {
			continue
		}
		drop[i], drop[j] = true, true
		out = append(out, Change{
			Kind: ChangeSoftwareUpdated, Subject: c.Subject, DisplayName: c.DisplayName,
			IdentityKey: c.IdentityKey, OldValue: in[j].OldValue, NewValue: c.NewValue,
			Vendor: c.Vendor, Scope: c.Scope,
			Attribution: AttrBackgroundLikely, AttributionReason: ReasonReinstallSameName,
			ObservedAt: now,
		})
	}
	for i, c := range in {
		if !drop[i] {
			out = append(out, c)
		}
	}
	return out
}

// DiffServices — дельта определений служб.
func DiffServices(before, after []SvcFP, now time.Time) []Change {
	beforeByKey := indexSvc(before)
	afterByKey := indexSvc(after)

	var out []Change
	for key, a := range afterByKey {
		b, existed := beforeByKey[key]
		if !existed {
			attr, reason := attributeService(a)
			out = append(out, Change{
				Kind: ChangeServiceInstalled, Subject: a.Key, DisplayName: a.Display,
				IdentityKey: key, NewValue: a.ImagePath,
				Attribution: attr, AttributionReason: reason, ObservedAt: now,
			})
			continue
		}
		// Порядок ветвей — от самого показательного к самому общему: смена учётки
		// запуска и отключение службы говорят больше, чем «поменялось определение»,
		// и не должны прятаться за общей строкой.
		switch {
		case b.Account != a.Account:
			out = append(out, Change{
				Kind: ChangeServiceAccountChange, Subject: a.Key, DisplayName: a.Display,
				IdentityKey: key, OldValue: b.Account, NewValue: a.Account,
				Attribution: AttrHumanLikely, AttributionReason: ReasonAccountChanged, ObservedAt: now,
			})
		case b.StartType != a.StartType:
			attr, reason := AttrBackgroundLikely, ReasonOSOwnedPath
			if isDisabling(b.StartType, a.StartType) {
				attr, reason = AttrHumanLikely, ReasonDisabledByHand
			} else if !a.OSOwned {
				attr, reason = AttrHumanLikely, ReasonAdminOwnedPath
			}
			out = append(out, Change{
				Kind: ChangeServiceStartTypeChange, Subject: a.Key, DisplayName: a.Display,
				IdentityKey: key, OldValue: b.StartType, NewValue: a.StartType,
				Attribution: attr, AttributionReason: reason, ObservedAt: now,
			})
		case b.DefHash != a.DefHash || b.ImagePath != a.ImagePath:
			attr, reason := attributeService(a)
			out = append(out, Change{
				Kind: ChangeServiceDefChange, Subject: a.Key, DisplayName: a.Display,
				IdentityKey: key, OldValue: b.ImagePath, NewValue: a.ImagePath,
				Attribution: attr, AttributionReason: reason, ObservedAt: now,
			})
		}
	}
	for key, b := range beforeByKey {
		if _, still := afterByKey[key]; !still {
			attr, reason := attributeService(b)
			out = append(out, Change{
				Kind: ChangeServiceRemoved, Subject: b.Key, DisplayName: b.Display,
				IdentityKey: key, OldValue: b.ImagePath,
				Attribution: attr, AttributionReason: reason, ObservedAt: now,
			})
		}
	}

	sortChanges(out)
	return out
}

// attributeService — правила атрибуции для служб.
//
// Драйвер ядра ВНЕ системного каталога — сильный сигнал: так выглядит установка
// стороннего драйвера руками. Драйвер В системном каталоге — наоборот, рутина
// патч-цикла: Windows Update ставит и обновляет их постоянно, и правило «любой
// драйвер = человек» било бы ложными срабатываниями ровно в ту корзину, которой
// оператора учат доверять.
func attributeService(s SvcFP) (string, string) {
	if s.Kind == collector.KindDriver {
		if s.OSOwned {
			return AttrBackgroundLikely, ReasonKernelDriverOS
		}
		return AttrHumanLikely, ReasonKernelDriverForeign
	}
	if s.OSOwned {
		return AttrBackgroundLikely, ReasonOSOwnedPath
	}
	return AttrHumanLikely, ReasonAdminOwnedPath
}

// isDisabling — переход в «отключено» из любого рабочего режима. Именно так
// выглядит попытка выключить мешающую службу, в том числе защитную.
func isDisabling(before, after string) bool {
	return after == collector.StartTypeDisabled && before != collector.StartTypeDisabled
}

// Degrade помечает всю дельту неизвестной атрибуцией, если базовая линия неполна
// или потеряна. Иначе короткий список выглядел бы как полная картина сессии, а
// уверенное враньё для подотчётности хуже честного «мы не знаем».
func Degrade(changes []Change, softwareHealth, servicesHealth string, baselineLost bool) []Change {
	degraded := baselineLost ||
		(softwareHealth != string(collector.HealthOK) && softwareHealth != "") ||
		(servicesHealth != string(collector.HealthOK) && servicesHealth != "")
	if !degraded {
		return changes
	}
	out := make([]Change, len(changes))
	copy(out, changes)
	for i := range out {
		out[i].Attribution = AttrUnknown
		out[i].AttributionReason = ReasonDegradedBaseline
	}
	return out
}

func indexSoft(in []SoftFP) map[string]SoftFP {
	m := make(map[string]SoftFP, len(in))
	for _, s := range in {
		m[s.Key] = s
	}
	return m
}

func indexSvc(in []SvcFP) map[string]SvcFP {
	m := make(map[string]SvcFP, len(in))
	for _, s := range in {
		m[s.Key] = s
	}
	return m
}

// sortChanges — канонический порядок. Дельта строится обходом map, порядок
// которого Go намеренно рандомизирует: без сортировки два одинаковых окна
// приезжали бы на сервер в разном порядке.
func sortChanges(in []Change) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Kind != in[j].Kind {
			return in[i].Kind < in[j].Kind
		}
		if in[i].Subject != in[j].Subject {
			return in[i].Subject < in[j].Subject
		}
		return in[i].IdentityKey < in[j].IdentityKey
	})
}
