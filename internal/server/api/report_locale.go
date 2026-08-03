package api

import (
	"net/http"
	"strings"

	"github.com/Floodww/RoutineOps/internal/server/storage"
)

// Язык серверных выгрузок.
//
// 🔴 Отчёт печатался по-русски независимо от языка панели: формулировки лежат в Go,
// а сервер языка оператора не знал. Англоязычный админ видел английский экран и
// скачивал русский файл — то есть подшивал к делу документ, который сам прочесть
// не может.
//
// Язык приходит параметром ?lang= (панель подставляет текущий i18n.language), с
// откатом на Accept-Language и дальше на русский. Заголовок один не годится:
// оператор мог переключить язык интерфейса, не трогая настройки браузера.

// Разделитель — часть локали, а не константа.
//
// 🔴 Excel берёт разделитель списка из СИСТЕМНОЙ локали: в русской это «;», в
// англоязычной — «,». Зашитая «;» чинила русский Excel и ровно так же ломала
// английский: весь отчёт складывался в одну колонку. Пара «разделитель + язык»
// обязана меняться вместе.
type reportLocale struct {
	comma   rune
	headers []string
	yes     string
	no      string
	reasons map[string]string
}

const defaultReportLang = "ru"

var reportLocales = map[string]reportLocale{
	"ru": {
		comma: ';',
		headers: []string{
			"Устройство", "ОС", "Версия ОС", "Версия агента", "Канал", "Статус",
			"Последний контакт", "Уязвимостей", "Не сопоставлено", "Соответствует", "Причины",
		},
		yes: "да",
		no:  "нет",
		// Те же формулировки, что в словаре панели (секция complianceReason): отчёт и
		// экран обязаны называть одно и то же одинаково, иначе выгрузку не сверить с
		// тем, что видел человек.
		reasons: map[string]string{
			storage.ComplianceVulnerable:    "есть уязвимости",
			storage.ComplianceUnverified:    "версии не сопоставлены",
			storage.ComplianceStale:         "давно не выходило на связь",
			storage.ComplianceOutdatedAgent: "версия агента отличается от канала",
			storage.ComplianceDegraded:      "очередь агента недоступна",
			storage.ComplianceLocked:        "заблокировано",
		},
	},
	"en": {
		comma: ',',
		headers: []string{
			"Device", "OS", "OS version", "Agent version", "Channel", "Status",
			"Last seen", "Vulnerabilities", "Unverified", "Compliant", "Reasons",
		},
		yes: "yes",
		no:  "no",
		reasons: map[string]string{
			storage.ComplianceVulnerable:    "has vulnerabilities",
			storage.ComplianceUnverified:    "versions not matched",
			storage.ComplianceStale:         "out of contact for a long time",
			storage.ComplianceOutdatedAgent: "agent version differs from the channel",
			storage.ComplianceDegraded:      "agent queue unavailable",
			storage.ComplianceLocked:        "locked",
		},
	},
}

// reportLocaleFor выбирает локаль выгрузки. Неизвестный язык — не ошибка: отчёт
// нужнее отказа, поэтому падаем на язык по умолчанию.
func reportLocaleFor(r *http.Request) reportLocale {
	if l, ok := reportLocales[normalizeLang(r.URL.Query().Get("lang"))]; ok {
		return l
	}
	if l, ok := reportLocales[normalizeLang(firstAcceptLanguage(r.Header.Get("Accept-Language")))]; ok {
		return l
	}
	return reportLocales[defaultReportLang]
}

// normalizeLang приводит "EN-US" и "ru_RU" к базовому тегу: панель шлёт то, что
// отдал детектор i18next, а он различает региональные варианты.
func normalizeLang(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, sep := range []string{"-", "_"} {
		if i := strings.Index(v, sep); i > 0 {
			v = v[:i]
		}
	}
	return v
}

// firstAcceptLanguage берёт первый тег заголовка, игнорируя q-веса: выбирать между
// «ru;q=0.9» и «en;q=0.8» здесь не из чего — поддерживаемых языков всего два, а
// точный разбор RFC 4647 ради этого тянул бы зависимость.
func firstAcceptLanguage(header string) string {
	if header == "" {
		return ""
	}
	first := strings.Split(header, ",")[0]
	return strings.TrimSpace(strings.Split(first, ";")[0])
}

func (l reportLocale) boolWord(b bool) string {
	if b {
		return l.yes
	}
	return l.no
}

// translateReasons — незнакомую причину отдаём как есть: набор причин расширяется
// на сервере, и новая причина должна быть видна в отчёте, а не исчезнуть из него.
func (l reportLocale) translateReasons(reasons []string) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		if w, ok := l.reasons[r]; ok {
			out = append(out, w)
			continue
		}
		out = append(out, r)
	}
	return out
}
