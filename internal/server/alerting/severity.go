// Package alerting хранит доменное знание о критичности алертов: сколько уровней
// бывает, какой уровень получает событие каждого типа и в каком порядке инциденты
// показываются оператору.
//
// До миграции 041 это знание жило в константе TYPE_ORDER во фронтенде
// (web/src/pages/Alerts.tsx) — то есть приоритет инцидента существовал только в
// браузере и был недоступен ни серверу, ни уведомлениям. Пакет переносит его на
// сервер, откуда им могут пользоваться маршрутизация в Telegram, эскалация
// непринятых алертов и (в будущем) экспорт в SIEM.
//
// Пакет не зависит от storage и от БД: это справочник решений, а не их исполнение.
package alerting

import "strings"

// Severity — уровень критичности алерта. Значения совпадают с CHECK-ограничением
// alerts_severity_check (миграция 041).
type Severity string

const (
	// SeverityCritical — деструктив идёт прямо сейчас либо на устройстве активный
	// противник. Требует реакции немедленно, само не рассосётся.
	SeverityCritical Severity = "critical"

	// SeverityHigh — нарушение или рассогласование, требующее вмешательства IT, но
	// машина при этом цела и ситуация не развивается сама по себе.
	SeverityHigh Severity = "high"

	// SeverityMedium — постфактум-нарушение политики: разбирается в рабочем порядке.
	SeverityMedium Severity = "medium"

	// SeverityLow — операционный сигнал, а не инцидент безопасности.
	SeverityLow Severity = "low"
)

// rank задаёт порядок «важнее → менее важно». Числа наружу не выставляются: их
// единственное назначение — сравнение, и любое их сохранение в БД или в API
// зафиксировало бы шкалу, которую потом нельзя расширить посередине.
var rank = map[Severity]int{
	SeverityCritical: 4,
	SeverityHigh:     3,
	SeverityMedium:   2,
	SeverityLow:      1,
}

// defaults — критичность по типу события.
//
// Карта обязана совпадать с CASE в migrations/041_alert_severity.sql; расхождение
// ловит TestDefaultsMatchMigration. Дублирование намеренно: бэкфилл существующих
// строк выполняется в SQL до старта сервера, вызвать сюда оттуда нечем.
//
// Уровни расставлены по СРОЧНОСТИ ВМЕШАТЕЛЬСТВА, а не по «серьёзности вообще» —
// та же логика, что была в комментарии к TYPE_ORDER во фронтенде:
//   - filevault_revoke_failed: деструктив уже начался, машина полу-ревокнута и
//     сама не починится;
//   - lock_tamper: живой противник на устройстве прямо сейчас;
//   - filevault_secret_mismatch: деструктив остановлен ДО мутации, машина цела,
//     но кастодия ключей разъехалась;
//   - outbox_unavailable: мёртвый датчик. Стоит выше нарушений политики не по
//     «серьёзности вообще», а потому что обесценивает ТИШИНУ: пока признак висит,
//     отсутствие остальных событий с этой машины ничего не доказывает — они
//     физически не могут доехать;
//   - остальное — постфактум-нарушения политики;
//   - agent_unreachable: операционный сигнал, а не инцидент.
var defaults = map[string]Severity{
	"filevault_revoke_failed":      SeverityCritical,
	"lock_tamper":                  SeverityCritical,
	"filevault_secret_mismatch":    SeverityHigh,
	"outbox_unavailable":           SeverityHigh,
	"forbidden_software":           SeverityHigh,
	"unauthorized_install":         SeverityMedium,
	"unauthorized_settings_change": SeverityMedium,
	"agent_unreachable":            SeverityLow,
	// Улики сессии админ-прав не доехали: подотчётность прав сломана.
	"admin_session_evidence_gap": SeverityHigh,
}

// UnknownSeverity — уровень для типа, которого нет в defaults.
//
// High, а НЕ low и не medium. Незнакомый alert_type означает агента новее сервера:
// событие, которое мы не умеем классифицировать, не должно молча уходить ниже
// порога доставки оператора (см. DeliverTo). High доставляется при любом разумном
// пороге, но не претендует на «будить ночью» — за это отвечает critical, и раздача
// его неизвестному типу обесценила бы уровень.
const UnknownSeverity = SeverityHigh

// typeOrder — порядок типов ВНУТРИ одного уровня критичности. Сохраняет ровно ту
// последовательность секций, которую видел оператор до 041: смена сортировки на
// «по severity» не должна была переставить местами то, что и так шло правильно.
var typeOrder = []string{
	"filevault_revoke_failed",
	"lock_tamper",
	"filevault_secret_mismatch",
	"outbox_unavailable",
	"forbidden_software",
	"unauthorized_install",
	"unauthorized_settings_change",
	"agent_unreachable",
	"admin_session_evidence_gap",
}

// DefaultFor возвращает критичность по умолчанию для типа события. Регистр и
// пробелы нормализуются: gateway кладёт в БД strings.ToLower от имени proto-энума,
// но alert_type — свободный TEXT, и в него исторически может попасть что угодно.
func DefaultFor(alertType string) Severity {
	if s, ok := defaults[strings.ToLower(strings.TrimSpace(alertType))]; ok {
		return s
	}
	return UnknownSeverity
}

// Parse разбирает уровень из строки (значение из БД или из тела запроса).
// ok=false для всего, что не входит в шкалу, — вызывающий обязан решить сам, и
// молчаливая подстановка значения по умолчанию здесь была бы ошибкой: она
// превратила бы опечатку оператора в тихое понижение критичности.
func Parse(s string) (Severity, bool) {
	v := Severity(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := rank[v]; ok {
		return v, true
	}
	return "", false
}

// AtLeast сообщает, что s не ниже threshold. Неизвестные значения считаются
// минимально возможными — но это не путь доставки: DeliverTo обрабатывает их
// явно и fail-open.
func AtLeast(s, threshold Severity) bool {
	return rank[s] >= rank[threshold]
}

// DeliverTo решает, уходит ли алерт уровня s получателю с порогом threshold.
//
// Fail-open по обоим аргументам, и это осознанно. Порог хранится в
// users.notify_min_severity под CHECK-ограничением, а критичность — в
// alerts.severity под таким же; попасть сюда битым значением можно только через
// ручной UPDATE в psql или через рассинхрон версий кода и схемы. В обоих случаях
// правильное поведение — доставить, а не проглотить: непришедшее уведомление о
// реальном инциденте стоит дороже лишнего сообщения в Telegram, и, в отличие от
// него, ничем себя не проявляет.
func DeliverTo(s, threshold Severity) bool {
	sr, ok := rank[s]
	if !ok {
		return true
	}
	tr, ok := rank[threshold]
	if !ok {
		return true
	}
	return sr >= tr
}

// Rank отдаёт вес уровня для сортировки (больше = важнее). Неизвестный уровень —
// 0, то есть уезжает в конец списка, а не в начало.
func Rank(s Severity) int { return rank[s] }

// TypeRank отдаёт позицию типа внутри его уровня критичности; неизвестные типы
// получают вес больше всех известных и сортируются в конце своей секции по
// алфавиту (порядок доопределяет вызывающий).
func TypeRank(alertType string) int {
	t := strings.ToLower(strings.TrimSpace(alertType))
	for i, known := range typeOrder {
		if known == t {
			return i
		}
	}
	return len(typeOrder)
}

// All возвращает уровни от самого важного к наименее важному — для валидации,
// выпадающих списков и тестов.
func All() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
}

// Label — человекочитаемое название уровня для уведомлений. Живёт здесь, а не в
// notifier: тем же словарём пользуется эскалация, и два независимых перевода
// одного и того же уровня в разных сообщениях читались бы как разные вещи.
func Label(s Severity) string {
	switch s {
	case SeverityCritical:
		return "критично"
	case SeverityHigh:
		return "высокая"
	case SeverityMedium:
		return "средняя"
	case SeverityLow:
		return "низкая"
	default:
		return string(s)
	}
}

// Emoji — маркер уровня в начале сообщения Telegram. Оператор видит ленту
// уведомлений в телефоне и разбирает её взглядом, а не чтением: маркер должен
// различаться по форме, а не только по цвету.
func Emoji(s Severity) string {
	switch s {
	case SeverityCritical:
		return "🛑"
	case SeverityHigh:
		return "🚨"
	case SeverityMedium:
		return "⚠️"
	case SeverityLow:
		return "ℹ️"
	default:
		return "🚨"
	}
}
