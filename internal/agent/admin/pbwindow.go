package admin

import (
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
	pb "github.com/Floodww/RoutineOps/proto"
)

// Перевод окна улик на провод.
//
// Сборка окна (window.go) намеренно не знает про proto: её решения — полнота,
// урезание, деградация — проверяются табличными тестами без кодогенерации. Весь
// контакт с проводом собран здесь, в одном месте, и здесь же живёт правило
// перевода строковых словарей агента в enum'ы контракта.
//
// Словари совпадают по написанию: "software_installed" ↔
// ADMIN_CHANGE_KIND_SOFTWARE_INSTALLED. Совпадение НЕ используется как алгоритм
// (сборка имени строкой): такой перевод молча выдумал бы значение для любой
// будущей константы агента, а на сервере оно превратилось бы в UNSPECIFIED уже
// после записи в улики. Явный switch, наоборот, заставляет добавить строку сюда
// и роняет тест полноты словаря (pbwindow_test.go), если о ней забыли.

// windowToProto собирает запрос по окну улик.
func windowToProto(w Window) *pb.ReportAdminSessionChangesRequest {
	changes := make([]*pb.AdminSessionChange, 0, len(w.Changes))
	for _, c := range w.Changes {
		changes = append(changes, &pb.AdminSessionChange{
			Kind:              changeKindToProto(c.Kind),
			Subject:           c.Subject,
			DisplayName:       c.DisplayName,
			IdentityKey:       c.IdentityKey,
			OldValue:          c.OldValue,
			NewValue:          c.NewValue,
			Vendor:            c.Vendor,
			Scope:             c.Scope,
			Attribution:       attributionToProto(c.Attribution),
			AttributionReason: c.AttributionReason,
			ObservedAt:        unixOrZero(c.ObservedAt),
		})
	}
	return &pb.ReportAdminSessionChangesRequest{
		RequestId:      w.RequestID,
		WindowSeq:      w.Seq,
		WindowStart:    unixOrZero(w.WindowStart),
		WindowEnd:      unixOrZero(w.WindowEnd),
		Changes:        changes,
		Final:          w.Final,
		Truncated:      w.Truncated,
		TotalChanges:   w.TotalChanges,
		Rebooted:       w.Rebooted,
		BaselineLost:   w.BaselineLost,
		SoftwareHealth: healthToProto(w.SoftwareHealth),
		ServicesHealth: healthToProto(w.ServicesHealth),
		Completeness:   completenessToProto(w.Completeness),
		SnapshotAt:     unixOrZero(w.SnapshotAt),
	}
}

// unixOrZero — нулевое время уезжает нулём, а не unix-меткой нулевого time.Time
// (это год 1 нашей эры, то есть −62135596800). Сервер читает 0 как «не указано»
// и подставляет своё время приёма; отрицательная метка так не читается нигде и
// заехала бы в улики датой из первого века.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func changeKindToProto(k string) pb.AdminChangeKind {
	switch k {
	case ChangeSoftwareInstalled:
		return pb.AdminChangeKind_ADMIN_CHANGE_KIND_SOFTWARE_INSTALLED
	case ChangeSoftwareRemoved:
		return pb.AdminChangeKind_ADMIN_CHANGE_KIND_SOFTWARE_REMOVED
	case ChangeSoftwareUpdated:
		return pb.AdminChangeKind_ADMIN_CHANGE_KIND_SOFTWARE_UPDATED
	case ChangeServiceInstalled:
		return pb.AdminChangeKind_ADMIN_CHANGE_KIND_SERVICE_INSTALLED
	case ChangeServiceRemoved:
		return pb.AdminChangeKind_ADMIN_CHANGE_KIND_SERVICE_REMOVED
	case ChangeServiceStartTypeChange:
		return pb.AdminChangeKind_ADMIN_CHANGE_KIND_SERVICE_START_TYPE_CHANGED
	case ChangeServiceAccountChange:
		return pb.AdminChangeKind_ADMIN_CHANGE_KIND_SERVICE_ACCOUNT_CHANGED
	case ChangeServiceDefChange:
		return pb.AdminChangeKind_ADMIN_CHANGE_KIND_SERVICE_DEFINITION_CHANGED
	default:
		return pb.AdminChangeKind_ADMIN_CHANGE_KIND_UNSPECIFIED
	}
}

// attributionToProto — неизвестное значение уезжает ЯВНЫМ UNKNOWN, а не
// UNSPECIFIED. Разница смысловая, а не оформительская: UNSPECIFIED — это «поля
// не было», и сервер вправе прочитать его как «старый агент», тогда как здесь
// агент точно знает, что атрибуцию не определил. Обвинительная сторона словаря
// (human_likely) никогда не должна получаться по умолчанию — ни из пустой
// строки, ни из будущей константы, забытой в этом switch.
func attributionToProto(a string) pb.ChangeAttribution {
	switch a {
	case AttrHumanLikely:
		return pb.ChangeAttribution_CHANGE_ATTRIBUTION_HUMAN_LIKELY
	case AttrBackgroundLikely:
		return pb.ChangeAttribution_CHANGE_ATTRIBUTION_BACKGROUND_LIKELY
	default:
		return pb.ChangeAttribution_CHANGE_ATTRIBUTION_UNKNOWN
	}
}

// healthToProto — пустое здоровье это UNSPECIFIED, а не OK. Пустым оно бывает у
// состояния сессии, записанного версией агента без этого поля; выдать его за
// «источник здоров» значит задним числом объявить достоверной дельту, о качестве
// сбора которой ничего не известно.
func healthToProto(h string) pb.CollectionHealth {
	switch h {
	case string(collector.HealthOK):
		return pb.CollectionHealth_COLLECTION_HEALTH_OK
	case string(collector.HealthPartial):
		return pb.CollectionHealth_COLLECTION_HEALTH_PARTIAL
	case string(collector.HealthFailed):
		return pb.CollectionHealth_COLLECTION_HEALTH_FAILED
	case string(collector.HealthUnsupported):
		return pb.CollectionHealth_COLLECTION_HEALTH_UNSUPPORTED
	default:
		return pb.CollectionHealth_COLLECTION_HEALTH_UNSPECIFIED
	}
}

func completenessToProto(c string) pb.EvidenceCompleteness {
	switch c {
	case CompletenessComplete:
		return pb.EvidenceCompleteness_EVIDENCE_COMPLETENESS_COMPLETE
	case CompletenessNoBaseline:
		return pb.EvidenceCompleteness_EVIDENCE_COMPLETENESS_NO_BASELINE
	case CompletenessPartial:
		return pb.EvidenceCompleteness_EVIDENCE_COMPLETENESS_PARTIAL
	case CompletenessTruncated:
		return pb.EvidenceCompleteness_EVIDENCE_COMPLETENESS_TRUNCATED
	case CompletenessStaleFinal:
		return pb.EvidenceCompleteness_EVIDENCE_COMPLETENESS_STALE_FINAL
	default:
		return pb.EvidenceCompleteness_EVIDENCE_COMPLETENESS_UNSPECIFIED
	}
}
