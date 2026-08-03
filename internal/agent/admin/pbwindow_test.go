package admin

import (
	"strings"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// fullWindow — окно, у которого заполнено ВСЁ: каждое поле ненулевое, включая
// булевы. Нужен ровно для проверки «ни одно поле не потерялось по дороге».
func fullWindow() Window {
	t0 := time.Unix(1_700_000_000, 0)
	return Window{
		RequestID:    "req-1",
		Seq:          7,
		WindowStart:  t0,
		WindowEnd:    t0.Add(time.Hour),
		SnapshotAt:   t0.Add(2 * time.Hour),
		Final:        true,
		Truncated:    true,
		TotalChanges: 3,
		Rebooted:     true,
		BaselineLost: true,
		// Здоровье не ok намеренно: ok — нулевое значение только на словах, а в
		// enum'е ему соответствует ненулевой COLLECTION_HEALTH_OK, и подмена
		// одного другим на этом тесте не всплыла бы.
		SoftwareHealth: string(collector.HealthPartial),
		ServicesHealth: string(collector.HealthFailed),
		Completeness:   CompletenessTruncated,
		Changes: []Change{{
			Kind:              ChangeSoftwareUpdated,
			Subject:           "Some App",
			DisplayName:       "Some App 2.0",
			IdentityKey:       "some app|vendor",
			OldValue:          "1.0",
			NewValue:          "2.0",
			Vendor:            "Vendor",
			Scope:             "user",
			Attribution:       AttrHumanLikely,
			AttributionReason: ReasonNewProduct,
			ObservedAt:        t0.Add(30 * time.Minute),
		}},
	}
}

// Каждое поле запроса и каждое поле записи дельты заполняется конвертером.
//
// Тест держит ровно ту ошибку, которую иначе не поймает ничто: поле добавили в
// Window и в proto, а в windowToProto забыли — улики уезжают молча неполными,
// сборка зелёная, сервер пишет нули. Проверка идёт по дескриптору сообщения, а
// не по списку в тесте, поэтому новое поле контракта роняет её автоматически.
func TestWindowToProtoCarriesEveryField(t *testing.T) {
	req := windowToProto(fullWindow())

	assertAllFieldsSet(t, "ReportAdminSessionChangesRequest", req.ProtoReflect())
	if len(req.GetChanges()) != 1 {
		t.Fatalf("ожидали одну запись дельты, got %d", len(req.GetChanges()))
	}
	assertAllFieldsSet(t, "AdminSessionChange", req.GetChanges()[0].ProtoReflect())
}

func assertAllFieldsSet(t *testing.T, name string, m protoreflect.Message) {
	t.Helper()
	set := make(map[string]bool)
	m.Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		set[string(fd.Name())] = true
		return true
	})
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		if fname := string(fields.Get(i).Name()); !set[fname] {
			t.Errorf("%s: поле %q осталось нулевым — конвертер его не заполняет", name, fname)
		}
	}
}

// Словари агента и сервера читают одни и те же значения.
//
// Агент хранит вид/атрибуцию/здоровье/полноту строками, сервер восстанавливает
// строку из имени enum'а (internal/server/gateway/admin_session.go: TrimPrefix +
// ToLower). Правило сервера здесь воспроизведено намеренно, а не импортировано:
// агентский пакет не должен зависеть от серверного, а сломаться тест обязан,
// даже если разъедется только одна сторона. Расхождение означает улики,
// записанные под другим именем вида, — их не найдёт ни фильтр, ни оператор.
func TestDictionariesRoundTripThroughProto(t *testing.T) {
	for _, k := range []string{
		ChangeSoftwareInstalled, ChangeSoftwareRemoved, ChangeSoftwareUpdated,
		ChangeServiceInstalled, ChangeServiceRemoved, ChangeServiceStartTypeChange,
		ChangeServiceAccountChange, ChangeServiceDefChange,
	} {
		e := changeKindToProto(k)
		if e == pb.AdminChangeKind_ADMIN_CHANGE_KIND_UNSPECIFIED {
			t.Errorf("вид %q не переведён в enum", k)
			continue
		}
		if got := serverName(e.String(), "ADMIN_CHANGE_KIND_"); got != k {
			t.Errorf("вид %q сервер прочитает как %q", k, got)
		}
	}

	for _, a := range []string{AttrHumanLikely, AttrBackgroundLikely, AttrUnknown} {
		if got := serverName(attributionToProto(a).String(), "CHANGE_ATTRIBUTION_"); got != a {
			t.Errorf("атрибуция %q сервер прочитает как %q", a, got)
		}
	}

	for _, h := range []collector.Health{
		collector.HealthOK, collector.HealthPartial, collector.HealthFailed, collector.HealthUnsupported,
	} {
		e := healthToProto(string(h))
		if e == pb.CollectionHealth_COLLECTION_HEALTH_UNSPECIFIED {
			t.Errorf("здоровье %q не переведено в enum", h)
			continue
		}
		if got := serverName(e.String(), "COLLECTION_HEALTH_"); got != string(h) {
			t.Errorf("здоровье %q сервер прочитает как %q", h, got)
		}
	}

	for _, c := range []string{
		CompletenessComplete, CompletenessNoBaseline, CompletenessPartial,
		CompletenessTruncated, CompletenessStaleFinal,
	} {
		e := completenessToProto(c)
		if e == pb.EvidenceCompleteness_EVIDENCE_COMPLETENESS_UNSPECIFIED {
			t.Errorf("полнота %q не переведена в enum", c)
			continue
		}
		if got := serverName(e.String(), "EVIDENCE_COMPLETENESS_"); got != c {
			t.Errorf("полнота %q сервер прочитает как %q", c, got)
		}
	}
}

func serverName(enumName, prefix string) string {
	return strings.ToLower(strings.TrimPrefix(enumName, prefix))
}

// Неизвестная атрибуция уезжает явным UNKNOWN и никогда — обвинением.
//
// Значение атрибуции сочиняет агент, работающий на машине подотчётного, и
// попадает в интерфейс как ключ сортировки «на что смотреть первым». Значение,
// которого нет в словаре (битое состояние, будущая константа, забытая в
// switch), обязано читаться как «не знаем», а не как «сделал человек».
func TestUnknownAttributionNeverAccuses(t *testing.T) {
	for _, a := range []string{"", "future_value", "HUMAN_LIKELY", "human likely"} {
		if got := attributionToProto(a); got != pb.ChangeAttribution_CHANGE_ATTRIBUTION_UNKNOWN {
			t.Errorf("атрибуция %q переведена как %v, ожидали UNKNOWN", a, got)
		}
	}
}

// Пустое здоровье не выдаётся за «источник в порядке».
//
// Пустым оно бывает у состояния сессии, записанного версией агента без этого
// поля. Перевод в OK задним числом объявил бы дельту достоверной, хотя о
// качестве сбора не известно ничего.
func TestEmptyHealthIsUnspecifiedNotOK(t *testing.T) {
	if got := healthToProto(""); got != pb.CollectionHealth_COLLECTION_HEALTH_UNSPECIFIED {
		t.Fatalf("пустое здоровье переведено как %v, ожидали UNSPECIFIED", got)
	}
}

// Нулевое время уезжает нулём, а не unix-меткой нулевого time.Time.
//
// time.Time{}.Unix() — это −62135596800, дата из первого века. Сервер читает 0
// как «не указано» и подставляет своё время приёма; отрицательная метка так не
// читается нигде и осела бы в уликах как реальная дата наблюдения.
func TestZeroTimeGoesAsZero(t *testing.T) {
	w := fullWindow()
	w.WindowStart = time.Time{}
	w.Changes[0].ObservedAt = time.Time{}

	req := windowToProto(w)
	if req.GetWindowStart() != 0 {
		t.Errorf("нулевое window_start уехало как %d", req.GetWindowStart())
	}
	if got := req.GetChanges()[0].GetObservedAt(); got != 0 {
		t.Errorf("нулевое observed_at уехало как %d", got)
	}
}
