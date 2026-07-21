package inventory

import (
	"testing"

	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func report(ram int64, sw ...*pb.SoftwareItem) *pb.InventoryReport {
	return &pb.InventoryReport{
		DeviceInfo: &pb.DeviceInfo{Hostname: "h", Os: "macOS", Ram: ram},
		Software:   sw,
	}
}

func mustHash(t *testing.T, r *pb.InventoryReport) string {
	t.Helper()
	h, err := hashReport(r)
	if err != nil {
		t.Fatalf("hashReport: %v", err)
	}
	return h
}

func TestHashReportStable(t *testing.T) {
	r := report(16, &pb.SoftwareItem{SoftwareName: "a", Version: "1"})
	h1, h2 := mustHash(t, r), mustHash(t, r)
	if h1 != h2 {
		t.Fatal("хэш нестабилен на одном входе")
	}
}

func TestHashReportOrderIndependent(t *testing.T) {
	a := &pb.SoftwareItem{SoftwareName: "a", Version: "1"}
	b := &pb.SoftwareItem{SoftwareName: "b", Version: "2"}
	if mustHash(t, report(16, a, b)) != mustHash(t, report(16, b, a)) {
		t.Fatal("порядок ПО не должен влиять на хэш")
	}
}

func TestHashReportChangesOnDiff(t *testing.T) {
	base := report(16, &pb.SoftwareItem{SoftwareName: "a", Version: "1"})
	if mustHash(t, base) == mustHash(t, report(32, &pb.SoftwareItem{SoftwareName: "a", Version: "1"})) {
		t.Fatal("изменение RAM должно менять хэш")
	}
	if mustHash(t, base) == mustHash(t, report(16, &pb.SoftwareItem{SoftwareName: "a", Version: "2"})) {
		t.Fatal("изменение версии ПО должно менять хэш")
	}
}

// После self-update версия агента меняется даже если прочий снимок тот же —
// хэш обязан отличаться, иначе новая версия не доедет до сервера.
func TestHashReportChangesOnAgentVersion(t *testing.T) {
	base := report(16)
	bumped := report(16)
	bumped.DeviceInfo.AgentVersion = "2.0.0"
	if mustHash(t, base) == mustHash(t, bumped) {
		t.Fatal("изменение версии агента должно менять хэш")
	}
}

// setNonZero проставляет полю заведомо ненулевое значение своего типа. Новый
// тип поля в DeviceInfo/SoftwareItem без ветки здесь валит тест с подсказкой —
// расширение switch дешевле молчаливо непокрытого поля.
func setNonZero(t *testing.T, m protoreflect.Message, fd protoreflect.FieldDescriptor) {
	t.Helper()
	if fd.IsList() || fd.IsMap() {
		t.Fatalf("поле %s: repeated/map в DeviceInfo не ожидалось — расширь setNonZero", fd.Name())
	}
	switch fd.Kind() {
	case protoreflect.StringKind:
		m.Set(fd, protoreflect.ValueOfString("probe"))
	case protoreflect.BoolKind:
		m.Set(fd, protoreflect.ValueOfBool(true))
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		m.Set(fd, protoreflect.ValueOfInt32(7))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		m.Set(fd, protoreflect.ValueOfInt64(7))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		m.Set(fd, protoreflect.ValueOfUint32(7))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		m.Set(fd, protoreflect.ValueOfUint64(7))
	case protoreflect.EnumKind:
		m.Set(fd, protoreflect.ValueOfEnum(1))
	case protoreflect.BytesKind:
		m.Set(fd, protoreflect.ValueOfBytes([]byte{1}))
	default:
		t.Fatalf("поле %s: тип %s не покрыт setNonZero — расширь switch", fd.Name(), fd.Kind())
	}
}

// Страж мины ручного перечисления: КАЖДОЕ поле DeviceInfo обязано влиять на
// хэш. Идёт по proto-дескриптору, а не по фиксированному списку — новое поле
// покрывается автоматически, без правки теста.
func TestHashReport_CoversEveryDeviceInfoField(t *testing.T) {
	baseHash := mustHash(t, &pb.InventoryReport{DeviceInfo: &pb.DeviceInfo{}})

	fields := (&pb.DeviceInfo{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		r := &pb.InventoryReport{DeviceInfo: &pb.DeviceInfo{}}
		setNonZero(t, r.DeviceInfo.ProtoReflect(), fd)
		if mustHash(t, r) == baseHash {
			t.Errorf("поле DeviceInfo.%s не влияет на hashReport — поле застынет после первой отправки", fd.Name())
		}
	}
}

// То же для SoftwareItem: новое поле записи ПО тоже обязано попадать в хэш.
func TestHashReport_CoversEverySoftwareItemField(t *testing.T) {
	baseHash := mustHash(t, &pb.InventoryReport{Software: []*pb.SoftwareItem{{}}})

	fields := (&pb.SoftwareItem{}).ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		item := &pb.SoftwareItem{}
		setNonZero(t, item.ProtoReflect(), fd)
		if mustHash(t, &pb.InventoryReport{Software: []*pb.SoftwareItem{item}}) == baseHash {
			t.Errorf("поле SoftwareItem.%s не влияет на hashReport", fd.Name())
		}
	}
}

// Невалидный UTF-8 в строковом поле — единственный реалистичный отказ
// маршалинга; hashReport обязан вернуть ошибку, а не тихий пустой хэш.
func TestHashReport_InvalidUTF8ReturnsError(t *testing.T) {
	r := &pb.InventoryReport{DeviceInfo: &pb.DeviceInfo{Hostname: string([]byte{0xff, 0xfe})}}
	if _, err := hashReport(r); err == nil {
		t.Fatal("ожидалась ошибка маршалинга на невалидном UTF-8")
	}
}
