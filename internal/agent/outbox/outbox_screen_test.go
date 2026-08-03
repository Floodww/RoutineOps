package outbox

import (
	"strings"
	"testing"
	"time"
)

// Классификация вытеснения обязана быть ПОЛНОЙ, а не «по умолчанию protected».
//
// §9.20 контракта удалённого стола: любой не перечисленный в isEvictableFirst вид молча
// считается protected, а при переполнении protected вытесняются по FIFO — то есть новый
// вид телеметрии, добавленный без правки списка, начинает выдавливать ИБ-алерты. Молча.
//
// Тест не проверяет «правильность» класса — её знает только автор вида. Он проверяет, что
// решение ПРИНЯТО осознанно: каждый вид из AllKinds назван в одном из двух списков ниже.
// Забыть добавить вид сюда невозможно — тест сравнивает объединение списков с AllKinds.
func TestEvictionClassOfEveryKind(t *testing.T) {
	evictable := map[string]bool{
		KindScript:          true, // серверная компенсация есть
		KindTask:            true, // late_task_result
		KindAdminChanges:    true, // окна улик кумулятивны
		KindScreenTelemetry: true, // счётчики сеанса кумулятивны
	}
	protected := map[string]bool{
		KindSecurity:      true, // ИБ-алерт невосстановим
		KindAdmin:         true, // аудит выданных прав
		KindLock:          true, // статус лока: потеря пере-запирает устройство
		KindScreenSession: true, // исход сеанса: без него аудит без ответа «чем кончилось»
	}

	for _, kind := range AllKinds {
		inE, inP := evictable[kind], protected[kind]
		switch {
		case inE && inP:
			t.Errorf("вид %q числится в обоих списках", kind)
		case !inE && !inP:
			t.Errorf("вид %q не классифицирован: решите явно, вытесняется он первым или последним, "+
				"иначе он молча станет protected и начнёт выдавливать ИБ-алерты (§9.20)", kind)
		case inE != isEvictableFirst(kind):
			t.Errorf("вид %q: ожидали evictable=%v, isEvictableFirst даёт %v", kind, inE, isEvictableFirst(kind))
		}
	}

	// Обратная сторона: в списках нет видов, которых больше нет в AllKinds — иначе
	// удалённый вид оставит зелёную строку, которая ничего не сторожит.
	all := map[string]bool{}
	for _, k := range AllKinds {
		all[k] = true
	}
	for _, m := range []map[string]bool{evictable, protected} {
		for k := range m {
			if !all[k] {
				t.Errorf("вид %q классифицирован, но отсутствует в AllKinds", k)
			}
		}
	}
}

// Имя вида обязано доживать до имени файла неискажённым.
//
// sanitize заменяет дефис на подчёркивание, а fileKind вытаскивает вид из имени файла
// разбором по дефисам (<unixnano>-<seq>-<kind>.json). Вид с дефисом в имени превратился бы
// в неузнаваемый — и запись потеряла бы свой класс вытеснения молча. На этом уже
// наступали с admin_changes; screen_session и screen_telemetry названы так же осознанно.
func TestScreenKindsSurviveFileNaming(t *testing.T) {
	for _, kind := range AllKinds {
		if strings.ContainsAny(kind, "-/\\.") {
			t.Errorf("вид %q содержит символ, который sanitize исказит — класс вытеснения потеряется", kind)
		}
	}

	dir := t.TempDir()
	q, err := New(dir, 10, time.Hour, discardLog(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{KindScreenSession, KindScreenTelemetry} {
		if err := q.Enqueue(kind, []byte(`{"session":"7f3a"}`)); err != nil {
			t.Fatalf("постановка %s: %v", kind, err)
		}
	}
	files, err := q.list()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		seen[fileKind(f)] = true
	}
	for _, kind := range []string{KindScreenSession, KindScreenTelemetry} {
		if !seen[kind] {
			t.Errorf("вид %q не вычитывается из имени файла: %v", kind, files)
		}
	}
}

// Телеметрия сеанса не имеет права выдавить исход сеанса.
//
// Кадры и байты кумулятивны — потеря стоит дырки в графике. Терминальное событие
// невосстановимо: без него в аудите остаётся сеанс без ответа на вопрос «чем кончилось»,
// и это ровно тот случай, ради которого класс вытеснения вообще существует.
func TestScreenTelemetryEvictedBeforeSessionOutcome(t *testing.T) {
	dir := t.TempDir()
	q, err := New(dir, 2, time.Hour, discardLog(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := q.Enqueue(KindScreenTelemetry, []byte(`{"frames":100}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Enqueue(KindScreenSession, []byte(`{"reason":"USER_TERMINATED"}`)); err != nil {
		t.Fatalf("исход сеанса не встал в очередь, забитую телеметрией: %v", err)
	}
	files, err := q.list()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range files {
		if fileKind(f) == KindScreenSession {
			found = true
		}
	}
	if !found {
		t.Fatalf("исход сеанса вытеснен собственной телеметрией: %v", files)
	}

	// И обратно: телеметрия в очередь, забитую ИБ-событиями, не лезет — иначе поток
	// счётчиков сеанса выдавит алерты, а это тот самый сценарий §9.20.
	dir2 := t.TempDir()
	q2, err := New(dir2, 1, time.Hour, discardLog(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := q2.Enqueue(KindSecurity, []byte("alert")); err != nil {
		t.Fatal(err)
	}
	if err := q2.Enqueue(KindScreenTelemetry, []byte(`{"frames":1}`)); err == nil {
		t.Error("телеметрия сеанса встала в очередь, забитую ИБ-событиями — значит выдавила алерт")
	}
	files2, err := q2.list()
	if err != nil {
		t.Fatal(err)
	}
	if len(files2) != 1 || fileKind(files2[0]) != KindSecurity {
		t.Errorf("в очереди %v, ожидался только ИБ-алерт", files2)
	}
}
