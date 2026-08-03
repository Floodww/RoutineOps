package selfupdate

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// holdFixture — Updater с подменёнными сеймами: манифест всегда новее, скачивание и
// замена только считают вызовы. Проверяем ОДНО: доходит ли дело до замены бинаря.
type holdFixture struct {
	u         *Updater
	downloads int
	replaces  int
	releases  int
	now       time.Time
	holding   bool
	what      string
}

func newHoldFixture(t *testing.T) *holdFixture {
	t.Helper()
	f := &holdFixture{now: time.Unix(1700000000, 0), what: "интерактивный сеанс 7f3a"}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	f.u = &Updater{
		current: "1.0.0",
		pubKey:  pub,
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		nowFn:   func() time.Time { return f.now },
	}
	f.u.check = func(ctx context.Context) (*Manifest, error) {
		return &Manifest{Version: "1.1.0", URL: "https://example.invalid/agent"}, nil
	}
	f.u.download = func(ctx context.Context, url string) ([]byte, error) {
		f.downloads++
		return []byte("binary"), nil
	}
	f.u.replace = func([]byte) error { f.replaces++; return nil }
	return f
}

func (f *holdFixture) withHold(cap, grace time.Duration) {
	f.u.SetHold(Hold{
		Active:  func() (bool, string) { return f.holding, f.what },
		Release: func() { f.releases++ },
		Cap:     cap,
		Grace:   grace,
		// Опрос частый: тест на штатное завершение не должен идти секундами.
		Poll: time.Millisecond,
	})
}

// verify() отклонит наш фейковый бинарь — до replace дело не дойдёт в любом случае.
// Поэтому «применили» проверяем по факту СКАЧИВАНИЯ: гейт стоит до него, и это
// единственное, что нас здесь интересует.
func (f *holdFixture) apply(t *testing.T) error {
	t.Helper()
	return f.u.checkAndApply(context.Background())
}

func TestHold_ActiveSessionBlocksDownloadAndReplace(t *testing.T) {
	f := newHoldFixture(t)
	f.withHold(DefaultHoldCap, DefaultHoldGrace)
	f.holding = true

	err := f.apply(t)
	if !errors.Is(err, ErrDeferred) {
		t.Fatalf("ошибка = %v, want ErrDeferred", err)
	}
	if !strings.Contains(err.Error(), "7f3a") {
		t.Errorf("в причине нет описания работы: %v", err)
	}
	// Скачивания быть не должно вовсе: 20 МБ по тому же каналу, по которому идёт сеанс,
	// превращают его в слайд-шоу ещё до всякой замены exe.
	if f.downloads != 0 {
		t.Errorf("скачиваний %d при активном сеансе, want 0", f.downloads)
	}
	if f.replaces != 0 {
		t.Errorf("замен бинаря %d при активном сеансе, want 0", f.replaces)
	}
	if f.releases != 0 {
		t.Errorf("просьб завершить %d до исчерпания потолка, want 0", f.releases)
	}
}

func TestHold_NoSessionLetsUpdateThrough(t *testing.T) {
	// Обратная сторона: без активной работы гейт обязан быть прозрачным, иначе
	// обновления встанут на всём парке.
	f := newHoldFixture(t)
	f.withHold(DefaultHoldCap, DefaultHoldGrace)
	f.holding = false

	err := f.apply(t)
	if errors.Is(err, ErrDeferred) {
		t.Fatalf("обновление отложено без активной работы: %v", err)
	}
	if f.downloads != 1 {
		t.Errorf("скачиваний %d, want 1", f.downloads)
	}
}

func TestHold_AbsentGateIsTransparent(t *testing.T) {
	f := newHoldFixture(t)
	f.holding = true // гейт не подключён — держать некому

	if err := f.apply(t); errors.Is(err, ErrDeferred) {
		t.Fatalf("отложено без подключённого гейта: %v", err)
	}
	if f.downloads != 1 {
		t.Errorf("скачиваний %d, want 1", f.downloads)
	}
}

func TestHold_CapExhaustedAsksGracefulRelease(t *testing.T) {
	// Потолок исчерпан → просим завершить ШТАТНО. Сеанс, завершившийся по этой просьбе,
	// оставляет запись, событие AGENT_UPDATE и строку аудита; TerminateProcess не
	// оставляет ничего.
	f := newHoldFixture(t)
	f.withHold(10*time.Minute, 3*time.Second)
	f.holding = true

	if err := f.apply(t); !errors.Is(err, ErrDeferred) {
		t.Fatalf("первая проверка: %v", err)
	}
	if f.releases != 0 {
		t.Fatalf("просьба завершить отправлена до исчерпания потолка")
	}

	// Прошло больше потолка, сеанс всё тот же.
	f.now = f.now.Add(11 * time.Minute)
	// Сеанс закрывается по просьбе: со второго опроса Active говорит «свободно».
	calls := 0
	f.u.hold.Active = func() (bool, string) {
		calls++
		return calls <= 1, f.what
	}

	if err := f.apply(t); err != nil && errors.Is(err, ErrDeferred) {
		t.Fatalf("после штатного завершения обновление всё ещё отложено: %v", err)
	}
	if f.releases != 1 {
		t.Errorf("просьб завершить %d, want 1", f.releases)
	}
	if f.downloads != 1 {
		t.Errorf("скачиваний %d, want 1 — после освобождения обновление обязано пойти", f.downloads)
	}
}

func TestHold_StubbornWorkIsNotKilled(t *testing.T) {
	// Работа не завершилась даже после просьбы и grace. Обновление откладывается до
	// следующей проверки, но НЕ применяется силой: убить процесс, который пишет запись
	// сеанса, хуже, чем поставить релиз на несколько часов позже.
	f := newHoldFixture(t)
	f.withHold(time.Minute, 20*time.Millisecond)
	f.holding = true

	_ = f.apply(t)
	f.now = f.now.Add(2 * time.Minute)

	err := f.apply(t)
	if !errors.Is(err, ErrDeferred) {
		t.Fatalf("ошибка = %v, want ErrDeferred", err)
	}
	if f.releases != 1 {
		t.Errorf("просьб завершить %d, want 1", f.releases)
	}
	if f.downloads != 0 || f.replaces != 0 {
		t.Errorf("обновление применено силой поверх незавершённой работы: скачиваний %d, замен %d",
			f.downloads, f.replaces)
	}
}

func TestHold_ReleaseAskedOncePerWork(t *testing.T) {
	// Повторные просьбы уже закрывающемуся сеансу — это шум, который в логе выглядит
	// как «агент долбится», и на который перестают смотреть.
	f := newHoldFixture(t)
	f.withHold(time.Minute, 5*time.Millisecond)
	f.holding = true

	_ = f.apply(t)
	f.now = f.now.Add(2 * time.Minute)
	_ = f.apply(t)
	f.now = f.now.Add(2 * time.Minute)
	_ = f.apply(t)

	if f.releases != 1 {
		t.Errorf("просьб завершить %d, want 1 на одну работу", f.releases)
	}
}

func TestHold_NewWorkResetsDeferralClock(t *testing.T) {
	// Ключевое требование к описанию работы: оно идентифицирует КОНКРЕТНЫЙ сеанс.
	//
	// Проверки идут раз в несколько часов, и между ними гейт не видит промежутка, когда
	// не держал никто. Если считать отсрочку по одному лишь факту «держат», два разных
	// сеанса на двух соседних проверках выглядят как одна непрерывная задержка — и
	// второй сеанс закроют за грехи первого, хотя он начался минуту назад.
	f := newHoldFixture(t)
	f.withHold(30*time.Minute, 5*time.Millisecond)
	f.holding = true
	f.what = "интерактивный сеанс AAAA"

	if err := f.apply(t); !errors.Is(err, ErrDeferred) {
		t.Fatalf("первая проверка: %v", err)
	}

	// Спустя час — но это уже ДРУГОЙ сеанс.
	f.now = f.now.Add(time.Hour)
	f.what = "интерактивный сеанс BBBB"
	if err := f.apply(t); !errors.Is(err, ErrDeferred) {
		t.Fatalf("вторая проверка: %v", err)
	}
	if f.releases != 0 {
		t.Errorf("новый сеанс закрыт за грехи предыдущего: просьб завершить %d, want 0", f.releases)
	}
}

func TestTaskkillArgs_ExcludesSelfAndProtected(t *testing.T) {
	// Фильтры /FI соединяются логическим И, поэтому каждый исключаемый PID — отдельный
	// фильтр. Проверяем ровно то, что уйдёт в командную строку.
	got := taskkillArgs("routineops-agent.exe", 100, []int{250, 250, 0, -3, 100, 180})
	want := []string{
		"/F", "/IM", "routineops-agent.exe",
		"/FI", "PID ne 100",
		"/FI", "PID ne 180",
		"/FI", "PID ne 250",
	}
	if len(got) != len(want) {
		t.Fatalf("аргументы = %q\nwant %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("аргументы = %q\nwant %q", got, want)
		}
	}
}

func TestTaskkillArgs_NoProtectedKeepsOldBehaviour(t *testing.T) {
	// Без захватчика команда обязана остаться ровно той, что чинила блокировку .old
	// треем в полевом баге v2.2.x — иначе починим одно и сломаем другое.
	got := taskkillArgs("routineops-agent.exe", 42, nil)
	want := []string{"/F", "/IM", "routineops-agent.exe", "/FI", "PID ne 42"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("аргументы = %q, want %q", got, want)
	}
}

func TestProtectedPIDs_SourceIsOptional(t *testing.T) {
	t.Cleanup(func() { SetProtectedPIDs(nil) })

	if got := protectedPIDs(); got != nil {
		t.Errorf("без источника = %v, want nil", got)
	}
	SetProtectedPIDs(func() []int { return []int{7} })
	if got := protectedPIDs(); len(got) != 1 || got[0] != 7 {
		t.Errorf("с источником = %v, want [7]", got)
	}
}
