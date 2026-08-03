//go:build windows

package collector

import (
	"testing"
	"time"
)

// Живой прогон среза служб на настоящей Windows. Кросс-компиляцией эти вещи не
// проверяются вовсе: обход реестра, отсев подключей без Start, стабильность
// снимка между вызовами.
//
// Собирается и возится на бокс отдельно:
//   GOOS=windows GOARCH=amd64 go test -c ./internal/agent/collector/ -o services.test.exe
//   scp services.test.exe work:C:/Temp/ && ssh work 'C:/Temp/services.test.exe -test.run Windows -test.v'

func TestWindowsServicesSnapshotSane(t *testing.T) {
	start := time.Now()
	svcs, health := Services()
	elapsed := time.Since(start)

	t.Logf("снимок: %d служб за %s, здоровье=%s", len(svcs), elapsed, health)
	if health == HealthFailed {
		t.Fatal("снимок служб не снялся — обход реестра не отработал")
	}
	// На любой живой Windows служб сотни. Пустой или крошечный снимок означает,
	// что обход отвалился молча, а для аудита это худший исход: дельта сессии
	// показала бы «служб не появлялось» вместо «мы не смогли посмотреть».
	if len(svcs) < 50 {
		t.Fatalf("подозрительно мало служб (%d) — обход реестра, похоже, оборвался", len(svcs))
	}

	var drivers, osOwned, noHash, noStart int
	for _, s := range svcs {
		if s.Kind == KindDriver {
			drivers++
		}
		if s.OSOwned {
			osOwned++
		}
		if s.DefHash == "" {
			noHash++
		}
		if s.StartType == StartTypeUnknown {
			noStart++
		}
	}
	t.Logf("драйверов=%d системных=%d без хэша=%d без режима запуска=%d", drivers, osOwned, noHash, noStart)

	if noHash > 0 {
		t.Errorf("%d служб без DefHash — их подмена была бы невидима", noHash)
	}
	// Системные службы обязаны составлять заметную долю: если OSOwned не
	// определяется, вся атрибуция схлопнется в «человек» и карточка заявки
	// превратится в сплошное ложное обвинение.
	if osOwned*4 < len(svcs) {
		t.Errorf("системными признаны лишь %d из %d — проверь префиксы путей", osOwned, len(svcs))
	}
	if drivers == 0 {
		t.Error("не найдено ни одного драйвера ядра — Type из реестра, похоже, не читается")
	}
}

// Главная проверка инварианта на живой машине: два снимка подряд обязаны быть
// идентичны. Любое волатильное поле, просочившееся в срез, всплывёт здесь —
// а в поле оно дало бы ложную дельту на каждом окне сессии по всему парку.
func TestWindowsServicesSnapshotIsStable(t *testing.T) {
	first, h1 := Services()
	second, h2 := Services()
	if h1 != h2 {
		t.Fatalf("здоровье снимка нестабильно: %s против %s", h1, h2)
	}
	if len(first) != len(second) {
		t.Fatalf("длина снимка плавает: %d против %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("снимок нестабилен на позиции %d:\n  %+v\n  %+v", i, first[i], second[i])
		}
	}
}
