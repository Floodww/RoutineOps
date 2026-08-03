package selfupdate

import (
	"fmt"
	"sort"
	"sync"
)

// Исключения по PID для taskkill на Windows (docs/remote-desktop-contract.md §9.1).
//
// Замена бинаря начинается с `taskkill /F /IM <exe>` — иначе трей в юзер-сессии держит
// блокировку .old от прошлого обновления, и rename падает (полевой баг v2.2.x). Но тот же
// удар прилетает и захватчику экрана: он запускается ТЕМ ЖЕ exe, значит попадает под
// /IM гарантированно, а /F — это TerminateProcess без финализации записи сеанса.
//
// Гейт §9.1 (hold.go) — первая линия: во время сеанса обновление вообще не начинается.
// Исключение по PID — вторая: между «гейт отпустил» и «taskkill выстрелил» есть окно, в
// которое успевает начаться новый сеанс, и по нему нельзя стрелять только потому, что он
// не успел заявиться.
//
// Файл без build-тега намеренно: сборка списка аргументов — чистая строковая логика, и
// проверять её надо тестом на любой ОС, а не глазами в комментарии к windows-файлу.

var (
	protectedMu  sync.RWMutex
	protectedPID func() []int
)

// SetProtectedPIDs подключает источник PID'ов, по которым taskkill стрелять не должен.
// Вызывается из cmd/agent, когда поднимается менеджер сеансов. nil = исключений нет.
func SetProtectedPIDs(f func() []int) {
	protectedMu.Lock()
	defer protectedMu.Unlock()
	protectedPID = f
}

// protectedPIDs — текущий список защищённых PID'ов.
func protectedPIDs() []int {
	protectedMu.RLock()
	f := protectedPID
	protectedMu.RUnlock()
	if f == nil {
		return nil
	}
	return f()
}

// taskkillArgs собирает аргументы taskkill для образа image.
//
// self исключается всегда (иначе апдейтер убьёт сам себя посреди обновления), protected —
// это PID'ы, которые ведут работу с внешне видимым исходом: их завершение обязано быть
// штатным, а не /F.
//
// Фильтры /FI в taskkill соединяются логическим И, поэтому каждый исключаемый PID —
// отдельный /FI "PID ne N". Дубликаты и мусор (<=0, self) отсеиваются, порядок
// стабилизируется — иначе аргументы будет невозможно проверить тестом.
func taskkillArgs(image string, self int, protected []int) []string {
	args := []string{"/F", "/IM", image, "/FI", fmt.Sprintf("PID ne %d", self)}

	seen := map[int]bool{self: true}
	uniq := make([]int, 0, len(protected))
	for _, pid := range protected {
		if pid <= 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		uniq = append(uniq, pid)
	}
	sort.Ints(uniq)
	for _, pid := range uniq {
		args = append(args, "/FI", fmt.Sprintf("PID ne %d", pid))
	}
	return args
}
