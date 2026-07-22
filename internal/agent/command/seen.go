package command

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// seenSet — множество уже обработанных task_id для идемпотентности (at-least-once
// доставка от Asynq). Переживает рестарт агента: при path != "" набор читается из
// файла при старте и дописывается при каждом новом id. Это «at-most-once» по
// факту старта задачи — критично для операций вроде выдачи прав (Этап 4), чтобы
// после перезапуска задача не выполнилась повторно.
//
// Запись best-effort: при ошибке файла id всё равно помечен в памяти (в пределах
// текущего процесса дубль не выполнится). Файл append-only; обрезка — позже.
type seenSet struct {
	mu   sync.Mutex
	m    map[string]struct{}
	path string
}

func loadSeenSet(path string) *seenSet {
	s := &seenSet{m: make(map[string]struct{}), path: path}
	if path == "" {
		return s
	}
	f, err := os.Open(path)
	if err != nil {
		return s // нет файла — пустой набор
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if id := strings.TrimSpace(sc.Text()); id != "" {
			s.m[id] = struct{}{}
		}
	}
	return s
}

// has сообщает, помечен ли id виденным (задача уже стартовала), не меняя набор.
func (s *seenSet) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[id]
	return ok
}

// markIfNew атомарно помечает id виденным. Возвращает true, если id новый (можно
// выполнять задачу), и false для повторной доставки (выполнять не нужно).
func (s *seenSet) markIfNew(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; ok {
		return false
	}
	s.m[id] = struct{}{}
	s.persist(id)
	return true
}

// persist дописывает id в файл состояния (под удержанным mu). Best-effort.
func (s *seenSet) persist(id string) {
	if s.path == "" {
		return
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, id)
}
