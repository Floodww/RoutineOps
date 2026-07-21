// Package security реализует Security Monitor агента (Этап 6): периодически
// смотрит запущенные процессы И установленное ПО и, если найдено запрещённое,
// шлёт ReportSecurityEvent. Список запрещённого читается из локального файла
// (работает и без связи с сервером); доставка списка с сервера — отдельный
// механизм, согласуется отдельно (в контракте пока нет).
//
// Реализация мониторинга — polling (macOS: ps; Linux: procfs; Windows:
// tasklist). Задержка обнаружения — секунды, для контроля ИБ приемлемо (не
// EDR-уровень). Установленное ПО сверяется по тому же инвентарному источнику,
// что и compliance-отчёт сервера (device_software.software_name): раньше агент
// смотрел ТОЛЬКО процессы, и правило вида «Google Chrome» (имя из инвентаря)
// никогда не совпадало с именем процесса chrome.exe — дэшборд показывал
// нарушения, а алерты не рождались вовсе.
package security

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"context"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
	"github.com/Floodww/RoutineOps/internal/agent/outbox"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/protobuf/proto"
)

// installedRefreshEvery — как часто обновлять снимок установленного ПО. Сам
// скан идёт каждые Interval (по умолчанию 30с), но инвентарный вызов дорогой
// (macOS: system_profiler — секунды), поэтому список кэшируется: установка/
// удаление ПО всплывает с задержкой до этого TTL, что для инвентарного сигнала
// приемлемо (runtime-сигнал по процессам остаётся быстрым).
const installedRefreshEvery = 10 * time.Minute

// EnqueueFunc ставит отчёт в устойчивую очередь доставки (outbox). Возврат nil
// означает, что событие durably сохранено и будет доставлено (в т.ч. после
// восстановления связи) — алерт ИБ не теряется при обрыве.
type EnqueueFunc func(kind string, data []byte) error

// Monitor следит за запущенными процессами и шлёт алерты ИБ.
type Monitor struct {
	Interval time.Duration
	ListFile string // путь к файлу со списком запрещённого ПО
	Enqueue  EnqueueFunc
	Log      *slog.Logger

	// alerted — запрещённые шаблоны, по которым уже отправлен алерт (чтобы не
	// слать на каждый poll). Снимается, когда шаблон пропал ИЗ ОБОИХ источников
	// (процесс завершён И ПО удалено) → повторное появление даёт новый алерт.
	//
	// Сознательный трейдофф «один алерт на эпизод»: пока запрещённое ПО остаётся
	// УСТАНОВЛЕННЫМ, повторные запуски его процесса НЕ рождают новых runtime-
	// алертов («запущено», с pid) — эпизод не закрывался. Оператору хватает
	// первого алерта + compliance-дэшборда; альтернатива (алерт на каждый запуск
	// при вечно открытом инвентарном эпизоде) — это спам.
	//
	// Набор персистится в stateFile: сервер алерты НЕ дедуплицирует (голый INSERT
	// + Telegram-нотификация на каждый), а установленное ПО «присутствует всегда»
	// — без персиста КАЖДЫЙ рестарт агента (self-update, ребут) рождал бы дубль
	// алерта на каждый установленный запрещённый пакет по всему парку.
	alerted map[string]struct{}

	// stateLoaded — эпизоды подняты с диска (лениво, перед первым сканом).
	stateLoaded bool

	// listProcs перечисляет процессы. Поле (а не прямой вызов listProcesses),
	// чтобы тесты могли подставить детерминированный список.
	listProcs func() ([]Process, error)

	// listInstalled — инвентарный снимок установленного ПО (сейм для тестов; в
	// проде — collector.InstalledSoftware). Кэшируется на installedRefresh.
	listInstalled    func() []collector.Software
	installedRefresh time.Duration
	installedCache   []collector.Software
	installedAt      time.Time
}

func NewMonitor(interval time.Duration, listFile string, enqueue EnqueueFunc, log *slog.Logger) *Monitor {
	return &Monitor{
		Interval:         interval,
		ListFile:         listFile,
		Enqueue:          enqueue,
		Log:              log,
		alerted:          make(map[string]struct{}),
		listProcs:        listProcesses,
		listInstalled:    collector.InstalledSoftware,
		installedRefresh: installedRefreshEvery,
	}
}

func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()
	m.scan(ctx) // первый прогон сразу
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.scan(ctx)
		}
	}
}

func (m *Monitor) scan(ctx context.Context) {
	// Перечитываем список каждый раз — правки файла (в т.ч. будущие обновления
	// с сервера) применяются без перезапуска.
	forbidden, err := loadForbidden(m.ListFile)
	if err != nil {
		m.Log.Error("security: чтение списка запрещённого ПО",
			slog.String("file", m.ListFile), slog.Any("error", err))
		return
	}
	if len(forbidden) == 0 {
		return
	}
	procs, err := m.listProcs()
	if err != nil {
		m.Log.Error("security: перечисление процессов", slog.Any("error", err))
		return
	}
	if !m.stateLoaded {
		m.loadAlerted()
		m.stateLoaded = true
	}

	// Шаблон запрещённого ПО -> найденный процесс / установленный пакет.
	running := findForbidden(procs, forbidden)
	installed := m.findInstalled(forbidden)

	// Новые срабатывания — алерт один раз на эпизод. Runtime-сигнал (процесс)
	// приоритетнее инвентарного: он и срочнее, и содержит pid.
	changed := false
	for bad, p := range running {
		if _, already := m.alerted[bad]; already {
			continue
		}
		if m.report(bad, fmt.Sprintf("запрещённое ПО запущено: %q (процесс %s, pid %d)", bad, p.Name, p.PID)) {
			m.alerted[bad] = struct{}{}
			changed = true
		}
	}
	for bad, sw := range installed {
		if _, already := m.alerted[bad]; already {
			continue
		}
		if _, alsoRunning := running[bad]; alsoRunning {
			continue // уже отрапортован строкой выше как запущенный
		}
		detail := fmt.Sprintf("запрещённое ПО установлено: %q (%s", bad, sw.Name)
		if sw.Version != "" {
			detail += " " + sw.Version
		}
		detail += ")"
		if m.report(bad, detail) {
			m.alerted[bad] = struct{}{}
			changed = true
		}
	}
	// Снять отметку с тех, что пропали из обоих источников (процесс завершён и
	// ПО удалено): следующее появление — новый эпизод, новый алерт.
	for bad := range m.alerted {
		_, run := running[bad]
		_, inst := installed[bad]
		if !run && !inst {
			delete(m.alerted, bad)
			changed = true
		}
	}
	if changed {
		m.saveAlerted()
	}
}

// stateFile — файл персиста эпизодов, рядом со списком запрещённого ПО (после
// раскладки это DataDir: на macOS/Linux — relocateForService, Windows-служба
// переводит дефолты в ProgramData\RoutineOps\state на старте; при переезде
// файл следует за списком — см. migrateLegacyState в cmd/agent). Пустой
// ListFile → без персиста.
func (m *Monitor) stateFile() string {
	if m.ListFile == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(m.ListFile), "security_alerted.seen")
}

// loadAlerted поднимает эпизоды с диска (по шаблону на строку). Best-effort:
// файла нет (первый запуск) или он битый — начинаем с пустого набора; протухшие
// записи (ПО удалили, пока агент не работал) снимет обычная зачистка в scan.
func (m *Monitor) loadAlerted() {
	path := m.stateFile()
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			m.alerted[line] = struct{}{}
		}
	}
}

// saveAlerted сбрасывает эпизоды на диск. Best-effort: сбой записи не должен
// мешать мониторингу — худшее следствие потери файла = один дубль-алерт после
// рестарта (как было до персиста вовсе).
func (m *Monitor) saveAlerted() {
	path := m.stateFile()
	if path == "" {
		return
	}
	lines := make([]string, 0, len(m.alerted))
	for bad := range m.alerted {
		lines = append(lines, bad)
	}
	sort.Strings(lines) // детерминированный файл — удобнее в диагностике
	data := strings.Join(lines, "\n")
	if data != "" {
		data += "\n"
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		m.Log.Debug("security: не удалось сохранить состояние эпизодов",
			slog.String("path", path), slog.Any("error", err))
	}
}

// findInstalled сопоставляет установленное ПО (инвентарный снимок, кэш с TTL
// installedRefresh) со списком запрещённого. Возвращает шаблон -> первый
// совпавший пакет. Матчинг тот же, что у процессов и у серверного compliance:
// подстрока имени, регистронезависимо.
func (m *Monitor) findInstalled(forbidden []string) map[string]collector.Software {
	if m.listInstalled == nil {
		return nil
	}
	if m.installedAt.IsZero() || time.Since(m.installedAt) >= m.installedRefresh {
		m.installedCache = m.listInstalled()
		m.installedAt = time.Now()
	}
	found := make(map[string]collector.Software)
	for _, sw := range m.installedCache {
		name := strings.ToLower(sw.Name)
		for _, bad := range forbidden {
			if _, ok := found[bad]; !ok && strings.Contains(name, bad) {
				found[bad] = sw
			}
		}
	}
	return found
}

// findForbidden сопоставляет процессы со списком запрещённого ПО (шаблоны уже в
// нижнем регистре). Возвращает шаблон -> найденный процесс (по подстроке
// имени/командной строки, регистронезависимо).
func findForbidden(procs []Process, forbidden []string) map[string]Process {
	current := make(map[string]Process)
	for _, p := range procs {
		hay := strings.ToLower(p.Name + " " + p.Cmd)
		for _, bad := range forbidden {
			if strings.Contains(hay, bad) {
				current[bad] = p
			}
		}
	}
	return current
}

// report ставит ReportSecurityEvent в устойчивую очередь (outbox) — доставка
// гарантируется даже при обрыве связи. Возвращает true при успешной постановке.
func (m *Monitor) report(pattern, details string) bool {
	data, err := proto.Marshal(&pb.SecurityEvent{
		AlertType:  pb.AlertType_ALERT_TYPE_FORBIDDEN_SOFTWARE,
		Details:    details,
		OccurredAt: time.Now().Unix(),
	})
	if err != nil {
		m.Log.Error("security: сериализация события", slog.Any("error", err))
		return false
	}
	if err := m.Enqueue(outbox.KindSecurity, data); err != nil {
		m.Log.Error("security: постановка алерта в очередь", slog.Any("error", err))
		return false
	}
	m.Log.Warn("алерт ИБ поставлен в очередь доставки",
		slog.String("pattern", pattern), slog.String("details", details))
	return true
}
