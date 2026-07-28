// Package uninstall снимает установленное ПО по команде оператора из карточки
// устройства (Task.uninstall).
//
// Базовое решение пакета: команда сервера — это СЕЛЕКТОР ЦЕЛИ, а не команда ОС.
// Агент заново снимает инвентарь, находит цель в СВОЁМ свежем снимке и выполняет
// метод, который его собственный коллектор считает применимым к этой записи.
// Ни строка деинсталлятора, ни метод исполнения от сервера не берутся никогда.
//
// Почему так, а не «сервер прислал команду — агент выполнил»: второй вариант
// превращает канал задач в произвольное исполнение на устройстве, уже поверх
// существующего канала скриптов, но мимо его подписи, аудита и потолков. Плюс
// инвентарь на сервере всегда чуть устарел (снимок раз в 5 минут), и слепое
// исполнение присланной строки снимало бы не ту версию — либо одноимённый
// продукт другого вендора.
//
// Порядок шагов (важен именно этот):
//
//	guard(селектор) → снимок → резолв → guard(найденное) → метод → исполнение → ПОВТОРНЫЙ снимок
//
// Guard самозащиты стоит ДВАЖДЫ и первым: до какой-либо работы — по присланному
// селектору, и повторно — по фактически найденной записи. Самоснос агента этой
// командой недопустим ни при каком стечении (см. selfguard.go), а повторный
// снимок в конце нужен потому, что успешный код возврата деинсталлятора не
// означает, что ПО снято.
package uninstall

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
	"github.com/Floodww/RoutineOps/internal/agent/scriptenc"
	pb "github.com/Floodww/RoutineOps/proto"
)

// Request — селектор цели, приехавший от сервера (pb.UninstallCommand).
// Пустое поле означает «сервер этого не знает», а НЕ «подходит любое»:
// сверяются только заполненные поля, но заполненное обязано совпасть.
type Request struct {
	RequestID       string
	Name            string
	Version         string
	UninstallID     string
	InstallLocation string
	Method          collector.UninstallMethod
	Scope           string
	Reason          string
}

// Result — исход попытки. Detail всегда человекочитаем и уезжает оператору в
// карточку устройства; Outcome — машиночитаемая причина для UI и аудита.
type Result struct {
	Outcome pb.UninstallOutcome
	Detail  string
}

// scanFunc — снимок установленного ПО. Поле (а не прямой вызов коллектора),
// чтобы тесты подставляли снимок, а исполнитель — проверяемо влиял на второй.
type scanFunc func() []collector.Software

// execFunc — платформенный исполнитель снятия. Возвращает вывод деинсталлятора
// (для оператора) и ошибку. Возврат без ошибки означает «деинсталлятор отработал
// без ошибки», а НЕ «ПО снято» — это проверяет уже повторный снимок.
type execFunc func(ctx context.Context, target collector.Software, log *slog.Logger) (string, error)

// Manager выполняет команды удаления ПО.
type Manager struct {
	scan scanFunc
	exec execFunc
	self selfID
	log  *slog.Logger
}

// New собирает Manager. Ошибка означает, что агент не смог установить
// собственную идентичность (см. resolveSelf) — тогда команда удаления должна
// быть НЕДОСТУПНА целиком: guard самозащиты без знания о себе не работает, а
// сносить ПО, не умея отличить от себя, нельзя. Отказ выдать функцию лучше, чем
// функция с выключенным предохранителем.
func New(log *slog.Logger) (*Manager, error) {
	self, err := resolveSelf()
	if err != nil {
		return nil, fmt.Errorf("идентичность агента не установлена, удаление ПО отключено: %w", err)
	}
	return &Manager{
		scan: collector.InstalledSoftware,
		exec: execute,
		self: self,
		log:  log,
	}, nil
}

// Run выполняет команду. Ошибку наружу не возвращает: любой исход — это Result с
// причиной, потому что оператору нужна причина, а не факт ошибки.
func (m *Manager) Run(ctx context.Context, req Request) Result {
	log := m.log.With(slog.String("request_id", req.RequestID), slog.String("software", req.Name))

	if strings.TrimSpace(req.Name) == "" {
		return Result{pb.UninstallOutcome_UNINSTALL_OUTCOME_TARGET_CHANGED, "селектор без имени ПО"}
	}

	// Guard №1 — по присланному селектору, ДО любой работы. Ловит команду,
	// нацеленную на агента, даже если она почему-то не сойдётся с инвентарём.
	if why := m.self.matchesRequest(req); why != "" {
		log.Error("uninstall: команда нацелена на самого агента — ОТКАЗ", slog.String("признак", why))
		return Result{pb.UninstallOutcome_UNINSTALL_OUTCOME_SELF_PROTECTED,
			"цель — сам агент RoutineOps (" + why + "); снятие агента выполняется только командой вывода из эксплуатации"}
	}

	target, res := m.resolve(req)
	if res != nil {
		log.Warn("uninstall: цель не разрешена", slog.String("outcome", res.Outcome.String()), slog.String("detail", res.Detail))
		return *res
	}

	// Guard №2 — по ФАКТИЧЕСКИ найденной записи. Селектор мог не содержать тех
	// полей, по которым видно, что это мы (например, сервер прислал только имя,
	// а путь установки ведёт в каталог агента).
	if why := m.self.matchesSoftware(target); why != "" {
		log.Error("uninstall: найденная запись — сам агент — ОТКАЗ", slog.String("признак", why))
		return Result{pb.UninstallOutcome_UNINSTALL_OUTCOME_SELF_PROTECTED,
			"найденная запись — сам агент RoutineOps (" + why + "); снятие агента выполняется только командой вывода из эксплуатации"}
	}

	// Метод берётся из СВЕЖЕЙ записи, а присланный — только сверяется. Коллектор
	// выставляет метод лишь там, где агент реально снимет ПО тихо и
	// неинтерактивно (fail-safe: пустой метод = снимать нечем).
	if target.UninstallMethod == collector.UninstallNone {
		return Result{pb.UninstallOutcome_UNINSTALL_OUTCOME_NOT_REMOVABLE,
			"для «" + target.Name + "» нет тихого деинсталлятора, применимого из-под службы"}
	}
	if req.Method != "" && req.Method != target.UninstallMethod {
		return Result{pb.UninstallOutcome_UNINSTALL_OUTCOME_TARGET_CHANGED,
			fmt.Sprintf("способ снятия изменился после снимка инвентаря: было %q, стало %q", req.Method, target.UninstallMethod)}
	}

	log.Warn("uninstall: снимаю ПО",
		slog.String("version", target.Version),
		slog.String("method", string(target.UninstallMethod)),
		slog.String("scope", target.Scope),
		slog.String("reason", req.Reason))

	out, err := m.exec(ctx, target, log)
	out = scriptenc.TruncateOutput(scriptenc.SanitizeUTF8(out))
	if err != nil {
		log.Error("uninstall: деинсталлятор завершился ошибкой", slog.Any("error", err))
		return Result{pb.UninstallOutcome_UNINSTALL_OUTCOME_FAILED, joinDetail(err.Error(), out)}
	}

	// Повторный снимок — единственное доказательство. msiexec возвращает 0 на
	// снос, отложенный до перезагрузки; pkgutil --forget вообще только чистит
	// квитанцию, не трогая файлы. Отчитываться по коду возврата означало бы
	// сказать оператору «снято» про работающую программу.
	if still, ok := findSame(m.scan(), target); ok {
		log.Warn("uninstall: деинсталлятор отработал без ошибки, но ПО осталось в снимке",
			slog.String("version", still.Version))
		return Result{pb.UninstallOutcome_UNINSTALL_OUTCOME_STILL_PRESENT,
			joinDetail("деинсталлятор завершился без ошибки, но ПО осталось на машине (возможно, снятие отложено до перезагрузки)", out)}
	}

	log.Info("uninstall: ПО снято")
	return Result{pb.UninstallOutcome_UNINSTALL_OUTCOME_REMOVED, joinDetail("снято: "+target.Name+" "+target.Version, out)}
}

// resolve находит ровно одну запись под селектор. Второе возвращаемое значение
// не nil — резолв не удался, и это уже готовый ответ оператору.
//
// Разделение ALREADY_ABSENT и TARGET_CHANGED здесь принципиально. «Имени нет на
// машине вовсе» — намерение оператора выполнено, спорить не о чем. «Имя есть, но
// версия/ключ разошлись» — это НЕ то же самое: между снимком инвентаря и
// командой ПО могли обновить, и снос по одному имени снял бы другую версию.
// Схлопнуть эти два исхода в один означало бы либо врать про удаление, либо
// пугать оператора ошибкой там, где всё в порядке.
func (m *Manager) resolve(req Request) (collector.Software, *Result) {
	installed := m.scan()

	byName := make([]collector.Software, 0, 2)
	for _, s := range installed {
		if strings.EqualFold(strings.TrimSpace(s.Name), strings.TrimSpace(req.Name)) {
			byName = append(byName, s)
		}
	}
	if len(byName) == 0 {
		return collector.Software{}, &Result{pb.UninstallOutcome_UNINSTALL_OUTCOME_ALREADY_ABSENT,
			"«" + req.Name + "» на устройстве не найдено — удалять нечего"}
	}

	matched := make([]collector.Software, 0, len(byName))
	for _, s := range byName {
		if matchesSelector(s, req) {
			matched = append(matched, s)
		}
	}
	switch len(matched) {
	case 1:
		return matched[0], nil
	case 0:
		return collector.Software{}, &Result{pb.UninstallOutcome_UNINSTALL_OUTCOME_TARGET_CHANGED,
			fmt.Sprintf("«%s» на устройстве есть, но запись изменилась после снимка инвентаря (на машине: %s)", req.Name, describe(byName))}
	default:
		// Одинаковые по всем известным серверу признакам записи. Догадка здесь
		// означала бы снос произвольной из них.
		return collector.Software{}, &Result{pb.UninstallOutcome_UNINSTALL_OUTCOME_AMBIGUOUS,
			fmt.Sprintf("селектору соответствует несколько записей (%s) — уточните цель", describe(matched))}
	}
}

// matchesSelector сверяет только ЗАПОЛНЕННЫЕ поля селектора: пустое поле — это
// «сервер не знает», а не «подходит любое». Имя уже сверено вызывающим.
func matchesSelector(s collector.Software, req Request) bool {
	if req.Version != "" && s.Version != req.Version {
		return false
	}
	if req.UninstallID != "" && s.UninstallID != req.UninstallID {
		return false
	}
	if req.InstallLocation != "" && !samePath(s.InstallLocation, req.InstallLocation) {
		return false
	}
	if req.Scope != "" && s.Scope != req.Scope {
		return false
	}
	return true
}

// findSame ищет в новом снимке ту же запись — по всем машинным признакам сразу.
// Только по имени искать нельзя: продукт мог быть переустановлен другой версией.
func findSame(installed []collector.Software, target collector.Software) (collector.Software, bool) {
	for _, s := range installed {
		if !strings.EqualFold(strings.TrimSpace(s.Name), strings.TrimSpace(target.Name)) {
			continue
		}
		if s.Version == target.Version && s.UninstallID == target.UninstallID && samePath(s.InstallLocation, target.InstallLocation) {
			return s, true
		}
	}
	return collector.Software{}, false
}

// describe — короткая сводка записей для оператора: что именно агент видит на
// машине вместо ожидаемого. Без неё TARGET_CHANGED неразбираем.
func describe(sw []collector.Software) string {
	const maxListed = 3
	parts := make([]string, 0, maxListed)
	for i, s := range sw {
		if i == maxListed {
			parts = append(parts, fmt.Sprintf("и ещё %d", len(sw)-maxListed))
			break
		}
		v := s.Version
		if v == "" {
			v = "без версии"
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, ", ")
}

func joinDetail(head, out string) string {
	if strings.TrimSpace(out) == "" {
		return head
	}
	return head + "\n" + out
}
