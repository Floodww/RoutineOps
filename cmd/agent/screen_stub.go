//go:build !enterprise

package main

import (
	"log/slog"

	"github.com/Floodww/RoutineOps/internal/agent/command"
	"github.com/Floodww/RoutineOps/internal/agent/selfupdate"
	"github.com/Floodww/RoutineOps/internal/agent/transport"
)

// Open-core: удалённого рабочего стола в этой редакции нет. Заглушка держит тот же набор
// символов, что enterprise-проводка (screen_wiring.go), — иначе main.go пришлось бы
// обвешивать build-тегами, а именно этого приём с парой файлов и избегает.
//
// Возврат nil — не забывчивость: исполнитель задач на nil-менеджере отвечает на
// приглашение ОШИБКОЙ с кодом причины (см. handleScreenSession), и оператор видит «фича не
// в этой редакции», а не молчание.
type screenRuntime struct{}

func wireScreen(_, _ string, _ *transport.Dialer, _ func(string, []byte) error, _ *slog.Logger) *screenRuntime {
	return nil
}

func (r *screenRuntime) capabilities() []string { return nil }

func (r *screenRuntime) sessioner() command.ScreenSessioner { return nil }

func (r *screenRuntime) holdUpdates(_ *selfupdate.Updater) {}
