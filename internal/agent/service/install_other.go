//go:build !darwin && !windows && !linux

package service

import (
	"errors"
	"log/slog"
)

var errUnsupported = errors.New("установка службы поддерживается только на macOS, Windows и Linux (на этой ОС используйте run)")

func Install(cfg Config) error { return errUnsupported }

func Uninstall() error { return errUnsupported }

// Harden — no-op: ужесточение DACL службы только для Windows.
func Harden() error { return nil }

// StopUserProcesses — no-op вне Windows.
//
// Не забывчивость: на macOS трей снимает launchd вместе с LaunchAgent, на Linux
// пользовательского процесса агента нет вовсе. Проблема «живой процесс держит файл и
// каталог не удаляется» — свойство Windows, где удалить открытый файл нельзя.
func StopUserProcesses(_ *slog.Logger) {}
