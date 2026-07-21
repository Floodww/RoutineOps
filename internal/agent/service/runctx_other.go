//go:build !windows

package service

// RunningAsService — вне Windows различие «служба/консоль» для раскладки
// состояния не используется (macOS/Linux решают это через Relocate + WorkingDir
// службы), поэтому всегда false.
func RunningAsService() bool { return false }
