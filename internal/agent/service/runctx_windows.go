//go:build windows

package service

import "golang.org/x/sys/windows/svc"

// RunningAsService — true, когда процесс запущен SCM как служба (а не интерактивно
// из консоли). Гейт для машинной раскладки состояния: интерактивный dev-запуск
// `agent run` должен по-прежнему работать с CWD-относительными путями.
func RunningAsService() bool {
	isSvc, err := svc.IsWindowsService()
	return err == nil && isSvc
}
