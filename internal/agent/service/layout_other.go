//go:build !darwin && !linux && !windows

package service

// InstallLayout — платформы без инсталлятора и без машинной раскладки состояния:
// Relocate=false, пути пустые (агент работает с CWD-относительными дефолтами).
// Windows выделен в layout_windows.go: там DataDir указывает в ProgramData.
func InstallLayout() Layout {
	return Layout{Relocate: false}
}
