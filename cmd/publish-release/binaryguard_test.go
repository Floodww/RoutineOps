package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Полевой случай 10.08.2026: на прод скачали канареечный агент через API с ПУСТЫМ токеном,
// GitHub ответил 112 байтами {"message":"Bad credentials"}, curl положил их в файл с именем
// агента — и publish-release это опубликовал: посчитал sha256, подписал релизным ключом и
// зарегистрировал версией.
//
// Дальше все защиты работают против нас, потому что каждая исправна: агент скачает 112
// байт, сверит sha (совпадёт — мы сами её посчитали), проверит подпись манифеста (валидна
// — мы сами подписали), заменит свой exe и перезапустится. Подписанный мусор неотличим от
// релиза; единственное место, где его ещё можно поймать, — до подписи.
func TestRequireExecutableRejectsDownloadedError(t *testing.T) {
	dir := t.TempDir()
	poison := filepath.Join(dir, "agent_windows_amd64_v2.6.7-enterprise.exe")
	body := []byte(`{
  "message": "Bad credentials",
  "documentation_url": "https://docs.github.com/rest"
}`)
	if err := os.WriteFile(poison, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := requireExecutable(poison, "windows"); err == nil {
		t.Fatal("ответ API принят за бинарь агента — публикация подписала бы мусор")
	}

	// HTML-страница прокси/капчи — та же ошибка другим текстом.
	html := filepath.Join(dir, "agent_linux_amd64")
	if err := os.WriteFile(html, []byte("<!DOCTYPE html><html><body>403</body></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := requireExecutable(html, "linux"); err == nil {
		t.Error("HTML принят за бинарь")
	}

	// Пустой файл — вырожденный случай того же класса (оборванная докачка).
	empty := filepath.Join(dir, "agent_darwin_arm64")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := requireExecutable(empty, "darwin"); err == nil {
		t.Error("пустой файл принят за бинарь")
	}
}

// Вторая половина: настоящий бинарь обязан проходить. Без неё гейт был бы зелёным и у
// правки, отвергающей вообще всё, — а это остановило бы выкатку целиком.
func TestRequireExecutableAcceptsRealBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip("не удалось найти собственный бинарь теста")
	}
	if err := requireExecutable(self, runtime.GOOS); err != nil {
		t.Errorf("настоящая сборка Go отвергнута: %v", err)
	}
	// Тот же файл под чужой ОС — отказ: формат опознаётся однозначно, и «windows-релиз»
	// из ELF означает перепутанные флаги, а не редкий случай.
	other := "windows"
	if runtime.GOOS == "windows" {
		other = "linux"
	}
	if err := requireExecutable(self, other); err == nil {
		t.Errorf("бинарь %s принят как %s — перепутанный -os прошёл бы молча", runtime.GOOS, other)
	}
}
