package contract

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Гейт редакции (scripts/agent-edition-guard.sh) ищет путь пакета в СЫРЫХ БАЙТАХ файла.
// На собранном бинаре это работает, на инсталляторе — нет: payload внутри .pkg (xar+gzip),
// .msi (OLE), .deb (ar) и .rpm сжат, токена там не найдётся никогда. Значит на контейнере
// гейт не «не нашёл», а НЕ ИСКАЛ — и отвечает самым опасным из двух исходов: «open-core,
// публикуй». Поймано на себе при выпуске 2.6.2: заведомо enterprise-пакет получил зелёное.
//
// Тест держит два свойства сразу, потому что по отдельности каждое даёт ложное спокойствие:
// контейнер обязан ОТКАЗАТЬ кодом 2 («проверить нечем»), а сырой бинарь обязан
// по-прежнему проверяться в обе стороны. Гейт, отказывающий на всём подряд, так же
// бесполезен, как гейт, соглашающийся на всё.
func TestEditionGuardRefusesContainers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("гейт — POSIX-sh скрипт, на windows его запускать нечем")
	}
	script := guardScript(t)
	dir := t.TempDir()

	const token = "internal/agent/screen"
	// Первые байты — единственное, по чему гейт отличает бинарь от контейнера.
	elf := []byte{0x7f, 'E', 'L', 'F'}
	pe := []byte{'M', 'Z', 0x90, 0x00}
	macho := []byte{0xcf, 0xfa, 0xed, 0xfe}
	xar := []byte{'x', 'a', 'r', '!'}
	cfb := []byte{0xd0, 0xcf, 0x11, 0xe0}
	gzip := []byte{0x1f, 0x8b, 0x08, 0x00}
	zip := []byte{'P', 'K', 0x03, 0x04}
	ar := []byte{'!', '<', 'a', 'r'}
	rpm := []byte{0xed, 0xab, 0xee, 0xdb}

	cases := []struct {
		name     string
		magic    []byte
		hasToken bool
		tags     string
		wantExit int
		why      string
	}{
		{"elf free под open-core", elf, false, "", 0, "обычная free-публикация linux"},
		{"pe enterprise под enterprise", pe, true, "enterprise", 0, "обычная enterprise-публикация windows"},
		{"macho enterprise под open-core", macho, true, "", 1, "раздача закрытого кода парку"},
		{"elf free под enterprise", elf, false, "enterprise", 1, "парк без удалённого стола и FileVault"},

		// 🔴 Сердцевина. Токена внутри нет и быть не может — но это НЕ «open-core».
		{"pkg (xar)", xar, false, "", 2, "payload сжат, гейт бы соврал «open-core»"},
		{"msi (OLE)", cfb, false, "", 2, "payload сжат, гейт бы соврал «open-core»"},
		{"gzip", gzip, false, "", 2, "payload сжат"},
		{"zip", zip, false, "", 2, "payload сжат"},
		{"deb (ar)", ar, false, "", 2, "payload сжат"},
		{"rpm", rpm, false, "", 2, "payload сжат"},
		{"текстовый файл", []byte("#!/bin/sh\n"), false, "", 2, "не исполняемый формат вовсе"},

		// Контейнер, в котором токен ЛЕЖИТ открытым (несжатое имя файла в оглавлении),
		// тоже не повод объявлять редакцию: проверено не то, что публикуется.
		{"pkg с токеном в оглавлении", xar, true, "enterprise", 2, "совпадение вне payload ничего не доказывает"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := make([]byte, 0, 512)
			body = append(body, c.magic...)
			body = append(body, []byte(strings.Repeat("x", 64))...)
			if c.hasToken {
				body = append(body, []byte(token)...)
			}
			path := filepath.Join(dir, strings.ReplaceAll(c.name, " ", "_"))
			if err := os.WriteFile(path, body, 0o644); err != nil {
				t.Fatalf("не записать фикстуру: %v", err)
			}

			code, out := runGuard(t, script, c.tags, path)
			if code != c.wantExit {
				t.Fatalf("код %d, ожидался %d (%s).\nВывод:\n%s", code, c.wantExit, c.why, out)
			}
			// Отдельная проверка вывода: код 2 с текстом «open-core ✅» был бы ровно тем
			// самым ложным зелёным, только с ненулевым кодом — читающий человек поверит
			// строке, а не коду.
			if c.wantExit == 2 && strings.Contains(out, "✅") {
				t.Fatalf("отказ напечатал галочку — это читается как успех.\nВывод:\n%s", out)
			}
		})
	}
}

// Трекнутые инсталляторы — тот самый файл, на который гейт наводили руками и получали
// зелёное. Проверяем их напрямую: синтетические фикстуры выше доказывают правило, этот
// случай доказывает, что мина в дереве обезврежена.
func TestEditionGuardRefusesTrackedInstallers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("гейт — POSIX-sh скрипт, на windows его запускать нечем")
	}
	root := repoRootOrSkip(t)
	script := guardScript(t)

	for _, rel := range []string{
		filepath.Join("build", "pkg", "RoutineOps-agent.pkg"),
		filepath.Join("build", "msi", "RoutineOps-agent.msi"),
	} {
		path := filepath.Join(root, rel)
		if _, err := os.Stat(path); err != nil {
			t.Logf("%s нет в дереве (Free-срез или чистая сборка) — пропуск", rel)
			continue
		}
		code, out := runGuard(t, script, "", path)
		if code != 2 {
			t.Errorf("гейт на инсталляторе %s вернул %d, а обязан 2 («проверить нечем»): "+
				"внутри payload сжат, и любой другой ответ — выдумка.\nВывод:\n%s", rel, code, out)
		}
	}
}

// Сам бинарь агента, лежащий в дереве, гейт обязан проверять как и раньше — иначе
// «починка» свелась бы к тому, что гейт отказывает всем.
func TestEditionGuardStillReadsTrackedPrebuilt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("гейт — POSIX-sh скрипт, на windows его запускать нечем")
	}
	root := repoRootOrSkip(t)
	prebuilt := filepath.Join(root, "build", "darwin", "agent_darwin_arm64")
	if _, err := os.Stat(prebuilt); err != nil {
		t.Skip("трекнутого darwin-prebuilt нет в дереве")
	}
	code, out := runGuard(t, guardScript(t), "", prebuilt)
	if code != 0 {
		t.Fatalf("гейт на трекнутом prebuilt вернул %d, ожидался 0 (он обязан быть open-core).\nВывод:\n%s", code, out)
	}
}

func runGuard(t *testing.T, script, tags, path string) (int, string) {
	t.Helper()
	cmd := exec.Command("sh", script, tags, path, "тест")
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("не запустить гейт: %v", err)
		}
		code = ee.ExitCode()
	}
	return code, string(out)
}

func guardScript(t *testing.T) string {
	t.Helper()
	root := repoRootOrSkip(t)
	path := filepath.Join(root, "scripts", "agent-edition-guard.sh")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("нет %s — проверять нечего", path)
	}
	return path
}

func repoRootOrSkip(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Skipf("не определить рабочий каталог: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("корень репозитория не найден — тест привязан к дереву")
		}
		dir = parent
	}
}
