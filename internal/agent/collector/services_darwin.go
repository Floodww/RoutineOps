//go:build darwin

package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Срез демонов и агентов launchd.
//
// Каталоги обходятся ReadDir + ReadFile, БЕЗ единого внешнего процесса на файл.
// Это не стилистика: в collector_darwin.go от такого подхода уже отказались при
// сборе инвентаря — defaults/mdls на каждую запись давали сотни процессов на один
// снимок. Здесь записей столько же (сотни plist'ов), а снимков за сессию несколько.
//
// Каталог ~/Library/LaunchAgents сотрудника НЕ обходится сознательно. Цель фичи —
// подотчётность выданных админ-прав, то есть машинные изменения; личные автозапуски
// в домашнем каталоге к правам администратора отношения не имеют, а собирать их
// значило бы следить за человеком. Всё, что ставится с админ-правами, ложится в
// /Library или /System.

type plistDir struct {
	path    string
	kind    string
	osOwned bool
}

var darwinServiceDirs = []plistDir{
	{path: "/System/Library/LaunchDaemons", kind: KindService, osOwned: true},
	{path: "/System/Library/LaunchAgents", kind: KindAgent, osOwned: true},
	{path: "/Library/LaunchDaemons", kind: KindService, osOwned: false},
	{path: "/Library/LaunchAgents", kind: KindAgent, osOwned: false},
}

func osServices() ([]Service, Health) {
	return servicesFromPlistDirs(darwinServiceDirs, darwinDisabledLabels())
}

// servicesFromPlistDirs — вся логика снимка, вынесенная из точки входа ради тестов:
// каталоги подставляются временными, и проверка не зависит от того, что стоит на
// машине, где гоняют тесты.
func servicesFromPlistDirs(dirs []plistDir, disabled map[string]bool) ([]Service, Health) {
	out := make([]Service, 0, 256)
	var seen, failed int

	for _, d := range dirs {
		entries, err := os.ReadDir(d.path)
		if err != nil {
			// Отсутствующий каталог — норма (на чистой системе /Library/LaunchAgents
			// может не существовать), а вот отказ в доступе к существующему — уже
			// деградация снимка, и её надо показать наверх.
			if !os.IsNotExist(err) {
				failed++
			}
			continue
		}
		seen++
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
				continue
			}
			full := filepath.Join(d.path, e.Name())
			body, err := os.ReadFile(full)
			if err != nil {
				failed++
				continue
			}
			label := strings.TrimSuffix(e.Name(), ".plist")
			svc := Service{
				// Имя файла, а не Label из тела: бинарный plist без сторонней
				// библиотеки не разобрать, а библиотеки в проекте запрещены.
				// launchd и сам требует совпадения имени файла с Label, а
				// расхождение (редкое) поймается сменой DefHash.
				Name:      label,
				Display:   label,
				ImagePath: plistFirstProgramArgument(body),
				Account:   plistStringValue(body, "UserName"),
				DefHash:   hashDefinition(body),
				OSOwned:   d.osOwned,
				Kind:      d.kind,
				StartType: StartTypeEnabled,
			}
			if disabled[label] {
				svc.StartType = StartTypeDisabled
			}
			out = append(out, svc)
		}
	}

	sortServices(out)
	switch {
	case seen == 0:
		return out, HealthFailed
	case failed > 0:
		return out, HealthPartial
	default:
		return out, HealthOK
	}
}

// darwinDisabledLabels — множество отключённых демонов. Единственный внешний
// процесс во всём снимке: состояние disabled живёт в служебной базе launchd, а не
// в plist'е, и прочитать его файлами нельзя. Неудача здесь не роняет снимок —
// службы просто останутся с StartTypeEnabled, а изменение самого определения
// (главный сигнал) всё равно будет видно.
func darwinDisabledLabels() map[string]bool {
	out, err := exec.Command("launchctl", "print-disabled", "system").Output()
	if err != nil {
		return nil
	}
	res := make(map[string]bool, 32)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasSuffix(line, "true") {
			continue
		}
		// Формат строки: "com.example.daemon" => true
		if i := strings.Index(line, "=>"); i > 0 {
			label := strings.Trim(strings.TrimSpace(line[:i]), `"`)
			if label != "" {
				res[label] = true
			}
		}
	}
	return res
}

// Разбор XML-plist регулярками — сознательное ограничение, а не небрежность.
// Полноценный парсер нужен был бы и для бинарного формата, а его без сторонней
// библиотеки не сделать. Поэтому явные поля заполняются только для текстовых
// plist'ов, а для бинарных остаются пустыми — и это честно: изменение такого
// определения ловится через DefHash, который считается по всему файлу.
var (
	reProgramArgs = regexp.MustCompile(`(?s)<key>ProgramArguments</key>\s*<array>\s*<string>([^<]*)</string>`)
	reProgram     = regexp.MustCompile(`(?s)<key>Program</key>\s*<string>([^<]*)</string>`)
)

func plistFirstProgramArgument(body []byte) string {
	if m := reProgram.FindSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(string(m[1]))
	}
	if m := reProgramArgs.FindSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

func plistStringValue(body []byte, key string) string {
	re := regexp.MustCompile(`(?s)<key>` + regexp.QuoteMeta(key) + `</key>\s*<string>([^<]*)</string>`)
	if m := re.FindSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}
