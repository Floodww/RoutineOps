//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Срез unit-файлов systemd.
//
// Читаем каталоги, а НЕ спрашиваем systemctl: агент ходит по машинам, где systemd
// может быть недоступен из контекста службы, а `systemctl list-unit-files` на
// большом парке — сотни миллисекунд процесса ради данных, которые лежат в файлах.
// Включённость определяется наличием симлинка в *.wants — ровно так systemd её и
// хранит.

type unitDir struct {
	path    string
	osOwned bool
}

// Порядок важен: юнит из /etc перекрывает одноимённый из /usr/lib (так же, как это
// делает сам systemd), поэтому админский каталог обходится ПОСЛЕДНИМ и затирает
// запись — иначе локальная подмена системного юнита осталась бы невидимой.
var linuxUnitDirs = []unitDir{
	{path: "/usr/lib/systemd/system", osOwned: true},
	{path: "/lib/systemd/system", osOwned: true},
	{path: "/etc/systemd/system", osOwned: false},
}

func osServices() ([]Service, Health) {
	return servicesFromUnitDirs(linuxUnitDirs)
}

func servicesFromUnitDirs(dirs []unitDir) ([]Service, Health) {
	byName := make(map[string]Service, 256)
	enabled := make(map[string]bool, 128)
	var seen, failed int

	for _, d := range dirs {
		entries, err := os.ReadDir(d.path)
		if err != nil {
			if !os.IsNotExist(err) {
				failed++
			}
			continue
		}
		seen++
		for _, e := range entries {
			name := e.Name()
			// Каталоги вида multi-user.target.wants — это и есть реестр
			// включённости: симлинк внутри означает «юнит включён».
			if e.IsDir() {
				if strings.HasSuffix(name, ".wants") {
					collectWants(filepath.Join(d.path, name), enabled)
				}
				continue
			}
			if !isUnitFile(name) {
				continue
			}
			full := filepath.Join(d.path, name)
			body, err := os.ReadFile(full)
			if err != nil {
				failed++
				continue
			}
			byName[name] = Service{
				Name:      name,
				Display:   unitValue(body, "Description"),
				ImagePath: unitValue(body, "ExecStart"),
				Account:   unitValue(body, "User"),
				DefHash:   hashDefinition(body),
				OSOwned:   d.osOwned,
				Kind:      KindService,
				StartType: StartTypeManual, // уточняется ниже по *.wants
			}
		}
	}

	out := make([]Service, 0, len(byName))
	for name, svc := range byName {
		if enabled[name] {
			svc.StartType = StartTypeEnabled
		}
		out = append(out, svc)
	}
	sortServices(out)

	switch {
	case seen == 0:
		// Нет ни одного каталога systemd — это не поломка, а другая система
		// инициализации. «Не поддерживается» и «сломалось» для подотчётности
		// разные ответы: первое не должно поднимать тревогу.
		return out, HealthUnsupported
	case failed > 0:
		return out, HealthPartial
	default:
		return out, HealthOK
	}
}

func collectWants(dir string, enabled map[string]bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if isUnitFile(e.Name()) {
			enabled[e.Name()] = true
		}
	}
}

func isUnitFile(name string) bool {
	for _, suf := range []string{".service", ".socket", ".timer", ".path", ".mount"} {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

// unitValue достаёт первое значение ключа из unit-файла. Формат ini-подобный, но
// полноценный парсер тут не нужен: нам важны три конкретных ключа, а любое
// изменение, которое парсер бы увидел, а мы нет, всё равно ловится DefHash.
func unitValue(body []byte, key string) string {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=\s*(.*)$`)
	if m := re.FindSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}
