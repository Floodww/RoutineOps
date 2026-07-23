// routineops — CLI управления конфигурацией парка через YAML.
//
//	routineops export -o routineops.yaml     # текущее состояние сервера → файл + скрипты
//	routineops apply  -f routineops.yaml     # файл → сервер
//
// Ходит публичным HTTP API под API-токеном (Authorization: Bearer) — теми же ручками,
// что и UI. Отдельного канала доступа у CLI нет намеренно.
//
// Формат файла, семантика скоупа и рецепты — docs/config-as-code.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `routineops — конфигурация парка в YAML.

Команды:
  export   выгрузить текущую конфигурацию сервера в YAML
  apply    применить YAML к серверу

Общие флаги:
  -server   адрес сервера, например https://mdm.example.com  (env ROUTINEOPS_URL)
  -token    API-токен                                        (env ROUTINEOPS_TOKEN)
  -ca       CA-сертификат сервера, если он собственный        (env ROUTINEOPS_CA)

export:
  -o           путь к YAML (по умолчанию routineops.yaml)
  -scripts-dir каталог для тел скриптов рядом с YAML (по умолчанию scripts;
               пустое значение — складывать тела инлайном в YAML)

apply:
  -f           путь к YAML
  -dry-run     показать план и выйти, ничего не меняя
  -y           не спрашивать подтверждения (обязателен в неинтерактивном запуске)

Файл управляет только тем, что в нём названо: группа, не упомянутая в YAML, не
трогается. Внутри названной группы списки авторитетны — правило, которого нет в
файле, будет удалено. Отсутствующий ключ (например, software) означает «не управляем
этим аспектом», пустой список (software: []) — «правил быть не должно».

Пример:
  export ROUTINEOPS_URL=https://mdm.example.com ROUTINEOPS_TOKEN=...
  routineops export -o fleet/routineops.yaml
  routineops apply -f fleet/routineops.yaml -dry-run
`)
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("не указана команда")
	}
	cmd, rest := args[0], args[1:]

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	server := fs.String("server", os.Getenv("ROUTINEOPS_URL"), "адрес сервера")
	token := fs.String("token", os.Getenv("ROUTINEOPS_TOKEN"), "API-токен")
	ca := fs.String("ca", os.Getenv("ROUTINEOPS_CA"), "CA-сертификат сервера")
	out := fs.String("o", "routineops.yaml", "путь к YAML (export)")
	scriptsDir := fs.String("scripts-dir", "scripts", "каталог тел скриптов (export)")
	file := fs.String("f", "", "путь к YAML (apply)")
	dryRun := fs.Bool("dry-run", false, "показать план и выйти, ничего не меняя")
	yes := fs.Bool("y", false, "не спрашивать подтверждения")

	switch cmd {
	case "export":
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *server == "" {
			return fmt.Errorf("нужен адрес сервера: -server или ROUTINEOPS_URL")
		}
		c, err := newClient(*server, *token, *ca)
		if err != nil {
			return err
		}
		return runExport(c, *out, *scriptsDir)
	case "apply":
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *server == "" {
			return fmt.Errorf("нужен адрес сервера: -server или ROUTINEOPS_URL")
		}
		if *file == "" {
			return fmt.Errorf("нужен путь к YAML: -f")
		}
		c, err := newClient(*server, *token, *ca)
		if err != nil {
			return err
		}
		return runApply(c, *file, *dryRun, *yes)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("неизвестная команда %q", cmd)
	}
}

func runApply(c *client, path string, dryRun, yes bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if cfg.APIVersion != "" && cfg.APIVersion != apiVersion {
		return fmt.Errorf("%s: apiVersion %q не поддерживается (нужен %s)", path, cfg.APIVersion, apiVersion)
	}

	plan, err := applyPlan(c, &cfg, filepath.Dir(path))
	if err != nil {
		return err
	}
	if len(plan) == 0 {
		fmt.Println("изменений нет — конфигурация сервера совпадает с файлом")
		return nil
	}

	fmt.Printf("План изменений (%d):\n", len(plan))
	for _, a := range plan {
		fmt.Println("  •", a.desc)
	}
	if dryRun {
		fmt.Println("\n-dry-run: ничего не применено")
		return nil
	}
	// Подтверждение обязательно: apply меняет конфигурацию парка вплоть до того, какие
	// скрипты поедут на машины. В неинтерактивном запуске (CI) молча применять тем более
	// нельзя — там требуем явный -y, иначе автоматика раскатала бы правку без свидетелей.
	if !yes {
		if !isTerminal(os.Stdin) {
			return fmt.Errorf("неинтерактивный запуск: подтвердите изменения флагом -y (или прогоните -dry-run)")
		}
		fmt.Print("\nПрименить? [y/N]: ")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" && a != "д" && a != "да" {
			fmt.Println("отменено")
			return nil
		}
	}

	for i, a := range plan {
		if err := a.do(); err != nil {
			// Останавливаемся на первой ошибке и говорим, сколько успели: половина
			// применённого плана — это состояние, в котором оператор обязан разобраться,
			// а не узнать о нём из общего «не получилось».
			return fmt.Errorf("шаг %d/%d (%s): %w\nприменено шагов: %d", i+1, len(plan), a.desc, err, i)
		}
		fmt.Println("  ✓", a.desc)
	}
	fmt.Printf("применено шагов: %d\n", len(plan))
	return nil
}

// isTerminal — грубая проверка «мы в интерактивной сессии». Через режим файла, чтобы не
// тянуть зависимость ради одного вопроса.
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func runExport(c *client, out, scriptsDir string) error {
	cfg, files, err := exportConfig(c, scriptsDir)
	if err != nil {
		return err
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	base := filepath.Dir(out)
	if err := os.MkdirAll(base, 0o755); err != nil {
		return err
	}
	if err := writeScriptFiles(base, files); err != nil {
		return err
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return err
	}
	fmt.Printf("выгружено: групп %d, скриптов %d, скрипт-политик %d → %s\n",
		len(cfg.Groups), len(cfg.Scripts), len(cfg.ScriptPolicies), out)
	return nil
}
