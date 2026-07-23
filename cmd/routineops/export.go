package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// exportConfig собирает текущее состояние сервера в YAML-конфигурацию. Обратный путь
// из UI в git: настроили руками — выгрузили — закоммитили.
//
// Всё сортируется по имени, а не по created_at из API: файл обязан быть стабильным
// между прогонами, иначе каждый export даёт шумный diff и обесценивает саму идею
// хранения конфигурации в git.
func exportConfig(c *client, scriptsDir string) (*Config, map[string]string, error) {
	var groups []apiGroup
	if err := c.get("/device-groups", &groups); err != nil {
		return nil, nil, err
	}
	var rules []apiPolicyRule
	if err := c.get("/policies", &rules); err != nil {
		return nil, nil, err
	}
	var scripts []apiScript
	if err := c.get("/scripts", &scripts); err != nil {
		return nil, nil, err
	}
	var policies []apiScriptPolicy
	if err := c.get("/script-policies", &policies); err != nil {
		return nil, nil, err
	}

	cfg := &Config{APIVersion: apiVersion}

	// Софт-правила раскладываем по группам. Правила без group_id (глобальные или
	// адресованные конкретному устройству) намеренно пропускаем: первые не принадлежат
	// ни одной группе, вторые — это инвентарь, которого в YAML не бывает.
	softByGroup := map[string][]SoftwareRule{}
	for _, r := range rules {
		if r.GroupID == nil || *r.GroupID == "" || r.DeviceID != nil {
			continue
		}
		softByGroup[*r.GroupID] = append(softByGroup[*r.GroupID], SoftwareRule{Name: r.SoftwareName, Rule: r.RuleType})
	}
	polsByGroup := map[string][]string{}
	for _, p := range policies {
		for _, g := range p.GroupNames {
			polsByGroup[g] = append(polsByGroup[g], p.Name)
		}
	}

	for _, g := range groups {
		soft := softByGroup[g.ID]
		sort.Slice(soft, func(i, j int) bool { return soft[i].Name < soft[j].Name })
		names := polsByGroup[g.Name]
		sort.Strings(names)
		cfg.Groups = append(cfg.Groups, Group{
			Name: g.Name, Color: g.Color, Software: soft, ScriptPolicies: names,
		})
	}
	sort.Slice(cfg.Groups, func(i, j int) bool { return cfg.Groups[i].Name < cfg.Groups[j].Name })

	// Тела скриптов уезжают в отдельные файлы; в YAML остаётся ссылка. Возвращаем их
	// вызывающему, а не пишем здесь: экспорт должен быть проверяем тестом без диска.
	files := map[string]string{}
	for _, s := range scripts {
		item := Script{Name: s.Name, Platform: s.Platform}
		if scriptsDir == "" {
			item.Content = s.Content
		} else {
			rel := filepath.Join(scriptsDir, slug(s.Name)+scriptExt(s.Platform))
			files[rel] = s.Content
			item.File = filepath.ToSlash(rel)
		}
		cfg.Scripts = append(cfg.Scripts, item)
	}
	sort.Slice(cfg.Scripts, func(i, j int) bool { return cfg.Scripts[i].Name < cfg.Scripts[j].Name })

	for _, p := range policies {
		cfg.ScriptPolicies = append(cfg.ScriptPolicies, ScriptPolicy{
			Name:     p.Name,
			Script:   p.ScriptName,
			Trigger:  p.TriggerType,
			Schedule: decodeJSONMap(p.ScheduleConfig),
			Event:    decodeJSONMap(p.EventTriggerConfig),
			Active:   p.IsActive,
		})
	}
	sort.Slice(cfg.ScriptPolicies, func(i, j int) bool { return cfg.ScriptPolicies[i].Name < cfg.ScriptPolicies[j].Name })

	return cfg, files, nil
}

// decodeJSONMap — schedule_config/event_trigger_config приезжают сырым JSON, и сервер
// отдаёт литеральный "null", когда конфига нет. Не разобралось — отдаём nil, а не
// падаем: конфиг триггера не должен ронять экспорт всего парка.
func decodeJSONMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

var nonSlug = regexp.MustCompile(`[^a-z0-9а-яё]+`)

// slug — имя файла из имени скрипта. Кириллицу оставляем как есть: имена у нас русские,
// транслитерация сделала бы имена файлов нечитаемыми, а файловые системы, где это
// проблема, мы не поддерживаем.
func slug(name string) string {
	s := nonSlug.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "script"
	}
	return s
}

func scriptExt(platform string) string {
	switch strings.ToLower(platform) {
	case "windows":
		return ".ps1"
	default:
		return ".sh"
	}
}

// writeScriptFiles кладёт тела скриптов рядом с YAML. base — каталог YAML-файла.
func writeScriptFiles(base string, files map[string]string) error {
	for rel, content := range files {
		full := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return fmt.Errorf("запись %s: %w", full, err)
		}
	}
	return nil
}
