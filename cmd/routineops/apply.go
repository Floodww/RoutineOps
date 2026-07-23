package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// action — один шаг плана. Описание пишется для человека и печатается ДО применения:
// apply меняет конфигурацию парка, вплоть до того, какие скрипты поедут на машины,
// поэтому «что именно произойдёт» оператор обязан увидеть заранее.
type action struct {
	desc string
	do   func() error
}

// applyPlan — что apply сделает с сервером.
//
// 🔴 Скоуп: файл управляет ТОЛЬКО тем, что в нём названо. Группа, не упомянутая в YAML,
// не трогается вообще — `apply -f accounting.yaml` не должен снести настройки соседнего
// отдела. Внутри же названной группы перечисленные коллекции авторитетны: правило,
// которого нет в файле, удаляется, иначе YAML перестал бы описывать реальность и убрать
// правило через него стало бы невозможно.
//
// Отличие «не управляем» от «управляем, должно быть пусто» — nil против пустого списка:
// ключ software вообще не указан → аспект не трогаем; `software: []` → правил быть не
// должно. Без этого различения нельзя было бы описать группу без софт-правил.
func applyPlan(c *client, cfg *Config, baseDir string) ([]action, error) {
	var groups []apiGroup
	if err := c.get("/device-groups", &groups); err != nil {
		return nil, err
	}
	var rules []apiPolicyRule
	if err := c.get("/policies", &rules); err != nil {
		return nil, err
	}
	var scripts []apiScript
	if err := c.get("/scripts", &scripts); err != nil {
		return nil, err
	}
	var policies []apiScriptPolicy
	if err := c.get("/script-policies", &policies); err != nil {
		return nil, err
	}

	groupByName := map[string]apiGroup{}
	for _, g := range groups {
		groupByName[key(g.Name)] = g
	}
	scriptByName := map[string]apiScript{}
	for _, s := range scripts {
		scriptByName[key(s.Name)] = s
	}
	policyByName := map[string]apiScriptPolicy{}
	for _, p := range policies {
		policyByName[key(p.Name)] = p
	}

	var plan []action

	// 1. Скрипты — первыми: скрипт-политики ссылаются на них, а группы ссылаются на
	// политики. Обратный порядок означал бы «политика на несуществующий скрипт».
	for _, want := range cfg.Scripts {
		content, err := scriptContent(want, baseDir)
		if err != nil {
			return nil, err
		}
		want := want
		cur, ok := scriptByName[key(want.Name)]
		if !ok {
			plan = append(plan, action{
				desc: fmt.Sprintf("создать скрипт %q (%s)", want.Name, want.Platform),
				do: func() error {
					var created apiScript
					err := c.post("/scripts", map[string]string{
						"name": want.Name, "platform": want.Platform, "content": content,
					}, &created)
					if err == nil {
						scriptByName[key(want.Name)] = created
					}
					return err
				},
			})
			continue
		}
		if cur.Platform == want.Platform && cur.Content == content {
			continue
		}
		plan = append(plan, action{
			desc: fmt.Sprintf("обновить скрипт %q%s", want.Name, platformNote(cur.Platform, want.Platform)),
			do: func() error {
				return c.put("/scripts/"+cur.ID, map[string]string{
					"name": want.Name, "platform": want.Platform, "content": content,
				}, nil)
			},
		})
	}

	// 2. Скрипт-политики.
	for _, want := range cfg.ScriptPolicies {
		want := want
		body := func() (map[string]any, error) {
			s, ok := scriptByName[key(want.Script)]
			if !ok {
				return nil, fmt.Errorf("политика %q ссылается на скрипт %q, которого нет ни в файле, ни на сервере", want.Name, want.Script)
			}
			b := map[string]any{"name": want.Name, "script_id": s.ID, "trigger_type": want.Trigger}
			if len(want.Schedule) > 0 {
				b["schedule_config"] = want.Schedule
			}
			if len(want.Event) > 0 {
				b["event_trigger_config"] = want.Event
			}
			return b, nil
		}
		cur, ok := policyByName[key(want.Name)]
		if !ok {
			plan = append(plan, action{
				desc: fmt.Sprintf("создать скрипт-политику %q (скрипт %q, триггер %s)", want.Name, want.Script, want.Trigger),
				do: func() error {
					b, err := body()
					if err != nil {
						return err
					}
					var created apiScriptPolicy
					if err := c.post("/script-policies", b, &created); err != nil {
						return err
					}
					policyByName[key(want.Name)] = created
					if !want.Active {
						return c.patch("/script-policies/"+created.ID+"/toggle", map[string]bool{"is_active": false}, nil)
					}
					return nil
				},
			})
			continue
		}
		if policyChanged(cur, want, scriptByName) {
			plan = append(plan, action{
				desc: fmt.Sprintf("обновить скрипт-политику %q", want.Name),
				do: func() error {
					b, err := body()
					if err != nil {
						return err
					}
					return c.put("/script-policies/"+cur.ID, b, nil)
				},
			})
		}
		if cur.IsActive != want.Active {
			plan = append(plan, action{
				desc: fmt.Sprintf("скрипт-политика %q: %s", want.Name, onOff(want.Active)),
				do: func() error {
					return c.patch("/script-policies/"+cur.ID+"/toggle", map[string]bool{"is_active": want.Active}, nil)
				},
			})
		}
	}

	// 3. Группы, их софт-правила и назначения политик.
	for _, want := range cfg.Groups {
		want := want
		cur, ok := groupByName[key(want.Name)]
		if !ok {
			plan = append(plan, action{
				desc: fmt.Sprintf("создать группу %q", want.Name),
				do: func() error {
					var created apiGroup
					if err := c.post("/device-groups", map[string]string{"name": want.Name, "color": want.Color}, &created); err != nil {
						return err
					}
					groupByName[key(want.Name)] = created
					return nil
				},
			})
		} else if want.Color != "" && !strings.EqualFold(want.Color, cur.Color) {
			plan = append(plan, action{
				desc: fmt.Sprintf("группа %q: цвет %s → %s", want.Name, cur.Color, want.Color),
				do: func() error {
					return c.patch("/device-groups/"+cur.ID, map[string]string{"color": want.Color}, nil)
				},
			})
		}

		// groupID берём отложенно: группа могла быть создана шагом выше, и её id
		// появится только в момент выполнения плана.
		groupID := func() (string, error) {
			g, ok := groupByName[key(want.Name)]
			if !ok || g.ID == "" {
				return "", fmt.Errorf("группа %q не найдена после создания", want.Name)
			}
			return g.ID, nil
		}

		if want.Software != nil {
			curRules := map[string]apiPolicyRule{}
			if ok {
				for _, r := range rules {
					if r.GroupID != nil && *r.GroupID == cur.ID && r.DeviceID == nil {
						curRules[key(r.SoftwareName)] = r
					}
				}
			}
			for _, sw := range want.Software {
				sw := sw
				if have, exists := curRules[key(sw.Name)]; exists {
					if have.RuleType == sw.Rule {
						delete(curRules, key(sw.Name))
						continue
					}
					// Смена типа правила = снять старое и поставить новое: отдельной
					// ручки правки у софт-правил нет.
					have := have
					plan = append(plan, action{
						desc: fmt.Sprintf("группа %q: %q %s → %s", want.Name, sw.Name, have.RuleType, sw.Rule),
						do: func() error {
							id, err := groupID()
							if err != nil {
								return err
							}
							if err := c.delete("/device-groups/" + id + "/software-policies/" + have.ID); err != nil {
								return err
							}
							return c.post("/device-groups/"+id+"/software-policies",
								map[string]string{"software_name": sw.Name, "rule_type": sw.Rule}, nil)
						},
					})
					delete(curRules, key(sw.Name))
					continue
				}
				plan = append(plan, action{
					desc: fmt.Sprintf("группа %q: добавить %s-правило %q", want.Name, sw.Rule, sw.Name),
					do: func() error {
						id, err := groupID()
						if err != nil {
							return err
						}
						return c.post("/device-groups/"+id+"/software-policies",
							map[string]string{"software_name": sw.Name, "rule_type": sw.Rule}, nil)
					},
				})
			}
			for _, extra := range sortedRules(curRules) {
				extra := extra
				plan = append(plan, action{
					desc: fmt.Sprintf("группа %q: удалить %s-правило %q (нет в файле)", want.Name, extra.RuleType, extra.SoftwareName),
					do: func() error {
						id, err := groupID()
						if err != nil {
							return err
						}
						return c.delete("/device-groups/" + id + "/software-policies/" + extra.ID)
					},
				})
			}
		}

		if want.ScriptPolicies != nil {
			curAssigned := map[string]bool{}
			for _, p := range policies {
				for _, gn := range p.GroupNames {
					if key(gn) == key(want.Name) {
						curAssigned[key(p.Name)] = true
					}
				}
			}
			for _, pn := range want.ScriptPolicies {
				pn := pn
				if curAssigned[key(pn)] {
					delete(curAssigned, key(pn))
					continue
				}
				plan = append(plan, action{
					desc: fmt.Sprintf("группа %q: назначить политику %q", want.Name, pn),
					do: func() error {
						id, err := groupID()
						if err != nil {
							return err
						}
						p, ok := policyByName[key(pn)]
						if !ok {
							return fmt.Errorf("группа %q ссылается на политику %q, которой нет ни в файле, ни на сервере", want.Name, pn)
						}
						return c.post("/device-groups/"+id+"/policies", map[string]string{"policy_id": p.ID}, nil)
					},
				})
			}
			for _, pn := range sortedKeys(curAssigned) {
				pn := pn
				plan = append(plan, action{
					desc: fmt.Sprintf("группа %q: снять политику %q (нет в файле)", want.Name, policyByName[pn].Name),
					do: func() error {
						id, err := groupID()
						if err != nil {
							return err
						}
						return c.delete("/device-groups/" + id + "/policies/" + policyByName[pn].ID)
					},
				})
			}
		}
	}

	return plan, nil
}

// policyChanged — сравниваем ровно те поля, которыми управляет YAML. is_active сюда не
// входит: у него отдельная ручка toggle и отдельный шаг плана.
func policyChanged(cur apiScriptPolicy, want ScriptPolicy, scripts map[string]apiScript) bool {
	if cur.TriggerType != want.Trigger {
		return true
	}
	if key(cur.ScriptName) != key(want.Script) {
		return true
	}
	if s, ok := scripts[key(want.Script)]; ok && cur.ScriptID != s.ID {
		return true
	}
	return !sameJSON(cur.ScheduleConfig, want.Schedule) || !sameJSON(cur.EventTriggerConfig, want.Event)
}

// sameJSON сравнивает конфиг триггера с сервера и из YAML по значению. Через
// json.Marshal обеих сторон, а не по строкам: сервер отдаёт JSONB с собственным
// форматированием и порядком ключей, и побайтовое сравнение давало бы вечный «дифф».
func sameJSON(raw json.RawMessage, want map[string]any) bool {
	a := decodeJSONMap(raw)
	if len(a) == 0 && len(want) == 0 {
		return true
	}
	x, err1 := json.Marshal(normalizeJSON(a))
	y, err2 := json.Marshal(normalizeJSON(want))
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// normalizeJSON прогоняет значение через JSON-раунд-трип: числа из YAML приезжают int,
// а из JSON — float64, и без этого «5» != «5» роняло бы сравнение в вечное различие.
func normalizeJSON(v map[string]any) map[string]any {
	if len(v) == 0 {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return v
	}
	return out
}

// scriptContent — тело скрипта из файла рядом с YAML или инлайна. Задано и то и другое —
// ошибка, а не «молча выберем одно»: разошедшиеся копии тела скрипта, который поедет на
// машины, обязаны падать на месте.
func scriptContent(s Script, baseDir string) (string, error) {
	if s.File != "" && s.Content != "" {
		return "", fmt.Errorf("скрипт %q: заданы и file, и content — оставьте одно", s.Name)
	}
	if s.File == "" {
		if s.Content == "" {
			return "", fmt.Errorf("скрипт %q: пустое тело (нужен file или content)", s.Name)
		}
		return s.Content, nil
	}
	if filepath.IsAbs(s.File) || strings.Contains(s.File, "..") {
		// Путь из файла конфигурации не должен уводить за пределы каталога с YAML.
		return "", fmt.Errorf("скрипт %q: путь %q должен быть относительным и без ..", s.Name, s.File)
	}
	raw, err := os.ReadFile(filepath.Join(baseDir, filepath.FromSlash(s.File)))
	if err != nil {
		return "", fmt.Errorf("скрипт %q: %w", s.Name, err)
	}
	return string(raw), nil
}

// key — ключ сравнения имён. Совпадает с уникальными индексами на сервере
// (lower(btrim(name)) в миграциях 026 и 033): «  Бухгалтерия » и «бухгалтерия» — одно
// и то же, иначе apply попытался бы создать дубль и упёрся в 409.
func key(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func onOff(active bool) string {
	if active {
		return "включить"
	}
	return "выключить"
}

func platformNote(cur, want string) string {
	if cur == want {
		return ""
	}
	return fmt.Sprintf(" (платформа %s → %s)", cur, want)
}

func sortedRules(m map[string]apiPolicyRule) []apiPolicyRule {
	out := make([]apiPolicyRule, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SoftwareName < out[j].SoftwareName })
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
