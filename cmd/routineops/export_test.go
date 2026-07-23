package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// fakeServer отдаёт четыре ручки, из которых собирается конфигурация. Ходим по HTTP, а
// не подменяем функции: так тест заодно проверяет заголовок авторизации и разбор
// ответов — то, на чём CLI ломается в первую очередь.
func fakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	body := map[string]string{
		"/api/v1/device-groups": `[
			{"id":"GRP-BBB","name":"Разработка","color":"#10b981"},
			{"id":"GRP-AAA","name":"Бухгалтерия","color":"#3b82f6"}
		]`,
		"/api/v1/policies": `[
			{"id":"RUL-AAA","software_name":"uTorrent","rule_type":"forbidden","device_id":null,"group_id":"GRP-AAA","platforms":["Windows"]},
			{"id":"RUL-BBB","software_name":"1С","rule_type":"allowed","device_id":null,"group_id":"GRP-AAA","platforms":[]},
			{"id":"RUL-CCC","software_name":"Глобальное","rule_type":"forbidden","device_id":null,"group_id":null,"platforms":[]},
			{"id":"RUL-DDD","software_name":"Девайсное","rule_type":"forbidden","device_id":"DEV-AAA","group_id":"GRP-AAA","platforms":[]}
		]`,
		"/api/v1/scripts": `[
			{"id":"SCR-AAA","name":"Проверка антивируса","platform":"Windows","content":"Get-Service\n"}
		]`,
		"/api/v1/script-policies": `[
			{"id":"POL-AAA","name":"Ежедневная проверка","script_id":"SCR-AAA","script_name":"Проверка антивируса",
			 "trigger_type":"schedule","schedule_config":{"cron":"0 9 * * *"},"event_trigger_config":null,
			 "is_active":true,"group_names":["Бухгалтерия"]}
		]`,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, ok := body[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(b))
	}))
}

func TestExportConfig(t *testing.T) {
	srv := fakeServer(t)
	defer srv.Close()
	c, err := newClient(srv.URL, "tok", "")
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}

	cfg, files, err := exportConfig(c, "scripts")
	if err != nil {
		t.Fatalf("exportConfig: %v", err)
	}

	// Порядок по имени, а не как отдал сервер: иначе каждый export даёт шумный diff.
	if len(cfg.Groups) != 2 || cfg.Groups[0].Name != "Бухгалтерия" {
		t.Fatalf("группы не отсортированы по имени: %+v", cfg.Groups)
	}

	buh := cfg.Groups[0]
	if len(buh.Software) != 2 || buh.Software[0].Name != "1С" || buh.Software[1].Name != "uTorrent" {
		t.Errorf("софт-правила группы = %+v", buh.Software)
	}
	// 🔴 Глобальное правило (group_id=null) и девайсное (device_id задан) в YAML не
	// попадают: первое не принадлежит группе, второе — инвентарь, которого тут не бывает.
	for _, s := range buh.Software {
		if s.Name == "Глобальное" || s.Name == "Девайсное" {
			t.Errorf("в YAML утекло правило вне группы: %s", s.Name)
		}
	}
	if len(buh.ScriptPolicies) != 1 || buh.ScriptPolicies[0] != "Ежедневная проверка" {
		t.Errorf("привязка политик к группе = %v", buh.ScriptPolicies)
	}
	if len(cfg.Groups[1].Software) != 0 || len(cfg.Groups[1].ScriptPolicies) != 0 {
		t.Errorf("чужие правила/политики приписаны второй группе: %+v", cfg.Groups[1])
	}

	// Тело скрипта уходит файлом, в YAML остаётся ссылка — иначе git-diff по скрипту
	// нечитаем, а правка одной строки переписывает YAML целиком.
	if len(cfg.Scripts) != 1 || cfg.Scripts[0].File != "scripts/проверка-антивируса.ps1" {
		t.Fatalf("ссылка на файл скрипта = %+v", cfg.Scripts)
	}
	if cfg.Scripts[0].Content != "" {
		t.Error("тело скрипта продублировано инлайном")
	}
	if got := files["scripts/проверка-антивируса.ps1"]; got != "Get-Service\n" {
		t.Errorf("содержимое файла скрипта = %q", got)
	}

	pol := cfg.ScriptPolicies[0]
	if pol.Script != "Проверка антивируса" {
		t.Errorf("политика ссылается на скрипт по имени, а не id: %q", pol.Script)
	}
	if pol.Schedule["cron"] != "0 9 * * *" {
		t.Errorf("schedule = %v", pol.Schedule)
	}
	if pol.Event != nil {
		t.Errorf("пустой event_trigger_config обязан быть nil, а не %v", pol.Event)
	}
}

// YAML должен читаться человеком и не содержать id: файл переносим между инсталляциями,
// а diff в git — это то, ради чего фича существует.
func TestExportYAML_NoIDs(t *testing.T) {
	srv := fakeServer(t)
	defer srv.Close()
	c, _ := newClient(srv.URL, "tok", "")
	cfg, _, err := exportConfig(c, "scripts")
	if err != nil {
		t.Fatalf("exportConfig: %v", err)
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out := string(raw)
	for _, id := range []string{"GRP-AAA", "GRP-BBB", "SCR-AAA", "POL-AAA", "RUL-AAA", "DEV-AAA"} {
		if strings.Contains(out, id) {
			t.Errorf("в YAML утёк идентификатор %q:\n%s", id, out)
		}
	}
	if !strings.Contains(out, "apiVersion: routineops/v1") {
		t.Errorf("нет версии схемы:\n%s", out)
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"Проверка антивируса": "проверка-антивируса",
		"  Disk  Cleanup  ":   "disk-cleanup",
		"!!!":                 "script",
	} {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}
