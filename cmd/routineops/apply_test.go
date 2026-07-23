package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// recordingServer — тот же набор ручек, что у fakeServer, плюс журнал мутаций. План
// проверяем не по строкам описаний, а по тому, ЧТО реально уехало на сервер.
type recordingServer struct {
	*httptest.Server
	calls []string
}

func newRecordingServer(t *testing.T) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	base := fakeServer(t)
	t.Cleanup(base.Close)
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// GET-ы проксируем на fakeServer: состояние «до» у обоих тестов общее.
			resp, err := http.Get(base.URL + r.URL.Path)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		rs.calls = append(rs.calls, r.Method+" "+r.URL.Path+" "+strings.TrimSpace(string(body)))
		w.Header().Set("Content-Type", "application/json")
		// Ответ на создание: id, по которому следующие шаги плана свяжут ресурсы.
		_, _ = w.Write([]byte(`{"id":"NEW-ID","name":"x","platform":"Windows","content":"","group_names":[]}`))
	}))
	t.Cleanup(rs.Server.Close)
	return rs
}

// GET-прокси добавляет Authorization сам: fakeServer его требует.
func init() { http.DefaultTransport = authRoundTripper{http.DefaultTransport} }

type authRoundTripper struct{ base http.RoundTripper }

func (a authRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer tok")
	return a.base.RoundTrip(r)
}

func planFor(t *testing.T, yamlSrc string) ([]action, *recordingServer, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "routineops.yaml")
	if err := os.WriteFile(path, []byte(yamlSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlSrc), &cfg); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	rs := newRecordingServer(t)
	c, err := newClient(rs.URL, "tok", "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := applyPlan(c, &cfg, dir)
	if err != nil {
		t.Fatalf("applyPlan: %v", err)
	}
	return plan, rs, dir
}

// Файл, совпадающий с состоянием сервера, обязан давать ПУСТОЙ план. Идемпотентность —
// главное свойство apply: повторный прогон не должен ничего трогать, иначе оператор
// перестанет ему верить и начнёт обходить руками.
func TestApplyPlan_Idempotent(t *testing.T) {
	src := `
apiVersion: routineops/v1
groups:
  - name: Бухгалтерия
    color: '#3b82f6'
    software:
      - name: 1С
        rule: allowed
      - name: uTorrent
        rule: forbidden
    scriptPolicies: [Ежедневная проверка]
scripts:
  - name: Проверка антивируса
    platform: Windows
    content: "Get-Service\n"
scriptPolicies:
  - name: Ежедневная проверка
    script: Проверка антивируса
    trigger: schedule
    schedule:
      cron: '0 9 * * *'
    active: true
`
	plan, _, _ := planFor(t, src)
	if len(plan) != 0 {
		var got []string
		for _, a := range plan {
			got = append(got, a.desc)
		}
		t.Fatalf("повторный apply не пустой: %v", got)
	}
}

// Группа, которой нет в файле, не должна пострадать: `apply -f accounting.yaml` не
// трогает соседний отдел. А внутри названной группы список правил авторитетен.
func TestApplyPlan_ScopeAndPrune(t *testing.T) {
	src := `
apiVersion: routineops/v1
groups:
  - name: Бухгалтерия
    software:
      - name: 1С
        rule: forbidden
`
	plan, _, _ := planFor(t, src)
	descs := strings.Join(descList(plan), "\n")
	if strings.Contains(descs, "Разработка") {
		t.Errorf("тронута группа, которой нет в файле:\n%s", descs)
	}
	if !strings.Contains(descs, `"1С" allowed → forbidden`) {
		t.Errorf("не увидел смену типа правила:\n%s", descs)
	}
	// uTorrent есть на сервере, но не в файле → внутри управляемой группы он лишний.
	if !strings.Contains(descs, `удалить forbidden-правило "uTorrent"`) {
		t.Errorf("лишнее правило не удаляется:\n%s", descs)
	}
	// Ключ scriptPolicies не указан вообще → аспектом не управляем, назначение не трогаем.
	if strings.Contains(descs, "политику") {
		t.Errorf("тронуты назначения политик, хотя ключа в файле нет:\n%s", descs)
	}
}

// Пустой список — это «должно быть пусто», в отличие от отсутствующего ключа.
func TestApplyPlan_EmptyListMeansEmpty(t *testing.T) {
	src := `
groups:
  - name: Бухгалтерия
    scriptPolicies: []
`
	plan, _, _ := planFor(t, src)
	descs := strings.Join(descList(plan), "\n")
	if !strings.Contains(descs, `снять политику "Ежедневная проверка"`) {
		t.Errorf("пустой список не снял назначение:\n%s", descs)
	}
}

// Новые ресурсы создаются в правильном порядке и с правильными телами запросов.
func TestApply_CreatesInDependencyOrder(t *testing.T) {
	src := `
scripts:
  - name: Новый скрипт
    platform: Linux
    content: "uname -a\n"
scriptPolicies:
  - name: Новая политика
    script: Новый скрипт
    trigger: on_connect
    active: false
groups:
  - name: Новая группа
    color: '#ff0000'
    scriptPolicies: [Новая политика]
`
	plan, rs, _ := planFor(t, src)
	for i, a := range plan {
		if err := a.do(); err != nil {
			t.Fatalf("шаг %d (%s): %v", i, a.desc, err)
		}
	}
	joined := strings.Join(rs.calls, "\n")
	for _, want := range []string{
		"POST /api/v1/scripts",
		"POST /api/v1/script-policies",
		"PATCH /api/v1/script-policies/NEW-ID/toggle",
		"POST /api/v1/device-groups",
		"POST /api/v1/device-groups/NEW-ID/policies",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("не было вызова %s:\n%s", want, joined)
		}
	}
	// Скрипт обязан создаваться ДО политики, которая на него ссылается.
	if idxOf(rs.calls, "POST /api/v1/scripts") > idxOf(rs.calls, "POST /api/v1/script-policies") {
		t.Errorf("политика создана раньше своего скрипта:\n%s", joined)
	}
	// active: false доезжает отдельным шагом toggle — сервер создаёт политику активной.
	if !strings.Contains(joined, `"is_active":false`) {
		t.Errorf("политика осталась включённой:\n%s", joined)
	}
}

// Тело скрипта берётся из файла рядом с YAML; выход за пределы каталога запрещён.
func TestScriptContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.sh"), []byte("echo hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := scriptContent(Script{Name: "s", File: "a.sh"}, dir)
	if err != nil || got != "echo hi\n" {
		t.Fatalf("scriptContent = %q, %v", got, err)
	}
	if _, err := scriptContent(Script{Name: "s", File: "../../etc/passwd"}, dir); err == nil {
		t.Error("путь с .. обязан отбиваться")
	}
	if _, err := scriptContent(Script{Name: "s", File: "a.sh", Content: "x"}, dir); err == nil {
		t.Error("file и content вместе обязаны быть ошибкой")
	}
	if _, err := scriptContent(Script{Name: "s"}, dir); err == nil {
		t.Error("пустое тело обязано быть ошибкой")
	}
}

// Число из YAML приезжает int, из JSON — float64. Без нормализации одинаковый конфиг
// вечно выглядел бы изменённым и apply переписывал бы политику на каждом прогоне.
func TestSameJSON_NumbersAcrossFormats(t *testing.T) {
	if !sameJSON(json.RawMessage(`{"every_minutes":5}`), map[string]any{"every_minutes": 5}) {
		t.Error("int из YAML не сошёлся с числом из JSON")
	}
	if !sameJSON(json.RawMessage(`null`), nil) {
		t.Error("null и nil должны совпадать")
	}
	if sameJSON(json.RawMessage(`{"cron":"0 9 * * *"}`), map[string]any{"cron": "0 10 * * *"}) {
		t.Error("разные расписания не должны совпадать")
	}
}

func descList(plan []action) []string {
	out := make([]string, 0, len(plan))
	for _, a := range plan {
		out = append(out, a.desc)
	}
	return out
}

func idxOf(calls []string, prefix string) int {
	for i, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}
