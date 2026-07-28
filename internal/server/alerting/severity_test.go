package alerting_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/alerting"
)

func TestDefaultFor(t *testing.T) {
	cases := []struct {
		alertType string
		want      alerting.Severity
	}{
		{"filevault_revoke_failed", alerting.SeverityCritical},
		{"lock_tamper", alerting.SeverityCritical},
		{"filevault_secret_mismatch", alerting.SeverityHigh},
		{"outbox_unavailable", alerting.SeverityHigh},
		{"forbidden_software", alerting.SeverityHigh},
		{"unauthorized_install", alerting.SeverityMedium},
		{"unauthorized_settings_change", alerting.SeverityMedium},
		{"agent_unreachable", alerting.SeverityLow},

		// Нормализация: alert_type — свободный TEXT, регистр и пробелы не должны
		// ронять классификацию в UnknownSeverity.
		{"  LOCK_TAMPER  ", alerting.SeverityCritical},

		// Неизвестный тип — high (агент новее сервера), см. UnknownSeverity.
		{"something_new_from_a_newer_agent", alerting.SeverityHigh},
		{"", alerting.SeverityHigh},
	}
	for _, c := range cases {
		if got := alerting.DefaultFor(c.alertType); got != c.want {
			t.Errorf("DefaultFor(%q) = %q, want %q", c.alertType, got, c.want)
		}
	}
}

func TestParse(t *testing.T) {
	for _, s := range alerting.All() {
		got, ok := alerting.Parse(string(s))
		if !ok || got != s {
			t.Errorf("Parse(%q) = %q, %v; want %q, true", s, got, ok, s)
		}
	}
	if got, ok := alerting.Parse(" CRITICAL "); !ok || got != alerting.SeverityCritical {
		t.Errorf("Parse(\" CRITICAL \") = %q, %v", got, ok)
	}
	// Опечатка не должна молча становиться уровнем по умолчанию: это превратило бы
	// ошибку оператора в тихое понижение критичности.
	for _, bad := range []string{"", "urgent", "sev1", "critical!", "hi"} {
		if _, ok := alerting.Parse(bad); ok {
			t.Errorf("Parse(%q) принят, а не должен", bad)
		}
	}
}

func TestRankOrdering(t *testing.T) {
	all := alerting.All()
	for i := 1; i < len(all); i++ {
		if alerting.Rank(all[i-1]) <= alerting.Rank(all[i]) {
			t.Fatalf("All() не по убыванию важности: %q(%d) <= %q(%d)",
				all[i-1], alerting.Rank(all[i-1]), all[i], alerting.Rank(all[i]))
		}
	}
	// Неизвестный уровень весит 0 — уезжает в конец списка, а не в начало.
	if alerting.Rank("nonsense") != 0 {
		t.Errorf("Rank(nonsense) = %d, want 0", alerting.Rank("nonsense"))
	}
}

func TestDeliverToFailsOpen(t *testing.T) {
	cases := []struct {
		sev, threshold alerting.Severity
		want           bool
	}{
		{alerting.SeverityCritical, alerting.SeverityCritical, true},
		{alerting.SeverityHigh, alerting.SeverityCritical, false},
		{alerting.SeverityLow, alerting.SeverityLow, true},
		{alerting.SeverityMedium, alerting.SeverityLow, true},
		{alerting.SeverityLow, alerting.SeverityMedium, false},

		// Битые значения (ручной UPDATE в psql, рассинхрон кода и схемы) обязаны
		// доставляться: непришедшее уведомление о реальном инциденте ничем себя не
		// проявляет, лишнее сообщение в Telegram — проявляет.
		{"garbage", alerting.SeverityCritical, true},
		{alerting.SeverityLow, "garbage", true},
		{"", "", true},
	}
	for _, c := range cases {
		if got := alerting.DeliverTo(c.sev, c.threshold); got != c.want {
			t.Errorf("DeliverTo(%q, %q) = %v, want %v", c.sev, c.threshold, got, c.want)
		}
	}
}

func TestTypeRankPreservesUIOrder(t *testing.T) {
	// Порядок, который оператор видел до 041 (TYPE_ORDER в web/src/pages/Alerts.tsx).
	// Сортировка «сначала по severity, потом по TypeRank» обязана его воспроизводить —
	// иначе перенос знания на сервер незаметно переставил бы секции местами.
	before := []string{
		"filevault_revoke_failed",
		"lock_tamper",
		"filevault_secret_mismatch",
		"outbox_unavailable",
		"forbidden_software",
		"unauthorized_install",
		"unauthorized_settings_change",
		"agent_unreachable",
	}
	after := append([]string(nil), before...)
	sort.SliceStable(after, func(i, j int) bool {
		si, sj := alerting.DefaultFor(after[i]), alerting.DefaultFor(after[j])
		if ri, rj := alerting.Rank(si), alerting.Rank(sj); ri != rj {
			return ri > rj
		}
		return alerting.TypeRank(after[i]) < alerting.TypeRank(after[j])
	})
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("порядок секций изменился:\nбыло:  %v\nстало: %v", before, after)
		}
	}

	if alerting.TypeRank("unknown_type") <= alerting.TypeRank("agent_unreachable") {
		t.Error("неизвестный тип обязан сортироваться после всех известных")
	}
}

// caseArmRe вытаскивает пары WHEN 'alert_type' THEN 'severity' из бэкфилла в 041.
var caseArmRe = regexp.MustCompile(`WHEN\s+'([a-z_]+)'\s+THEN\s+'([a-z]+)'`)

// TestDefaultsMatchMigration — гейт против рассинхрона SQL и Go.
//
// Бэкфилл существующих строк выполняется в миграции, до старта сервера, и вызвать
// DefaultFor оттуда нечем — карта неизбежно продублирована. Дубль безопасен ровно
// до тех пор, пока за ним следят: расхождение означало бы, что старые алерты
// классифицированы по одному правилу, новые — по другому, и сортировка в списке
// перестала бы быть осмысленной.
func TestDefaultsMatchMigration(t *testing.T) {
	path := filepath.Join("..", "..", "..", "migrations", "041_alert_severity.sql")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не читается %s: %v", path, err)
	}
	arms := caseArmRe.FindAllStringSubmatch(string(body), -1)
	if len(arms) == 0 {
		t.Fatal("в 041 не найдено ни одной ветки CASE — сломался парсер, а не миграция")
	}
	for _, m := range arms {
		alertType, want := m[1], alerting.Severity(m[2])
		if got := alerting.DefaultFor(alertType); got != want {
			t.Errorf("%s: миграция говорит %q, alerting.DefaultFor — %q", alertType, want, got)
		}
	}

	// Обратная сторона: тип, добавленный в Go и забытый в миграции, оставил бы
	// уже существующие строки этого типа с бэкфиллом по ветке ELSE.
	inSQL := make(map[string]bool, len(arms))
	for _, m := range arms {
		inSQL[m[1]] = true
	}
	var missing []string
	for _, known := range knownTypes(t) {
		if !inSQL[known] {
			missing = append(missing, known)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("типы есть в alerting, но не в CASE миграции 041: %s", strings.Join(missing, ", "))
	}
}

// knownTypes перечисляет типы, которым alerting выдаёт НЕ UnknownSeverity, — то
// есть те, что реально описаны картой, а не попали под общее правило.
func knownTypes(t *testing.T) []string {
	t.Helper()
	candidates := []string{
		"filevault_revoke_failed",
		"lock_tamper",
		"filevault_secret_mismatch",
		"outbox_unavailable",
		"forbidden_software",
		"unauthorized_install",
		"unauthorized_settings_change",
		"agent_unreachable",
	}
	var known []string
	for _, c := range candidates {
		if alerting.TypeRank(c) < len(candidates) {
			known = append(known, c)
		}
	}
	return known
}
