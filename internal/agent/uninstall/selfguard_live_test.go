package uninstall

import (
	"os"
	"strings"
	"testing"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

// Самозащита проверяется на ФАКТИЧЕСКОМ инвентаре живой машины с установленным
// агентом, а не на выдуманной записи.
//
// Причина отдельного теста: табличные проверки в selfguard_test.go подставляют
// поля такими, какими мы их СЧИТАЕМ, — а guard обязан сработать на том, что
// реально лежит в ARP этой машины. Между ними разница ровно того сорта, что
// однажды уже стоила полевого бага: имя продукта в реестре ставит инсталлятор,
// издателя — MSI-свойство Manufacturer, и оба могут разойтись с ожиданиями кода.
// Промах guard'а здесь означает снос агента с парка командой оператора.
//
// Тест ЧИТАЮЩИЙ: он не снимает ПО и не запускает деинсталлятор — только
// спрашивает у guard'а вердикт по каждой записи. Гоняется на стенде:
//
//	ROUTINEOPS_LIVE_INVENTORY=1 uninstall.test.exe -test.run Live
//
// Без переменной пропускается: на машине разработчика и в CI агент не
// установлен, и «записи не нашлось» там означало бы не поломку, а другое
// окружение.
func TestSelfGuard_Live_BlocksRealAgentRecord(t *testing.T) {
	if os.Getenv("ROUTINEOPS_LIVE_INVENTORY") == "" {
		t.Skip("живой инвентарь: ROUTINEOPS_LIVE_INVENTORY=1 на машине с установленным агентом")
	}
	self, err := resolveSelf()
	if err != nil {
		t.Fatalf("resolveSelf: %v", err)
	}

	items := collector.InstalledSoftware()
	if len(items) == 0 {
		t.Fatal("инвентарь пуст — проверять нечего")
	}

	var agentRecords, blocked int
	for _, sw := range items {
		// Запись агента ищем НЕ теми же признаками, которыми её ловит guard
		// (иначе тест проверял бы сам себя): берём вхождение имени продукта или
		// издателя, а вердикт спрашиваем у guard'а.
		looksLikeAgent := strings.Contains(strings.ToLower(sw.Name), "routineops") ||
			strings.Contains(strings.ToLower(sw.Name), "mdm-agent") ||
			strings.Contains(strings.ToLower(sw.Vendor), "routineops")
		reason := self.matchesSoftware(sw)

		if looksLikeAgent {
			agentRecords++
			if reason == "" {
				t.Errorf("guard ПРОПУСТИЛ собственную запись: name=%q vendor=%q id=%q location=%q",
					sw.Name, sw.Vendor, sw.UninstallID, sw.InstallLocation)
				continue
			}
			blocked++
			t.Logf("заблокировано: %q → %s", sw.Name, reason)
			continue
		}
		// Обратная сторона: чужое ПО guard блокировать не должен, иначе фича
		// молча не работает ни на чём.
		if reason != "" {
			t.Errorf("guard принял ЧУЖОЕ ПО за себя: name=%q vendor=%q → %s", sw.Name, sw.Vendor, reason)
		}
	}

	if agentRecords == 0 {
		t.Fatal("в инвентаре нет ни одной записи агента — тест ничего не проверил " +
			"(на этой машине агент не установлен либо назван иначе)")
	}
	t.Logf("записей агента: %d, заблокировано: %d, всего в инвентаре: %d", agentRecords, blocked, len(items))
}
