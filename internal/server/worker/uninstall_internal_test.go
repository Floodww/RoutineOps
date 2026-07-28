package worker

import (
	"strings"
	"testing"

	pb "github.com/Floodww/RoutineOps/proto"
)

// 🔴 Метод — предмет СВЕРКИ на агенте: он сравнивает присланный с тем, что определил
// сам, и при расхождении отказывает TARGET_CHANGED. Значит, разъезд двух половин
// маппинга (gateway пишет строку в БД, worker читает её обратно в enum) проявится не
// компиляцией и не тестом, а отказом сноса на живой машине.
//
// Поэтому проверяем ВЕСЬ enum из proto, а не список, выписанный руками: добавление
// нового метода в контракт автоматически попадает под проверку. Список пришлось бы
// дописывать — и никто бы не дописал.
func TestUninstallMethodFromString_CoversWholeEnum(t *testing.T) {
	for value, name := range pb.UninstallMethod_name {
		if pb.UninstallMethod(value) == pb.UninstallMethod_UNINSTALL_METHOD_UNSPECIFIED {
			continue
		}
		// Канон БД (миграция 036) — ровно то, что пишет gateway.uninstallMethodToString.
		canonical := strings.ToLower(strings.TrimPrefix(name, "UNINSTALL_METHOD_"))
		if got := uninstallMethodFromString(canonical); got != pb.UninstallMethod(value) {
			t.Errorf("%q → %v, ожидался %v", canonical, got, pb.UninstallMethod(value))
		}
	}
}

// Неизвестное и пустое значение дают UNSPECIFIED, и это fail-closed: агент сверит его
// со своим методом и откажет, вместо того чтобы снести цель наугад. Регистр прощаем —
// канон в БД нижний, но данные из старых снимков надёжнее принять, чем отвергнуть.
func TestUninstallMethodFromString_UnknownIsUnspecified(t *testing.T) {
	for _, s := range []string{"", "нет такого метода", "chocolatey"} {
		if got := uninstallMethodFromString(s); got != pb.UninstallMethod_UNINSTALL_METHOD_UNSPECIFIED {
			t.Errorf("%q → %v, ожидался UNSPECIFIED", s, got)
		}
	}
	if got := uninstallMethodFromString("MSI"); got != pb.UninstallMethod_UNINSTALL_METHOD_MSI {
		t.Errorf("верхний регистр → %v", got)
	}
}
