package decommission

import (
	"strings"
	"testing"
)

// Трактовка кодов возврата msiexec — место, где ошибка стоит дороже всего, и обе
// стороны ошибки одинаково молчаливы:
//
//   - посчитать 1605 («продукта нет») отказом — и штатное снятие на машине с ручной,
//     не-MSI установкой начнёт рапортовать «[ЧАСТИЧНО]» и код 3 на пустом месте;
//   - посчитать 1603 («фатальный сбой удаления») успехом — и ARP-хвост вернётся без
//     единого сигнала, то есть ровно исходный полевой баг, только уже с гейтом,
//     который его не ловит.
//
// 3010 и 1641 документированы Microsoft как УСПЕХ наравне с 0: удаление завершено,
// отложена только физическая чистка занятых файлов. Считать их отказом значило бы
// объявлять сбоем самый ожидаемый исход — батник сам держит открытым свой файл в
// удаляемом каталоге.
func TestClassifyMSIExit(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		want msiOutcome
	}{
		{"0 — снято", msiSuccess, msiOutcomeDone},
		{"1605 — продукта нет, это не ошибка", msiUnknownProduct, msiOutcomeGone},
		{"3010 — снято, файлы уйдут после перезагрузки", msiRebootRequired, msiOutcomeReboot},
		{"1641 — снято, установщик просит перезагрузку", msiRebootInitiated, msiOutcomeReboot},
		{"1618 — установщик занят, повторить", msiInstallBusy, msiOutcomeBusy},
		{"1603 — фатальный сбой удаления", msiInstallFailure, msiOutcomeFailed},
		{"1619 — кэшированный пакет недоступен", msiPackageOpenFail, msiOutcomeFailed},
		{"1620 — пакет повреждён", msiPackageInvalid, msiOutcomeFailed},
		{"1652 — безопасный режим", msiSafeBootDisabled, msiOutcomeFailed},
		{"неизвестный код — отказ, а не успех", 4711, msiOutcomeFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyMSIExit(tc.code); got != tc.want {
				t.Errorf("classifyMSIExit(%d) = %v, ждали %v", tc.code, got, tc.want)
			}
		})
	}
}

// Подсказка обязана быть КОНКРЕТНОЙ там, где оператор иначе застрянет. Особый случай —
// 1652: процедура снятия по инструкции НАЧИНАЕТСЯ в безопасном режиме, а Windows
// Installer там не работает вовсе. Без явного текста администратор увидит голое число и
// решит, что скрипт сломан, — ровно тот сценарий, из-за которого батник и переписывали.
func TestMsiExitHintNamesSafeMode(t *testing.T) {
	hint := msiExitHint(msiSafeBootDisabled)
	for _, want := range []string{"безопасн", "ОБЫЧНЫЙ"} {
		if !strings.Contains(hint, want) {
			t.Errorf("подсказка для 1652 не содержит %q: %s", want, hint)
		}
	}
	if msiExitHint(4711) == "" {
		t.Error("для неизвестного кода подсказка не должна быть пустой — оператор останется с голым числом")
	}
}
