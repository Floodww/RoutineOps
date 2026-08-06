//go:build windows

package decommission

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"time"
)

// Ретрай ровно на 1618 — те же величины, что в bat-делетере самосноса
// (buildDeleterScript): 6 попыток по ~10с. Кумулятивное обновление Windows держит
// мьютекс установщика минутами, а снятие без ретрая оставило бы ровно тот ARP-хвост,
// ради которого шаг и делается.
const (
	msiBusyRetries = 6
	msiBusyWait    = 10 * time.Second
)

// msiRunTimeout — потолок на ОДИН запуск msiexec. Логика та же, что у
// pkgRemoveTimeout на Linux: подвисший установщик не должен держать процедуру снятия
// вечно — перед батником сидит администратор, и он должен получить ответ, а не
// молчащий экран. Убийство клиентского msiexec.exe транзакцию не рвёт: работу делает
// служба Windows Installer, клиент лишь ждёт её.
const msiRunTimeout = 15 * time.Minute

// maxRelatedProducts — сколько связанных продуктов подряд готовы снять.
//
// В норме он один. Двое бывают после ОБОРВАННОГО major upgrade: MajorUpgrade со
// Schedule="afterInstallValidate" сносит старый продукт между InstallValidate и
// RemoveExistingProducts, и потеря питания в этом окне оставляет обе регистрации. Снять
// только первую значит оставить Installed=true — то есть исходный баг, но уже с гейтом,
// который его не видит. Потолок нужен, чтобы ошибка в опросе не превратилась в
// бесконечный цикл msiexec.
const maxRelatedProducts = 4

// unregisterMSI — Windows-реализация UnregisterMSI (док там же).
func unregisterMSI(ctx context.Context, log *slog.Logger) (MSIUnregisterResult, error) {
	var res MSIUnregisterResult
	for round := 1; round <= maxRelatedProducts; round++ {
		// Опрашиваем ИНДЕКС 0 каждый раз, а не перебираем индексы: после успешного
		// снятия нумерация связанных продуктов сдвигается, и шаг по индексу пропустил бы
		// следующий. Заодно это и ПОСТ-ПРОВЕРКА: «снято» = база Installer больше не знает
		// продукта, а не «msiexec сказал 0».
		productCode, _, err := enumRelatedProduct(0)
		if err != nil {
			return res, err
		}
		if productCode == "" {
			if round == 1 {
				log.Info("msi-unregister: MSI-регистрация агента не найдена — снимать нечего",
					slog.String("upgrade_code", upgradeCode))
			} else {
				log.Info("msi-unregister: связанных продуктов не осталось",
					slog.Int("снято", round-1))
			}
			return res, nil
		}
		res.Found = true
		res.ProductCode = productCode
		if err := removeOneProduct(ctx, productCode, &res, log); err != nil {
			return res, err
		}
	}
	// Потолок исчерпан, а продукт всё ещё числится: молчать об этом нельзя — именно так
	// выглядит «msiexec отдал 0, не сделав ничего».
	return res, fmt.Errorf("после %d снятий продукт по UpgradeCode %s всё ещё зарегистрирован — "+
		"запись в «Установка и удаление программ» останется", maxRelatedProducts, upgradeCode)
}

// removeOneProduct снимает один продукт, повторяя на 1618.
func removeOneProduct(ctx context.Context, productCode string, res *MSIUnregisterResult, log *slog.Logger) error {
	log.Info("msi-unregister: снимаю MSI-установку агента", slog.String("product_code", productCode))
	for attempt := 1; ; attempt++ {
		code, err := runMsiexecRemove(ctx, productCode)
		if err != nil {
			return fmt.Errorf("запуск msiexec /x %s: %w", productCode, err)
		}
		res.ExitCode = code

		switch classifyMSIExit(code) {
		case msiOutcomeDone:
			log.Info("msi-unregister: MSI-регистрация снята", slog.String("product_code", productCode))
			return nil
		case msiOutcomeGone:
			// Продукт исчез между опросом базы и /x. Цель достигнута — регистрации нет.
			log.Info("msi-unregister: продукт уже не установлен — регистрации нет",
				slog.String("product_code", productCode))
			return nil
		case msiOutcomeReboot:
			// Регистрация ушла из Installer-БД и ARP; занятые файлы переименованы в .rbf
			// и удалятся после перезагрузки — в норме это сам uninstall.bat, который
			// держит открытым cmd.exe. Остаток добьют следующие шаги батника.
			res.RebootNeeded = true
			log.Warn("msi-unregister: регистрация снята, часть файлов удалится после перезагрузки",
				slog.String("product_code", productCode), slog.Int("msiexec", code))
			return nil
		case msiOutcomeBusy:
			if attempt >= msiBusyRetries {
				return fmt.Errorf("msiexec /x %s: Windows Installer занят другой установкой (%d) "+
					"после %d попыток — повторите после завершения обновлений Windows",
					productCode, code, msiBusyRetries)
			}
			log.Warn("msi-unregister: Windows Installer занят другой установкой — жду и повторяю",
				slog.Int("попытка", attempt), slog.Int("из", msiBusyRetries))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(msiBusyWait):
			}
		default:
			return fmt.Errorf("msiexec /x %s вернул %d: %s", productCode, code, msiExitHint(code))
		}
	}
}

// runMsiexecRemove запускает одно `msiexec /x` и возвращает его код возврата. Ошибка —
// только невозможность ЗАПУСТИТЬ процесс (нет msiexec, отказ ОС); ненулевой код
// возврата ошибкой здесь не считается, его трактует classifyMSIExit.
//
// Свойства помимо /qn /norestart:
//
//	MSIRMSHUTDOWN=2 — Restart Manager гасит держателей файлов, ТОЛЬКО если все они
//	  зарегистрированы на перезапуск (RegisterApplicationRestart); агент не регистрируется
//	  нигде, поэтому предусловие не выполняется и RM не гасит ничего. Это важно: команду
//	  зовёт uninstall.bat, а silent-установка (/qn) по документации всегда использует RM —
//	  без этого замка установщик имел бы право закрыть процессы, которые ведут снятие.
//	REBOOT=ReallySuppress — дублирует /norestart ДРУГИМ механизмом (свойство, а не ключ)
//	  и снимает 1641: снос агента не должен ронять машину оператора.
//
// MSIRESTARTMANAGERCONTROL=Disable сюда СОЗНАТЕЛЬНО не добавлен: документация Microsoft
// оговаривает задание этого свойства через transform/upgrade и прямо предупреждает, что
// из custom action оно не действует — про командную строку не сказано ничего. Полагаться
// на свойство с неопределённым поведением в пути снятия агента нельзя, а нужный эффект
// уже даёт MSIRMSHUTDOWN=2 с документированной семантикой.
func runMsiexecRemove(ctx context.Context, productCode string) (int, error) {
	runCtx, cancel := context.WithTimeout(ctx, msiRunTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "msiexec", "/x", productCode, "/qn", "/norestart",
		"REBOOT=ReallySuppress", "MSIRMSHUTDOWN=2")
	err := cmd.Run()
	if err == nil {
		return msiSuccess, nil
	}
	// Таймаут проверяем ДО разбора кода возврата, и это не педантизм: CommandContext
	// убивает процесс через TerminateProcess(handle, 1), Run отдаёт ExitError с
	// ExitCode()==1, и без этой проверки оператор получил бы «msiexec вернул 1» — код
	// ERROR_INVALID_FUNCTION, которого не было, и пошёл бы разбирать несуществующую
	// ошибку вместо истёкшего потолка. Хуже другое: клиент убит, а транзакцию доводит
	// служба Windows Installer — про это надо сказать прямо, потому что следующие шаги
	// батника (rmdir, reg delete) пойдут поверх живого удаления.
	if runCtx.Err() != nil {
		return 0, fmt.Errorf("msiexec /x %s не уложился в %s и был снят; сама транзакция удаления "+
			"продолжается службой Windows Installer — дождитесь её окончания и повторите снятие, "+
			"не удаляя файлы вручную", productCode, msiRunTimeout)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, err
}
