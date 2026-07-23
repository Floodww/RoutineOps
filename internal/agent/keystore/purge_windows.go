//go:build windows

package keystore

import (
	"crypto/x509"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// maxPurgeIdentities — потолок правдоподобного числа дубликатов идентичности под
// одной меткой в одном сторе (повторные энроллы под тем же device_id). Снято
// больше потолка и конца не видно — что-то не так, останавливаемся с ошибкой.
const maxPurgeIdentities = 8

var (
	procNCryptDeleteKey  = windows.NewLazySystemDLL("ncrypt.dll").NewProc("NCryptDeleteKey")
	procNCryptFreeObject = windows.NewLazySystemDLL("ncrypt.dll").NewProc("NCryptFreeObject")
)

// Purge удаляет идентичность агента из Windows Certificate Store: для каждого
// серта с subject CN == label СНАЧАЛА NCryptDeleteKey приватного CNG-ключа,
// ПОТОМ CertDeleteCertificateFromStore. Одного удаления серта (как certutil
// -delstore) недостаточно: приватный ключ живёт отдельным контейнером в KSP и
// осиротел бы.
//
// target ("LocalMachine"|"CurrentUser") сохранён для симметрии с Import/
// ProvisionTarget, но scope не сужает: провайдер ищет идентичность в ОБОИХ
// (см. ClientCertificate) — идентичность не должна пережить снос в непокрытом
// сторе, поэтому метём оба достижимых.
func Purge(label, target string) error {
	_ = target
	if label == "" {
		return fmt.Errorf("keystore: пустая метка идентичности — purge невозможен")
	}
	var errs []error
	deleted := 0
	for _, loc := range []uint32{windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, windows.CERT_SYSTEM_STORE_CURRENT_USER} {
		n, err := purgeStore(loc, label)
		deleted += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if deleted == 0 {
		return fmt.Errorf("cert store: идентичность %q не найдена в My (LocalMachine/CurrentUser)", label)
	}
	return nil
}

// purgeStore выметает из одного системного My-стора все серты, чей subject CN
// РАВЕН label, удаляя перед каждым его приватный CNG-ключ. Поиск идёт по
// CERT_FIND_SUBJECT_STR (у CryptoAPI это подстрочный case-insensitive матч по
// всему subject — другого нет), но перед НЕОБРАТИМЫМ удалением CN сверяется на
// точное равенство: подстрочное совпадение (label внутри чужого subject, напр.
// доменного computer-серта) не должно уничтожать чужой серт и его ключ — у
// читающего провайдера промах безобиден, здесь операция деструктивна.
// Возвращает число снятых сертов; ошибки ключей копятся (осиротевший серт без
// ключа — не повод его оставить).
func purgeStore(location uint32, label string) (int, error) {
	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return 0, err
	}
	store, err := windows.CertOpenStore(
		uintptr(windows.CERT_STORE_PROV_SYSTEM_W), 0, 0, location,
		uintptr(unsafe.Pointer(storeName)))
	if err != nil {
		return 0, fmt.Errorf("cert store: открыть My (location 0x%x): %w", location, err)
	}
	defer windows.CertCloseStore(store, 0)

	subject, err := windows.UTF16PtrFromString(label)
	if err != nil {
		return 0, err
	}

	var errs []error
	deleted := 0
	// Обход: find сам освобождает переданный prev-контекст. Пропущенные чужие
	// серты проходим prev-цепочкой; после каждого УДАЛЕНИЯ поиск стартует заново
	// (prev=nil — удалённый контекст уже освобождён самим delete). Цикл конечен:
	// рестарт бывает только после удаления (их ≤ потолка), внутри прохода
	// цепочка строго движется вперёд.
	var prev *windows.CertContext
	for {
		ctx, ferr := windows.CertFindCertificateInStore(store,
			windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
			windows.CERT_FIND_SUBJECT_STR, unsafe.Pointer(subject), prev)
		if ferr != nil || ctx == nil {
			break // совпадений больше нет — вычищено (или их и не было)
		}
		if certSubjectCN(ctx) != label {
			prev = ctx // подстрочное совпадение с ЧУЖИМ сертом — не трогаем
			continue
		}
		if deleted >= maxPurgeIdentities {
			// Ещё одно точное совпадение СВЕРХ потолка: не молчим (иначе остаток
			// ключевого материала выглядел бы полным успехом) и не зацикливаемся.
			windows.CertFreeCertificateContext(ctx)
			errs = append(errs, fmt.Errorf("cert store: снято уже %d сертов %q и это не конец — останавливаюсь", deleted, label))
			break
		}
		// Сначала ключ: удаление одного серта ОСИРОТИЛО бы приватный CNG-ключ
		// (контейнер в KSP живёт отдельно от серта).
		if kerr := deleteNCryptKey(ctx); kerr != nil {
			errs = append(errs, kerr)
		}
		// CertDeleteCertificateFromStore освобождает контекст всегда (даже при
		// ошибке) — продолжать prev-цепочку по нему нельзя.
		if derr := windows.CertDeleteCertificateFromStore(ctx); derr != nil {
			errs = append(errs, fmt.Errorf("cert store: удалить серт %q: %w", label, derr))
			break // рестарт нашёл бы тот же серт — цикл завис бы
		}
		deleted++
		prev = nil
	}
	return deleted, errors.Join(errs...)
}

// certSubjectCN — CN субъекта серта из контекста; "" при ошибке разбора. Такой
// серт безопаснее НЕ трогать: не удаляем то, что не смогли опознать (и читающий
// провайдер его так же не разберёт — рабочей идентичностью он быть не может).
func certSubjectCN(ctx *windows.CertContext) string {
	der := make([]byte, ctx.Length)
	copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length))
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	return leaf.Subject.CommonName
}

// deleteNCryptKey удаляет персистентный приватный ключ серта из CNG
// (NCryptDeleteKey с флагом 0 заодно освобождает хэндл). Отсутствие ключа
// (осиротевший серт) — не повод не снимать серт: ошибка уходит наверх для лога,
// purge продолжается.
func deleteNCryptKey(ctx *windows.CertContext) error {
	// Find() вместо прямого Call: LazyProc.Call ПАНИКУЕТ, если экспорт не
	// резолвится, а Purge зовётся в терминальном сносе — деградируем мягко
	// (тот же приём, что resolveProductCode в decommission).
	if err := procNCryptDeleteKey.Find(); err != nil {
		return fmt.Errorf("cert store: NCryptDeleteKey недоступен: %w", err)
	}
	key, err := acquireNCryptKey(ctx)
	if err != nil {
		return fmt.Errorf("cert store: приватный ключ для удаления не получен: %w", err)
	}
	if st, _, _ := procNCryptDeleteKey.Call(uintptr(key), 0); st != 0 {
		// NCryptDeleteKey освобождает хэндл только при УСПЕХЕ — на ошибке
		// владелец по-прежнему мы (callerFree в acquireNCryptKey), иначе утечка.
		freeNCryptHandle(key)
		return fmt.Errorf("cert store: NCryptDeleteKey: SECURITY_STATUS 0x%x", uint32(st))
	}
	return nil
}

// freeNCryptHandle — best-effort NCryptFreeObject (мягкая деградация через Find,
// как у остальных ncrypt-процедур на терминальном пути сноса).
func freeNCryptHandle(h windows.Handle) {
	if procNCryptFreeObject.Find() == nil {
		_, _, _ = procNCryptFreeObject.Call(uintptr(h))
	}
}
