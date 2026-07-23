//go:build windows

// Windows Certificate Store провайдер: приватный ключ остаётся в хранилище
// (CNG/NCrypt), подпись TLS-хендшейка делает ОС через NCryptSignHash. CGO не
// используется — только syscalls через golang.org/x/sys/windows и ncrypt.dll.
package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"unsafe"

	"github.com/Floodww/RoutineOps/internal/agent/transport"
	"golang.org/x/sys/windows"
)

// Флаги паддинга BCrypt (нет в x/sys/windows).
const (
	bcryptPadPKCS1 = 0x00000002
	bcryptPadPSS   = 0x00000008
)

var procNCryptSignHash = windows.NewLazySystemDLL("ncrypt.dll").NewProc("NCryptSignHash")

type bcryptPKCS1PaddingInfo struct{ pszAlgID *uint16 }

type bcryptPSSPaddingInfo struct {
	pszAlgID *uint16
	cbSalt   uint32
}

// certStoreProvider достаёт клиентскую идентичность из хранилища Windows по
// подстроке subject (CN = device_id). CA публичен — читается из файла.
type certStoreProvider struct {
	label  string
	caFile string
}

func newKeychainProvider(o Options) (transport.CertProvider, error) {
	if o.Label == "" {
		return nil, fmt.Errorf("cert-source=keystore: не задана метка идентичности (-keystore-label, обычно device_id)")
	}
	return &certStoreProvider{label: o.Label, caFile: o.CAFile}, nil
}

func (p *certStoreProvider) RootCAs() (*x509.CertPool, error) {
	return transport.FileCertProvider{CAFile: p.caFile}.RootCAs()
}

// ClientCertificate ищет серт по subject в My-хранилищах (сначала LocalMachine —
// агент-служба под LocalSystem, затем CurrentUser) и возвращает tls.Certificate
// с приватным ключом-делегатом (ключ не покидает хранилище).
func (p *certStoreProvider) ClientCertificate() (tls.Certificate, error) {
	locations := []uint32{
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
		windows.CERT_SYSTEM_STORE_CURRENT_USER,
	}
	for _, loc := range locations {
		cert, err := p.fromStore(loc)
		if err == nil {
			return cert, nil
		}
	}
	return tls.Certificate{}, fmt.Errorf("cert store: идентичность с subject %q не найдена в My (LocalMachine/CurrentUser)", p.label)
}

func (p *certStoreProvider) fromStore(location uint32) (tls.Certificate, error) {
	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return tls.Certificate{}, err
	}
	store, err := windows.CertOpenStore(
		uintptr(windows.CERT_STORE_PROV_SYSTEM_W), 0, 0, location,
		uintptr(unsafe.Pointer(storeName)))
	if err != nil {
		return tls.Certificate{}, err
	}
	defer windows.CertCloseStore(store, 0)

	subject, err := windows.UTF16PtrFromString(p.label)
	if err != nil {
		return tls.Certificate{}, err
	}
	ctx, err := windows.CertFindCertificateInStore(store,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
		windows.CERT_FIND_SUBJECT_STR, unsafe.Pointer(subject), nil)
	if err != nil || ctx == nil {
		return tls.Certificate{}, fmt.Errorf("cert store: не найдено: %w", err)
	}
	defer windows.CertFreeCertificateContext(ctx)

	der := make([]byte, ctx.Length)
	copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length))
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert store: разбор серта: %w", err)
	}

	key, err := acquireNCryptKey(ctx)
	if err != nil {
		return tls.Certificate{}, err
	}
	// key оставляем открытым: ClientCertificate вызывается один раз в NewDialer,
	// tls.Config живёт до выхода агента.
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  &ncryptSigner{key: key, pub: leaf.PublicKey},
		Leaf:        leaf,
	}, nil
}

// acquireNCryptKey получает дескриптор приватного ключа CNG для серта.
func acquireNCryptKey(ctx *windows.CertContext) (windows.Handle, error) {
	var h windows.Handle
	var keySpec uint32
	callerFree := true
	err := windows.CryptAcquireCertificatePrivateKey(ctx,
		windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, nil, &h, &keySpec, &callerFree)
	if err != nil {
		return 0, fmt.Errorf("cert store: CryptAcquireCertificatePrivateKey: %w", err)
	}
	if keySpec != windows.CERT_NCRYPT_KEY_SPEC {
		// Защитная ветка (с ONLY_NCRYPT-флагом практически недостижима), но хэндл
		// при успешном Acquire уже наш (callerFree) — без free он утёк бы.
		freeNCryptHandle(h)
		return 0, fmt.Errorf("cert store: ключ не CNG/NCrypt (keySpec=%d)", keySpec)
	}
	return h, nil
}

// ncryptSigner — crypto.Signer поверх CNG: ключ не извлекается, подпись считает ОС.
type ncryptSigner struct {
	key windows.Handle
	pub crypto.PublicKey
}

func (s *ncryptSigner) Public() crypto.PublicKey { return s.pub }

func (s *ncryptSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch s.pub.(type) {
	case *ecdsa.PublicKey:
		// CNG отдаёт сырую r||s — приводим к ASN.1 DER (ждёт crypto/tls).
		raw, err := ncryptSignHash(s.key, nil, digest, 0)
		if err != nil {
			return nil, err
		}
		return ecdsaRawToASN1(raw)
	case *rsa.PublicKey:
		algID, err := bcryptHashAlgID(opts.HashFunc())
		if err != nil {
			return nil, err
		}
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			info := bcryptPSSPaddingInfo{pszAlgID: algID, cbSalt: uint32(pssSaltLen(pss, opts.HashFunc()))}
			return ncryptSignHash(s.key, unsafe.Pointer(&info), digest, bcryptPadPSS)
		}
		info := bcryptPKCS1PaddingInfo{pszAlgID: algID}
		return ncryptSignHash(s.key, unsafe.Pointer(&info), digest, bcryptPadPKCS1)
	}
	return nil, fmt.Errorf("cert store: неподдержанный тип ключа %T", s.pub)
}

// ncryptSignHash вызывает NCryptSignHash по двухпроходной схеме (узнать размер →
// подписать). Возврат NCryptSignHash — SECURITY_STATUS, 0 = успех.
func ncryptSignHash(key windows.Handle, padding unsafe.Pointer, hash []byte, flags uint32) ([]byte, error) {
	if len(hash) == 0 {
		return nil, fmt.Errorf("cert store: пустой дайджест для подписи")
	}
	var size uint32
	st, _, _ := procNCryptSignHash.Call(
		uintptr(key), uintptr(padding),
		uintptr(unsafe.Pointer(&hash[0])), uintptr(len(hash)),
		0, 0, uintptr(unsafe.Pointer(&size)), uintptr(flags))
	if st != 0 {
		return nil, fmt.Errorf("cert store: NCryptSignHash(размер): SECURITY_STATUS 0x%x", uint32(st))
	}
	sig := make([]byte, size)
	st, _, _ = procNCryptSignHash.Call(
		uintptr(key), uintptr(padding),
		uintptr(unsafe.Pointer(&hash[0])), uintptr(len(hash)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(size),
		uintptr(unsafe.Pointer(&size)), uintptr(flags))
	if st != 0 {
		return nil, fmt.Errorf("cert store: NCryptSignHash(подпись): SECURITY_STATUS 0x%x", uint32(st))
	}
	return sig[:size], nil
}

// bcryptHashAlgID возвращает UTF16-идентификатор алгоритма хеша для CNG.
func bcryptHashAlgID(h crypto.Hash) (*uint16, error) {
	var name string
	switch h {
	case crypto.SHA256:
		name = "SHA256"
	case crypto.SHA384:
		name = "SHA384"
	case crypto.SHA512:
		name = "SHA512"
	default:
		return nil, fmt.Errorf("cert store: неподдержанный хеш %v", h)
	}
	return windows.UTF16PtrFromString(name)
}

// pssSaltLen переводит PSSOptions в длину соли для CNG (TLS использует
// SaltLengthEqualsHash; Auto трактуем так же).
func pssSaltLen(opts *rsa.PSSOptions, h crypto.Hash) int {
	switch opts.SaltLength {
	case rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash:
		return h.Size()
	default:
		return opts.SaltLength
	}
}
