//go:build darwin && cgo

// macOS Keychain-провайдер: приватный ключ остаётся в Keychain, подпись
// TLS-хендшейка выполняет Security.framework через crypto.Signer (SecKey).
//
// Построение CFDictionary и поиск вынесены в C-хелпер mdmCopyIdentity: в этом
// SDK CF-типы маппятся cgo как uintptr, и собирать словарь из []unsafe.Pointer
// на стороне Go — это uintptr→unsafe.Pointer (go vet «possible misuse»). В C это
// естественно и безопасно.
package keystore

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// mdmCopyIdentity ищет идентичность, чей сертификат несёт CN РОВНО label, и
// возвращает её сертификат и приватный ключ. kc != NULL ограничивает поиск одним
// keychain (для изолированных тестов); NULL — список поиска по умолчанию.
//
// Фильтр kSecAttrLabel в запросе kSecClassIdentity на legacy file-keychain
// (System.keychain — наша боевая цель, см. ProvisionTarget) ИГНОРИРУЕТСЯ:
// проверено живьём — запрос с любой меткой отдаёт первую попавшуюся идентичность
// хранилища. На System.keychain парка живут и чужие идентичности (VPN, Wi-Fi,
// сторонний MDM) — полагаться на порядок нельзя. Поэтому перечисляем ВСЕ
// идентичности и сверяем CN сертификата на точное равенство сами — зеркало
// certSubjectCN в purge_windows.go.
static OSStatus mdmCopyIdentity(const char *label, SecKeychainRef kc,
                                SecCertificateRef *outCert, SecKeyRef *outKey) {
    CFStringRef cflabel = CFStringCreateWithCString(kCFAllocatorDefault, label, kCFStringEncodingUTF8);
    if (!cflabel) {
        return errSecParam; // метка не декодируется как UTF-8 — сверять нечем
    }
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(q, kSecClass, kSecClassIdentity);
    CFDictionarySetValue(q, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitAll);

    CFArrayRef list = NULL;
    if (kc) {
        const void *arr[1] = { kc };
        list = CFArrayCreate(kCFAllocatorDefault, arr, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(q, kSecMatchSearchList, list);
    }

    CFArrayRef found = NULL;
    OSStatus st = SecItemCopyMatching(q, (CFTypeRef *)&found);
    if (st == errSecSuccess && found) {
        st = errSecItemNotFound; // нет ТОЧНОГО совпадения CN — «не найдено»
        CFIndex n = CFArrayGetCount(found);
        for (CFIndex i = 0; i < n; i++) {
            SecIdentityRef ident = (SecIdentityRef)CFArrayGetValueAtIndex(found, i);
            SecCertificateRef cert = NULL;
            if (SecIdentityCopyCertificate(ident, &cert) != errSecSuccess || !cert) {
                continue;
            }
            CFStringRef cn = NULL;
            bool match = false;
            if (SecCertificateCopyCommonName(cert, &cn) == errSecSuccess && cn) {
                match = (CFStringCompare(cn, cflabel, 0) == kCFCompareEqualTo);
                CFRelease(cn);
            }
            if (!match) {
                CFRelease(cert);
                continue;
            }
            st = SecIdentityCopyPrivateKey(ident, outKey);
            if (st == errSecSuccess) {
                *outCert = cert; // ретейн от SecIdentityCopyCertificate уезжает вызывающему
            } else {
                CFRelease(cert);
            }
            break;
        }
        CFRelease(found);
    }
    if (list) CFRelease(list);
    CFRelease(q);
    CFRelease(cflabel);
    return st;
}
*/
import "C"

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
)

// keychainProvider достаёт клиентскую идентичность (cert + ключ-через-SecKey) из
// Keychain по метке (label = CN серта = device_id). CA публичен — читается из файла.
type keychainProvider struct {
	label    string
	caFile   string
	keychain string // путь к конкретному keychain ("" = список поиска по умолчанию)
}

func newKeychainProvider(o Options) (transport.CertProvider, error) {
	if o.Label == "" {
		return nil, fmt.Errorf("cert-source=keystore: не задана метка идентичности (-keystore-label, обычно device_id)")
	}
	return &keychainProvider{label: o.Label, caFile: o.CAFile}, nil
}

// RootCAs — CA не секрет, берём из файла (тот же бандл, что и для file-провайдера).
func (p *keychainProvider) RootCAs() (*x509.CertPool, error) {
	return transport.FileCertProvider{CAFile: p.caFile}.RootCAs()
}

// ClientCertificate находит идентичность в Keychain и возвращает tls.Certificate
// с приватным ключом-делегатом (SecKey не покидает Keychain).
func (p *keychainProvider) ClientCertificate() (tls.Certificate, error) {
	clabel := C.CString(p.label)
	defer C.free(unsafe.Pointer(clabel))

	var kc C.SecKeychainRef
	if p.keychain != "" {
		cpath := C.CString(p.keychain)
		defer C.free(unsafe.Pointer(cpath))
		if st := C.SecKeychainOpen(cpath, &kc); st != C.errSecSuccess {
			return tls.Certificate{}, fmt.Errorf("keychain: SecKeychainOpen(%s): OSStatus %d", p.keychain, int(st))
		}
		defer C.CFRelease(C.CFTypeRef(kc))
	}

	var certRef C.SecCertificateRef
	var keyRef C.SecKeyRef
	if st := C.mdmCopyIdentity(clabel, kc, &certRef, &keyRef); st != C.errSecSuccess {
		return tls.Certificate{}, fmt.Errorf("keychain: идентичность с меткой %q не найдена (OSStatus %d)", p.label, int(st))
	}
	defer C.CFRelease(C.CFTypeRef(certRef))

	certData := C.SecCertificateCopyData(certRef)
	if certData == 0 {
		return tls.Certificate{}, fmt.Errorf("keychain: пустые данные сертификата")
	}
	defer C.CFRelease(C.CFTypeRef(certData))
	leaf, err := x509.ParseCertificate(cfDataBytes(certData))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("keychain: разбор сертификата: %w", err)
	}

	// keyRef оставляем ретейненным: ClientCertificate вызывается один раз в
	// NewDialer, tls.Config живёт до выхода агента (см. transport.NewDialer).
	return tls.Certificate{
		Certificate: [][]byte{cfDataBytes(certData)},
		PrivateKey:  &secKeySigner{key: keyRef, pub: leaf.PublicKey},
		Leaf:        leaf,
	}, nil
}

// secKeySigner — crypto.Signer поверх SecKey: приватный ключ не извлекается,
// подпись считает Security.framework.
type secKeySigner struct {
	key C.SecKeyRef
	pub crypto.PublicKey
}

func (s *secKeySigner) Public() crypto.PublicKey { return s.pub }

func (s *secKeySigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	algo, err := signAlgorithm(s.pub, opts)
	if err != nil {
		return nil, err
	}
	data := cfData(digest)
	defer C.CFRelease(C.CFTypeRef(data))

	var cfErr C.CFErrorRef
	sig := C.SecKeyCreateSignature(s.key, algo, data, &cfErr)
	if sig == 0 {
		defer func() {
			if cfErr != 0 {
				C.CFRelease(C.CFTypeRef(cfErr))
			}
		}()
		return nil, fmt.Errorf("keychain: SecKeyCreateSignature: код %d", int(C.CFErrorGetCode(cfErr)))
	}
	defer C.CFRelease(C.CFTypeRef(sig))
	return cfDataBytes(sig), nil
}

// signAlgorithm выбирает SecKeyAlgorithm по типу ключа и хешу подписи. Для ECDSA
// SecKey возвращает DER ASN.1 — ровно то, что ждёт crypto/tls.
func signAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (C.SecKeyAlgorithm, error) {
	h := opts.HashFunc()
	switch pub.(type) {
	case *ecdsa.PublicKey:
		switch h {
		case crypto.SHA256:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256, nil
		case crypto.SHA384:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384, nil
		case crypto.SHA512:
			return C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512, nil
		}
	case *rsa.PublicKey:
		_, pss := opts.(*rsa.PSSOptions)
		switch h {
		case crypto.SHA256:
			if pss {
				return C.kSecKeyAlgorithmRSASignatureDigestPSSSHA256, nil
			}
			return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256, nil
		case crypto.SHA384:
			if pss {
				return C.kSecKeyAlgorithmRSASignatureDigestPSSSHA384, nil
			}
			return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384, nil
		case crypto.SHA512:
			if pss {
				return C.kSecKeyAlgorithmRSASignatureDigestPSSSHA512, nil
			}
			return C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512, nil
		}
	}
	return 0, fmt.Errorf("keychain: неподдержанная пара ключ/хеш (%T, %v)", pub, h)
}

// --- CoreFoundation helpers (без uintptr→unsafe.Pointer) ---

func cfData(b []byte) C.CFDataRef {
	var p *C.UInt8
	if len(b) > 0 {
		p = (*C.UInt8)(unsafe.Pointer(&b[0]))
	}
	return C.CFDataCreate(C.kCFAllocatorDefault, p, C.CFIndex(len(b)))
}

func cfDataBytes(d C.CFDataRef) []byte {
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(d)), C.int(C.CFDataGetLength(d)))
}
