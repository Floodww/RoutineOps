package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Floodww/RoutineOps/internal/server/api"
	"github.com/Floodww/RoutineOps/internal/server/enroll"
	"github.com/Floodww/RoutineOps/internal/server/mailer"
	"github.com/Floodww/RoutineOps/internal/server/storage"
	"github.com/Floodww/RoutineOps/internal/server/testutil"
)

var sharedDSN string

func TestMain(m *testing.M) {
	dsn, cleanup := testutil.NewDSNWithCleanup()
	sharedDSN = dsn
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Connect(context.Background(), sharedDSN)
	if err != nil {
		t.Fatalf("storage.Connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func newRouterWithDB(t *testing.T) (http.Handler, *storage.DB) {
	t.Helper()
	db := newTestDB(t)
	return newRouterFull(t, db), db
}

func newRouterFull(t *testing.T, db *storage.DB) http.Handler {
	t.Helper()
	return newRouterWithMailer(t, db, mailer.New("", "", "", "", "", false))
}

func newRouterWithMailer(t *testing.T, db *storage.DB, m *mailer.Mailer) http.Handler {
	t.Helper()
	return api.NewRouter(db, nil, []byte("test-secret"), nil, "https://test.local", t.TempDir(), m, false)
}

// newRouterWithCA создаёт роутер с настоящим CA для enrollment тестов.
func newRouterWithCA(t *testing.T, db *storage.DB) http.Handler {
	t.Helper()
	certFile, keyFile := makeTempCA(t)
	ca, err := enroll.LoadCASigner(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCASigner: %v", err)
	}
	return api.NewRouter(db, nil, []byte("test-secret"), ca, "https://test.local", t.TempDir(), nil, false)
}

// authToken создаёт пользователя, логинится и возвращает "Bearer <token>".
func authToken(t *testing.T, rtr http.Handler, db *storage.DB) string {
	t.Helper()
	return tokenForRole(t, rtr, db, "it_admin", "admin_")
}

// tokenForRole — то же, что authToken, но с произвольной ролью: нужен проверкам 403,
// где важно, что запрос отвергнут именно по роли, а не по отсутствию токена. Префикс
// email'а разводит пользователей внутри одного теста (email уникален).
func tokenForRole(t *testing.T, rtr http.Handler, db *storage.DB, role, emailPrefix string) string {
	t.Helper()
	email := emailPrefix + t.Name() + "@test.com"
	seedUser(t, db, email, "pass123", role)

	body, _ := json.Marshal(map[string]string{"email": email, "password": "pass123"})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	rtr.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("tokenForRole(%s) login failed: %d %s", role, w.Code, w.Body)
	}
	// Токен больше не возвращается в теле ответа (только httpOnly cookie, 12bc96f) —
	// достаём его из Set-Cookie для заголовка Authorization.
	for _, c := range w.Result().Cookies() {
		if c.Name == "token" {
			return "Bearer " + c.Value
		}
	}
	t.Fatalf("tokenForRole(%s): no token cookie in login response", role)
	return ""
}

// authedDo выполняет запрос с JWT и возвращает ResponseRecorder.
func authedDo(t *testing.T, rtr http.Handler, method, path string, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", token)
	w := httptest.NewRecorder()
	rtr.ServeHTTP(w, r)
	return w
}

// makeTempCA генерирует самоподписанный ECDSA CA и возвращает пути к файлам.
func makeTempCA(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	certFile = filepath.Join(dir, "ca.crt")
	keyFile = filepath.Join(dir, "ca.key")

	cf, _ := os.Create(certFile)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	keyDER, _ := x509.MarshalECPrivateKey(caKey)
	kf, _ := os.Create(keyFile)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	return certFile, keyFile
}

// makeCSR генерирует ECDSA CSR в PEM.
func makeCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

// serviceTokenSecret — секрет сервисного токена, выведенный ИЗ ИМЕНИ ТЕСТА.
//
// Литералы вида strings.Repeat("c", 40) здесь ломаются: пакет ходит в ОДНУ общую базу
// (sharedDSN), у api_tokens уникальный индекс по хешу токена, и два теста с одинаковым
// литералом валят друг друга «duplicate key» — причём падает тот, кто запустился вторым,
// то есть жалоба приходит на невиновного. По отдельности оба при этом зелёные. Поймали
// ровно так: новый тест взял ту же букву, что уже занятая соседом.
func serviceTokenSecret(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte(t.Name()))
	return "rops_" + hex.EncodeToString(sum[:])[:40]
}
