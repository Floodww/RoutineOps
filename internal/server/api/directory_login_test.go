package api_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/api"
)

// Вход по паролю каталога на уровне ручки /auth/login. Каталог подставной: проверяется не
// LDAP-провод (это live_stand_test.go в internal/server/directory), а решения обвязки —
// что именно считается основанием выдать токен. Файл без build-тега намеренно: интерфейс
// живёт во free-пакете, и в open-core-сборке те же тесты проверяют, что при незарегистри-
// рованном каталоге вход остаётся ровно локальным.

// fakeDirectory — каталог, который отвечает заранее заданным. calls считает обращения:
// по нему видно не только ответ, но и сам ФАКТ похода в каталог, а он в половине проверок
// и есть суть.
type fakeDirectory struct {
	ok       bool
	err      error
	calls    int
	gotLogin string
	gotPass  string
}

func (f *fakeDirectory) GetConfig(context.Context) (api.DirectoryConfig, error) {
	return api.DirectoryConfig{}, nil
}

func (f *fakeDirectory) SetConfig(context.Context, api.DirectoryConfig, string, string) error {
	return nil
}

func (f *fakeDirectory) TestConnection(context.Context) error { return nil }

func (f *fakeDirectory) SyncNow(context.Context) (api.DirectorySyncResult, error) {
	return api.DirectorySyncResult{}, nil
}

func (f *fakeDirectory) Authenticate(_ context.Context, login, password string) (bool, error) {
	f.calls++
	f.gotLogin, f.gotPass = login, password
	return f.ok, f.err
}

// routerWithDirectory поднимает роутер с подставным каталогом — тем же швом, которым
// подключается настоящий (WithDirectoryService в enterprise composition-root), и заводит
// пользователя с локальным паролем local-pass-123.
func routerWithDirectory(t *testing.T, fake *fakeDirectory) func(email, password string) int {
	t.Helper()
	db := newTestDB(t)
	rtr := api.NewRouter(db, nil, []byte("test-secret"), nil, "https://test.local", t.TempDir(), nil, false,
		api.WithDirectoryService(fake))
	seedUser(t, db, "ldap_"+t.Name()+"@test.com", "local-pass-123", "it_admin")
	return func(email, password string) int {
		return doLogin(t, rtr, email, password).Code
	}
}

// TestLogin_LocalPasswordSurvivesDeadDirectory — требование, из-за которого локальная
// проверка стоит ПЕРВОЙ: учётку отключили в AD (или DC просто лежит), а локальный пароль
// обязан работать. Иначе падение домена запирает всех, включая админа, которому в этот
// момент и надо чинить. Отзыв доступа у нас — удаление пользователя, а не отключение в AD.
func TestLogin_LocalPasswordSurvivesDeadDirectory(t *testing.T) {
	fake := &fakeDirectory{err: errors.New("DC недоступен")}
	login := routerWithDirectory(t, fake)
	email := "ldap_" + t.Name() + "@test.com"

	if code := login(email, "local-pass-123"); code != http.StatusOK {
		t.Fatalf("локальный пароль при мёртвом каталоге: got %d, want 200", code)
	}
	// В каталог не ходили вовсе: локальный пароль сошёлся раньше. Это не оптимизация, а
	// то самое свойство — доступность входа не зависит от доступности AD.
	if fake.calls != 0 {
		t.Errorf("каталог опрошен %d раз, хотя локальный пароль верный", fake.calls)
	}
}

// TestLogin_DirectoryPasswordAccepted — собственно фича: локальный пароль не тот, каталог
// подтвердил — вход есть.
func TestLogin_DirectoryPasswordAccepted(t *testing.T) {
	fake := &fakeDirectory{ok: true}
	login := routerWithDirectory(t, fake)
	email := "ldap_" + t.Name() + "@test.com"

	if code := login(email, "domain-pass"); code != http.StatusOK {
		t.Fatalf("пароль каталога: got %d, want 200", code)
	}
	if fake.calls != 1 {
		t.Fatalf("каталог опрошен %d раз, ожидался 1", fake.calls)
	}
	if fake.gotLogin != email || fake.gotPass != "domain-pass" {
		t.Errorf("в каталог ушло login=%q pass-совпал=%v; ожидались присланные значения",
			fake.gotLogin, fake.gotPass == "domain-pass")
	}
}

// TestLogin_DirectoryDoesNotCreateAccounts — «входят только те, у кого уже есть аккаунт».
// Каталог отвечает лишь «пароль верный»; прав это не выдаёт и пользователя не заводит.
// Без строки в users каталог не должны даже спрашивать.
func TestLogin_DirectoryDoesNotCreateAccounts(t *testing.T) {
	fake := &fakeDirectory{ok: true}
	login := routerWithDirectory(t, fake)

	if code := login("nobody_"+t.Name()+"@test.com", "domain-pass"); code != http.StatusUnauthorized {
		t.Fatalf("вход без аккаунта в панели: got %d, want 401", code)
	}
	if fake.calls != 0 {
		t.Errorf("каталог опрошен %d раз для несуществующего аккаунта, ожидался 0", fake.calls)
	}
}

// TestLogin_DirectoryErrorIsNotAccess — fail-closed: ошибка каталога это отказ, а не
// разрешение. Иначе способом обойти пароль становился бы отвалившийся DC.
func TestLogin_DirectoryErrorIsNotAccess(t *testing.T) {
	fake := &fakeDirectory{ok: true, err: errors.New("таймаут каталога")}
	login := routerWithDirectory(t, fake)
	email := "ldap_" + t.Name() + "@test.com"

	if code := login(email, "domain-pass"); code != http.StatusUnauthorized {
		t.Fatalf("ошибка каталога: got %d, want 401", code)
	}
}

// TestLogin_DirectoryRejectionIsRejection — каталог сказал «не тот пароль»: 401, и ответ
// неотличим от локального промаха (перечислять учётки по коду ответа не даём).
func TestLogin_DirectoryRejectionIsRejection(t *testing.T) {
	fake := &fakeDirectory{}
	login := routerWithDirectory(t, fake)
	email := "ldap_" + t.Name() + "@test.com"

	if code := login(email, "wrong-pass"); code != http.StatusUnauthorized {
		t.Fatalf("отказ каталога: got %d, want 401", code)
	}
	if fake.calls != 1 {
		t.Errorf("каталог опрошен %d раз, ожидался 1", fake.calls)
	}
}

// TestLogin_WithoutDirectoryServiceStaysLocal — open-core-путь: каталог не зарегистрирован
// (h.directorySvc == nil). Вход обязан остаться локальным и молчаливым — 401, а не 501:
// человеку на входе про несобранную enterprise-фичу сообщать нечего.
func TestLogin_WithoutDirectoryServiceStaysLocal(t *testing.T) {
	rtr, db := newRouterWithDB(t)
	email := "nodir_" + t.Name() + "@test.com"
	seedUser(t, db, email, "local-pass-123", "it_admin")

	if code := doLogin(t, rtr, email, "local-pass-123").Code; code != http.StatusOK {
		t.Fatalf("локальный пароль без каталога: got %d, want 200", code)
	}
	if code := doLogin(t, rtr, email, "domain-pass").Code; code != http.StatusUnauthorized {
		t.Fatalf("чужой пароль без каталога: got %d, want 401", code)
	}
}
