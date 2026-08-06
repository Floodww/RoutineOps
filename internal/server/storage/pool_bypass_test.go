package storage_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// poolBypassAllowed — ПОИМЁННЫЙ список функций, которым разрешено ходить в базу мимо
// скоупа вызывающего (`db.pool` вместо `db.Scoped(ctx)`), с причиной у каждой.
//
// 🔴 Зачем список вообще. `db.pool` берёт СОСЕДНЕЕ соединение, на котором
// routineops.tenant_id не выставлен. Для таблицы под FORCE RLS это значит:
// на свежем соединении предикат не совпадает ни с одной строкой (запрос молча отдаёт
// ноль / UPDATE трогает ноль строк), а на отравленном — падает 22P02 на пустой строке в ::uuid.
// Оба лица одного дефекта, и первое — тихое. Ровно так в июле лёг командный канал, а
// 04.08 тем же способом ТИХО терялся отчёт агента о выдаче локального админа
// (UpdateAdminAccessReport): вызывающий трактует «0 строк» как accept-and-drop.
//
// Локальные тесты этот класс не ловят сами по себе: testutil ставит роли
// `ALTER ROLE mdm_app SET routineops.tenant_id = <default>`, поэтому запрос через пул
// в тестах «попадает» в дефолтный тенант и выглядит рабочим. Отсюда и гейт: не «работает
// ли», а «объяснено ли, почему здесь можно».
//
// Что делать, если тест упал на НОВОЙ функции: это не повод дописать строку. Сначала
// ответьте, читает ли она таблицу под RLS (см. internal/server/tenancy/tables.go и
// migrations/046_rls.sql). Если да — почти наверняка нужен `db.Scoped(ctx)`, а вызывающему
// скоуп; если скоуп открыть неоткуда, функция обязана биндить тенанта сама
// (BindTenantForDevice / BindTenantForTask). Строка сюда — только для случаев ниже.
var poolBypassAllowed = map[string]string{
	// Сама машинерия скоупа: этим функциям пул и нужен, они его и открывают.
	"tx.go:BindTenant":          "открывает транзакцию и выставляет GUC — это и есть механизм",
	"tx.go:beginScoped":         "то же, для запросов без явного скоупа",
	"tx.go:BindTenantForDevice": "резолвит тенанта ПО устройству до того, как скоуп существует",
	"tx.go:BindTenantForTask":   "то же, по задаче",
	"tx.go:DeviceTenantID":      "auth_device_tenant: надзорные операции над устройством тенанта его не знают — этим вызовом и узнают",
	"postgres.go:Close":         "закрытие пула, запроса нет",
	"postgres.go:Pool":          "аксессор к пулу; ответственность на вызывающем",
	// tx.go:Q записи больше нет и быть не должно: Scoped(ctx) в пул не ходит вовсе —
	// нет контекста со скоупом, нет и запроса (ErrTenantScopeMissing).

	// Резолв идентичности ДО того, как тенант известен: SECURITY DEFINER-функции
	// auth_* (миграция 046) намеренно исполняются вне тенантского скоупа.
	"oidc.go:AuthOIDCProvider":                 "auth_oidc_provider: вход, тенанта ещё нет",
	"saml.go:GetSAMLProviderForAuth":           "auth_saml_provider: вход, тенанта ещё нет",
	"identities.go:GetIdentityByEmail":         "auth_identity_by_email: по e-mail и происходит вход",
	"identities.go:ListMemberships":            "auth_identity_memberships: членства резолвятся ДО выбора тенанта",
	"enrollment.go:GetEnrollmentToken":         "auth_enrollment_by_hash: энролл не аутентифицирован, тенанта в контексте нет никогда",
	"postgres.go:GetDeviceTenantByFingerprint": "auth_device_by_fingerprint: этим вызовом тенант и УЗНАЁТСЯ",
	"postgres.go:GetUserEpoch":                 "auth_user_password_epoch: проверка в middleware до резолва тенанта",
	"postgres.go:GetInvitationByToken":         "auth_invitation_by_token: приглашение принимают, ещё не будучи в тенанте",
	"postgres.go:GetPasswordResetToken":        "auth_password_reset_by_token: сброс пароля вне сессии",
	"postgres.go:GetUserByLinkToken":           "auth_user_by_link_token (069): токен привязки приходит от Bot API, где нашей сессии нет вовсе",
	"api_tokens.go:AuthenticateAPIToken":       "auth_api_token_touch: тенант токена фиксирован при выпуске и берётся отсюда",

	// Кросс-тенантный надзор: вопрос «весь парк инсталляции» одним тенантом в GUC не
	// выражается. Изоляцию держит сама SECURITY DEFINER-функция и гард роли у ручки.
	"across_tenants.go:ListDevicesAcrossTenants": "list_devices_across_tenants (048): ответ шире одного тенанта по определению",

	// Таблицы ScopeGlobal (internal/server/tenancy/tables.go): строки не принадлежат
	// тенанту, RLS на них не включается, и скоуп для них бессмысленен.
	"identities.go:UpdateIdentityPassword":           "identities — ScopeGlobal (человек, а не членство)",
	"identities.go:PromoteBootstrapProviderAdmin":    "identities — ScopeGlobal",
	"identities.go:EnsureIdentity":                   "identities — ScopeGlobal",
	"identities.go:SetMFA":                           "identities — ScopeGlobal",
	"tenants.go:ListTenants":                         "tenants — ScopeGlobal (реестр тенантов инсталляции)",
	"tenants.go:GetTenant":                           "tenants — ScopeGlobal",
	"tenants.go:CreateTenant":                        "tenants — ScopeGlobal",
	"tenants.go:SetTenantMFA":                        "tenants — ScopeGlobal",
	"tenants.go:RenameTenant":                        "tenants — ScopeGlobal",
	"tenants.go:CountTenants":                        "tenants — ScopeGlobal",
	"tenants.go:DeleteTenant":                        "tenants — ScopeGlobal + вызов SECURITY DEFINER admin_reparent_tenant: кросс-тенантная операция одним GUC не выражается",
	"tenants.go:MoveDeviceToTenant":                  "SECURITY DEFINER admin_move_device_tenant: переносит строку МЕЖДУ тенантами",
	"releases.go:GetLatestAgentReleaseForChannel":    "agent_releases — ScopeGlobal (один набор подписанных бинарей на инсталляцию)",
	"releases.go:ListAgentReleases":                  "agent_releases — ScopeGlobal",
	"releases.go:RegisterAgentRelease":               "agent_releases — ScopeGlobal",
	"escrow_recipient.go:LatestEscrowRecipient":      "escrow_recipients — ScopeGlobal (кастодия одна на инсталляцию)",
	"escrow_recipient.go:IsPublishedEscrowRecipient": "escrow_recipients — ScopeGlobal",
	"escrow_recipient.go:PublishEscrowRecipient":     "escrow_recipients — ScopeGlobal",
	"token_blocklist.go:RevokeToken":                 "token_blocklist — ScopeGlobal (проверяется по jti до того, как тенант известен)",
	"token_blocklist.go:IsTokenRevoked":              "token_blocklist — ScopeGlobal",
	"token_blocklist.go:CleanupExpiredRevokedTokens": "token_blocklist — ScopeGlobal",
	"postgres.go:IsFingerprintRevoked":               "revoked_fingerprints — ScopeGlobal (отозванный серт обязан быть отозван ВЕЗДЕ, тенантский скоуп здесь fail-open)",
}

// Каждый прямой поход в пул из пакета storage обязан быть в списке выше — с причиной.
// Новая функция с `db.pool` роняет тест, и это намеренно: решение «под RLS или нет»
// принимается один раз и записывается, а не выводится заново каждым читающим.
func TestPoolBypassesAreDocumented(t *testing.T) {
	found := poolCallSites(t)

	var undocumented []string
	for site := range found {
		if _, ok := poolBypassAllowed[site]; !ok {
			undocumented = append(undocumented, site)
		}
	}
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Errorf("прямой db.pool без записанной причины (%d):\n  %s\n\n"+
			"Сначала выясните, под RLS ли таблица (internal/server/tenancy/tables.go, "+
			"migrations/046_rls.sql). Если под RLS — нужен db.Scoped(ctx), а не строка в списке: "+
			"через пул запрос уходит на соединение без routineops.tenant_id и молча "+
			"не находит строк.",
			len(undocumented), strings.Join(undocumented, "\n  "))
	}

	// Обратная сторона: устаревшие записи. Иначе список превращается в свалку, где
	// нельзя отличить действующее исключение от следа давно переписанной функции.
	var stale []string
	for site := range poolBypassAllowed {
		if !found[site] {
			stale = append(stale, site)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("в списке исключений %d записей, которым в коде уже ничего не соответствует:\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}

// poolCallSites возвращает множество "файл.go:Функция" по всем вхождениям db.pool
// в непроверочных исходниках пакета storage.
func poolCallSites(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	sites := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("разбор %s: %v", path, err)
		}
		base := filepath.Base(path)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				// Ищем именно `<что-то>.pool`: db.pool.Exec разбирается в
				// SelectorExpr{X: SelectorExpr{X: db, Sel: pool}, Sel: Exec}.
				if sel.Sel.Name == "pool" {
					sites[base+":"+fn.Name.Name] = true
				}
				return true
			})
		}
	}
	if len(sites) == 0 {
		t.Fatal("не найдено ни одного db.pool — сломался разбор, а не код")
	}
	return sites
}
