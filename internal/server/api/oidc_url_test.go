package api_test

import (
	"testing"

	"github.com/Floodww/RoutineOps/internal/server/api"
)

// Q-29: issuer_url без https означал discovery и JWKS по открытому каналу, то есть
// подменяемые ключи проверки подписи id_token. Loopback — осознанное исключение под
// локальный стенд IdP.
func TestRequireHTTPSURL(t *testing.T) {
	ok := []string{
		"https://idp.example.com",
		"https://idp.example.com/realms/test",
		"http://localhost:8080/realms/test",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	}
	for _, u := range ok {
		if err := api.RequireHTTPSURL(u); err != nil {
			t.Errorf("RequireHTTPSURL(%q) = %v; want nil", u, err)
		}
	}

	bad := []string{
		"http://idp.example.com",
		"http://192.0.2.10:8080",
		"ftp://idp.example.com",
		"idp.example.com",
		"https://",
		"",
	}
	for _, u := range bad {
		if err := api.RequireHTTPSURL(u); err == nil {
			t.Errorf("RequireHTTPSURL(%q) = nil; want error", u)
		}
	}
}
