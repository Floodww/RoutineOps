package selfupdate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// maxBinarySize — потолок на скачиваемый бинарь (защита от раздувания памяти).
const maxBinarySize = 200 << 20 // 200 МБ

// NewHTTPClient строит HTTP-клиент, доверяющий CA из caFile (manifest и бинарь
// раздаёт тот же сервер, что и mTLS — с приватной CA). Подлинность бинаря всё
// равно гарантирует ed25519-подпись; CA нужен лишь чтобы TLS-верификация
// эндпоинта прошла. Пустой caFile → системные корни (для публичного хоста).
// Экспортирован, потому что тем же клиентом ходит обвязка эскроу: подписанного
// получателя отдаёт тот же сервер и та же приватная CA.
// Возвращает (клиент, ok): ok=false если CA задан, но не загрузился.
func NewHTTPClient(caFile string) (*http.Client, bool) {
	if caFile == "" {
		return http.DefaultClient, true
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return http.DefaultClient, false
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return http.DefaultClient, false
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		},
	}, true
}

// httpCheck запрашивает manifest актуальной версии. os/arch/current сервер ждёт
// query-параметрами (см. docs/self-update.md) — добавляем их к checkURL.
func httpCheck(ctx context.Context, client *http.Client, checkURL, current string) (*Manifest, error) {
	u, err := url.Parse(checkURL)
	if err != nil {
		return nil, fmt.Errorf("разбор update-url: %w", err)
	}
	q := u.Query()
	q.Set("os", runtime.GOOS)
	q.Set("arch", runtime.GOARCH)
	if current != "" {
		q.Set("current", current)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("manifest: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, fmt.Errorf("разбор manifest: %w", err)
	}
	if m.Version == "" || m.URL == "" || m.SHA256 == "" || m.Signature == "" {
		return nil, fmt.Errorf("неполный manifest: %+v", m)
	}
	return &m, nil
}

// httpDownload скачивает бинарь по URL с потолком размера.
func httpDownload(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBinarySize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBinarySize {
		return nil, fmt.Errorf("бинарь больше лимита %d байт", maxBinarySize)
	}
	return data, nil
}
