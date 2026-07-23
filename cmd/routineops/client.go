package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// client — тонкая обёртка над публичным HTTP API сервера. Никакой своей логики:
// CLI обязан ходить теми же ручками, что и UI, иначе появится второй набор правил
// доступа, который однажды разъедется с первым.
type client struct {
	base  string // https://host[:port]
	token string
	http  *http.Client
}

// newClient. caFile нужен для типовой установки: сервер стоит с собственным CA, и без
// пина запрос упрётся в x509. Пустой caFile = системные корни (публичный сертификат).
func newClient(base, token, caFile string) (*client, error) {
	if token == "" {
		return nil, fmt.Errorf("нужен API-токен: -token или ROUTINEOPS_TOKEN")
	}
	tr := &http.Transport{}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("чтение CA %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("в %s нет ни одного сертификата", caFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &client{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http:  &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}, nil
}

func (c *client) do(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+"/api/v1"+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// Тело ответа в ошибку целиком: сервер объясняет отказ текстом («script name
		// already exists», «403 requires human»), и глотать это — обречь оператора на
		// гадание по коду.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *client) get(path string, out any) error { return c.do(http.MethodGet, path, nil, out) }

func (c *client) post(path string, body, out any) error {
	return c.do(http.MethodPost, path, body, out)
}

func (c *client) put(path string, body, out any) error {
	return c.do(http.MethodPut, path, body, out)
}

func (c *client) patch(path string, body, out any) error {
	return c.do(http.MethodPatch, path, body, out)
}

func (c *client) delete(path string) error { return c.do(http.MethodDelete, path, nil, nil) }

// ---- Типы ответов сервера. Только те поля, которые нужны CLI. ----

type apiGroup struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

type apiPolicyRule struct {
	ID           string   `json:"id"`
	SoftwareName string   `json:"software_name"`
	RuleType     string   `json:"rule_type"`
	DeviceID     *string  `json:"device_id"`
	GroupID      *string  `json:"group_id"`
	Platforms    []string `json:"platforms"`
}

type apiScript struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	Content  string `json:"content"`
}

type apiScriptPolicy struct {
	ID                 string          `json:"id"`
	Name               string          `json:"name"`
	ScriptID           string          `json:"script_id"`
	ScriptName         string          `json:"script_name"`
	TriggerType        string          `json:"trigger_type"`
	ScheduleConfig     json.RawMessage `json:"schedule_config,omitempty"`
	EventTriggerConfig json.RawMessage `json:"event_trigger_config,omitempty"`
	IsActive           bool            `json:"is_active"`
	GroupNames         []string        `json:"group_names"`
}
