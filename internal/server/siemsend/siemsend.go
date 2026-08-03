// Package siemsend — доставка события журнала во внешний приёмник.
//
// Вынесен из воркера, потому что доставку выполняют ДВА разных потребителя: фоновый
// экспорт и кнопка «Проверить» в панели. Пока код жил только в воркере, проверить
// настройку из панели было нечем — а именно это и есть главная жалоба на выгрузку в
// SIEM: неверный адрес обнаруживается тем, что события молча не доезжают.
//
// Единая реализация здесь означает, что кнопка проверяет ТОТ ЖЕ путь, по которому
// поедут боевые события. Проверка, идущая другим кодом, отвечала бы не на тот вопрос.
package siemsend

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HkdfInfo — метка вывода ключа шифрования секрета приёмника из JWT-секрета.
// Своя, отдельная от MFA и SAML: утечка одного секрета не должна открывать остальные.
const HkdfInfo = "routineops:siem:secret:v1"

// Типы приёмников. Дублировать константы storage тут нельзя — получилось бы два
// источника правды, поэтому сравнение идёт по строкам, а валидация живёт в storage.
const (
	typeWebhook = "webhook"
	typeSyslog  = "syslog"
	typeCEF     = "cef"
)

const (
	httpTimeout = 10 * time.Second
	dialTimeout = 5 * time.Second
)

// Event — событие журнала в том виде, в каком оно уезжает наружу.
type Event struct {
	TenantID   string `json:"tenant_id"`
	Action     string `json:"action"`
	UserEmail  string `json:"user_email"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Details    any    `json:"details"`
}

// Deliver отправляет событие. secret == "" означает «без подписи».
func Deliver(ctx context.Context, typ, addr, secret string, ev *Event) error {
	switch typ {
	case typeWebhook:
		return pushWebhook(ctx, addr, secret, ev)
	case typeCEF:
		return pushLine(ctx, addr, formatCEF(ev))
	case typeSyslog:
		return pushLine(ctx, addr, formatSyslog(ev))
	default:
		return fmt.Errorf("неизвестный тип приёмника %q", typ)
	}
}

// pushWebhook шлёт JSON и, если задан секрет, подписывает тело.
//
// Подпись нужна приёмнику, чтобы отличить наши события от чужого POST'а на тот же
// адрес: URL вебхука не секрет, он лежит в конфиге и в журнале доставки. Схема —
// HMAC-SHA256 над `timestamp.body`, а не над одним телом: без метки времени
// перехваченный запрос переигрывается бесконечно, и подпись остаётся валидной.
func pushWebhook(ctx context.Context, webhookURL, secret string, ev *Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts))
		mac.Write([]byte("."))
		mac.Write(body)
		req.Header.Set("X-RoutineOps-Timestamp", ts)
		req.Header.Set("X-RoutineOps-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("приёмник ответил %d", resp.StatusCode)
	}
	return nil
}

// pushLine отправляет одну строку по udp/tcp.
func pushLine(ctx context.Context, addr, msg string) error {
	network, address, err := parseSyslogAddr(addr)
	if err != nil {
		return err
	}
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(dialTimeout))
	_, err = conn.Write([]byte(msg))
	return err
}

// parseSyslogAddr разбирает udp://host:port. Порт по умолчанию — 514.
func parseSyslogAddr(raw string) (network, address string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	network = u.Scheme
	if network != "udp" && network != "tcp" {
		network = "udp"
	}
	address = u.Host
	if address == "" {
		// Адрес без схемы («192.0.2.1:514») url.Parse кладёт в Path.
		// Пример из RFC 5737 (документационный диапазон), а не из 10/8: leak-скан
		// Free-среза ищет 10.0.0.x как адрес нашего прода и на комментарий срабатывает
		// так же, как на настоящую утечку.
		address = strings.TrimPrefix(u.Path, "//")
	}
	if address == "" {
		return "", "", fmt.Errorf("в адресе %q нет хоста", raw)
	}
	if _, _, splitErr := net.SplitHostPort(address); splitErr != nil {
		address = net.JoinHostPort(address, "514")
	}
	return network, address, nil
}

// cefEscape экранирует значение поля CEF.
//
// Без этого любое поле события (а туда попадает пользовательский ввод — имя скрипта,
// причина, e-mail) может закрыть запись и начать новую: перевод строки в syslog это
// граница сообщения, а `=` и `|` — разделители CEF. То есть оператор с правом
// назвать скрипт умел бы писать в SIEM произвольные события от имени сервера.
func cefEscape(s string) string {
	return strings.NewReplacer(
		`\`, `\\`,
		"|", `\|`,
		"=", `\=`,
		"\n", " ",
		"\r", " ",
	).Replace(s)
}

func formatCEF(ev *Event) string {
	details, _ := json.Marshal(ev.Details)
	// Severity 5 — «средняя»: своей severity у записи журнала нет, а выдумывать её
	// здесь значит врать приёмнику.
	return fmt.Sprintf("CEF:0|RoutineOps|MDM|1.0|%s|%s|5|dvchost=%s suser=%s msg=%s\n",
		cefEscape(ev.Action), cefEscape(ev.Action),
		cefEscape(ev.TenantID), cefEscape(ev.UserEmail), cefEscape(string(details)))
}

// syslogEscape режет то, что ломает границу сообщения. Экранировать `=`/`|` здесь
// не нужно — разделителей CEF в обычном syslog нет.
func syslogEscape(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
}

// formatSyslog — RFC 5424 с приоритетом 13 (user.notice).
//
// Отдельно от CEF, потому что до 063 тип `syslog` слал CEF: оператор выбирал
// «syslog», получал CEF и не понимал, почему его парсер молчит.
func formatSyslog(ev *Event) string {
	details, _ := json.Marshal(ev.Details)
	target := ev.TargetType
	if ev.TargetID != "" {
		target += "/" + ev.TargetID
	}
	return fmt.Sprintf("<13>1 %s routineops - %s - action=%s tenant=%s user=%s target=%s details=%s\n",
		time.Now().UTC().Format(time.RFC3339),
		syslogEscape(ev.Action),
		syslogEscape(ev.Action),
		syslogEscape(ev.TenantID),
		syslogEscape(ev.UserEmail),
		syslogEscape(target),
		syslogEscape(string(details)))
}
