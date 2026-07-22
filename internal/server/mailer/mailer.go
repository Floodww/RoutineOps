package mailer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

type Mailer struct {
	host   string
	port   string
	user   string
	pass   string
	from   string
	useTLS bool // true = implicit TLS (port 465); false = STARTTLS (port 587)
}

func New(host, port, user, pass, from string, useTLS bool) *Mailer {
	return &Mailer{host: host, port: port, user: user, pass: pass, from: from, useTLS: useTLS}
}

func (m *Mailer) Enabled() bool {
	return m.host != ""
}

// PortTLSMismatch — порт и режим шифрования задаются двумя независимыми переменными
// (SMTP_PORT, SMTP_TLS), а их рассинхрон проявляется только при ПЕРВОЙ отправке:
// приглашение или сброс пароля тихо не уходит, ошибка видна лишь в логе сервера
// часами позже. Дефолты согласованы (587 + STARTTLS), ломается это при смене порта
// на 465 у провайдера, требующего implicit TLS. Проверяем на старте.
// Нестандартные порты не судим — там режим знает только оператор.
func PortTLSMismatch(port string, useTLS bool) bool {
	switch port {
	case "465": // implicit TLS
		return !useTLS
	case "587", "25": // STARTTLS
		return useTLS
	}
	return false
}

func (m *Mailer) Send(to, subject, body string) error {
	if !m.Enabled() {
		return nil
	}
	msg := strings.Join([]string{
		"From: " + m.from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	addr := fmt.Sprintf("%s:%s", m.host, m.port)

	if m.useTLS {
		return m.sendTLS(addr, to, []byte(msg))
	}
	var auth smtp.Auth
	if m.user != "" {
		auth = smtp.PlainAuth("", m.user, m.pass, m.host)
	}
	return smtp.SendMail(addr, auth, m.from, []string{to}, []byte(msg))
}

// sendTLS dials with implicit TLS (port 465) and sends the message.
func (m *Mailer) sendTLS(addr, to string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: m.host}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	host, _, _ := net.SplitHostPort(addr)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()

	if m.user != "" {
		if err := c.Auth(smtp.PlainAuth("", m.user, m.pass, m.host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(m.from); err != nil {
		return fmt.Errorf("smtp MAIL: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	return wc.Close()
}

func (m *Mailer) SendInvite(to, inviteURL string) error {
	body := fmt.Sprintf(
		"Вас пригласили в MDM-систему.\n\nПерейдите по ссылке для создания аккаунта:\n%s\n\nСсылка действительна 7 дней.",
		inviteURL,
	)
	return m.Send(to, "Приглашение в MDM", body)
}

func (m *Mailer) SendPasswordReset(to, resetURL string) error {
	body := fmt.Sprintf(
		"Запрос на сброс пароля для MDM.\n\nПерейдите по ссылке для сброса пароля:\n%s\n\nСсылка действительна 1 час.\n\nЕсли вы не запрашивали сброс пароля, проигнорируйте это письмо.",
		resetURL,
	)
	return m.Send(to, "Сброс пароля MDM", body)
}
