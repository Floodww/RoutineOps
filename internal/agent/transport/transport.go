// Package transport отвечает за mTLS-соединение агента с сервером: постоянный
// gRPC Connect-стрим (heartbeat) с автопереподключением и общий Dialer, который
// переиспользуют редкие unary-вызовы (inventory) — см. ADR-5.
package transport

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"

	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// Stream — постоянный двунаправленный поток Connect: агент шлёт HeartbeatRequest,
// сервер шлёт Task (см. proto/agent.proto, ADR-5).
type Stream = grpc.BidiStreamingClient[pb.HeartbeatRequest, pb.Task]

// SessionFunc обслуживает один установленный стрим до его обрыва.
type SessionFunc func(ctx context.Context, stream Stream) error

// Dialer создаёт gRPC-соединения по mTLS. Один Dialer держит весь mTLS-конфиг
// и адрес в одном месте и переиспользуется и постоянным стримом (Client), и
// редкими unary-вызовами inventory — потоки логически разделены (ADR-5), но
// конфигурация подключения общая.
type Dialer struct {
	serverAddr string
	creds      credentials.TransportCredentials
}

// NewDialer собирает Dialer из источника сертификатов (абстракция CertProvider).
func NewDialer(serverAddr, serverName string, certs CertProvider) (*Dialer, error) {
	cert, err := certs.ClientCertificate()
	if err != nil {
		return nil, err
	}
	roots, err := certs.RootCAs()
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}
	return &Dialer{serverAddr: serverAddr, creds: credentials.NewTLS(cfg)}, nil
}

// Dial открывает новое соединение. grpc.ClientConn сам поддерживает транспорт и
// переподключается под капотом — вызывающий отвечает за Close.
func (d *Dialer) Dial() (*grpc.ClientConn, error) {
	return grpc.NewClient(d.serverAddr, grpc.WithTransportCredentials(d.creds))
}

// DialStream открывает ОТДЕЛЬНОЕ соединение под медиастрим интерактивного сеанса
// (docs/remote-desktop-contract.md §3.2, ADR-8 п.1).
//
// Почему не Dial: разница не в кредах, а в двух параметрах, каждый из которых на обычном
// соединении не нужен, а здесь обязателен.
//
//   - Keepalive 20 с. Сервер enforce'ит MinTime: 10 * time.Second
//     (cmd/server/main.go), и клиент, пингующий чаще, получает GOAWAY too_many_pings и
//     уходит в вечный цикл переподключений — снаружи это выглядит как «сеанс не
//     запускается». Двадцать секунд — с запасом к порогу, а не впритык к нему.
//     PermitWithoutStream не ставим: пинговать соединение без стрима незачем, оно живёт
//     ровно один сеанс.
//   - Потолок исходящего сообщения. Кадр режется на части по 256 KiB, и умолчание gRPC
//     (4 МиБ на приём, без потолка на отправку) здесь не защищает ни от чего: явный
//     потолок превращает ошибку кодирования в отказ отправки, а не в OOM на сервере.
func (d *Dialer) DialStream() (*grpc.ClientConn, error) {
	return grpc.NewClient(d.serverAddr,
		grpc.WithTransportCredentials(d.creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    20 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(streamMaxMessage),
			grpc.MaxCallRecvMsgSize(streamMaxMessage),
		),
	)
}

// streamMaxMessage — потолок одного сообщения медиастрима: часть кадра (256 KiB) плюс
// накладные расходы protobuf. Держится заведомо ниже серверного MaxRecvMsgSize(4 МиБ),
// который трогать нельзя — он общий на весь grpc.Server и защищает все мелкие RPC.
const streamMaxMessage = 512 << 10

// Addr — адрес сервера (для логов).
func (d *Dialer) Addr() string { return d.serverAddr }

// Client держит постоянный Connect-стрим и переподключается при обрыве.
type Client struct {
	dialer *Dialer
	log    *slog.Logger

	baseBackoff time.Duration
	maxBackoff  time.Duration
	// minHealthy — сколько должна прожить сессия, чтобы считать соединение
	// установившимся и сбросить backoff (защита от плотного цикла при ленивом
	// grpc.NewClient к лежащему серверу).
	minHealthy time.Duration
	// blockedRetry — пауза между попытками, когда сервер вернул PermissionDenied
	// (устройство заблокировано). Реже обычного backoff: бан — не временный сбой,
	// долбить каждые 60с смысла нет; но повторяем, чтобы после разблокировки
	// агент сам переподключился.
	blockedRetry time.Duration
}

func New(dialer *Dialer, log *slog.Logger) *Client {
	return &Client{
		dialer:       dialer,
		log:          log,
		baseBackoff:  1 * time.Second,
		maxBackoff:   60 * time.Second,
		minHealthy:   5 * time.Second,
		blockedRetry: 5 * time.Minute,
	}
}

// SetBlockedRetry задаёт паузу реконнекта при блокировке устройства (по умолчанию 5 мин).
func (c *Client) SetBlockedRetry(d time.Duration) {
	if d > 0 {
		c.blockedRetry = d
	}
}

// Run обслуживает сессию через session, переподключаясь с exponential backoff +
// jitter, пока ctx не будет отменён.
func (c *Client) Run(ctx context.Context, session SessionFunc) error {
	bo := newBackoff(c.baseBackoff, c.maxBackoff)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		start := time.Now()
		err := c.connectAndServe(ctx, session)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Устройство заблокировано на сервере (status='blocked'): это не временный
		// сбой, а явный отказ. Ждём дольше и логируем отдельно, но не сдаёмся —
		// после разблокировки агент переподключится сам.
		var delay time.Duration
		if status.Code(err) == codes.PermissionDenied {
			bo.reset() // после разблокировки backoff стартует с базы
			delay = c.blockedRetry
			c.log.Warn("устройство заблокировано сервером — повтор реже",
				slog.Duration("retry_in", delay), slog.Any("error", err))
		} else {
			if time.Since(start) >= c.minHealthy {
				bo.reset()
			}
			delay = bo.next()
			c.log.Warn("соединение потеряно, переподключение",
				slog.Duration("retry_in", delay), slog.Any("error", err))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

func (c *Client) connectAndServe(ctx context.Context, session SessionFunc) error {
	conn, err := c.dialer.Dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)
	stream, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	c.log.Info("стрим Connect открыт", slog.String("server", c.dialer.Addr()))

	return session(ctx, stream)
}
