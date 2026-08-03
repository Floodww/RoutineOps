package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// SignedRecipient — получатель эскроу, подписанный релизным ключом деплойера.
//
// Агент проверяет подпись релизным ключом (он у него с энроллмента) и принимает
// запись, только если epoch не меньше уже виденного. Пиннинг получателя в бинарь
// после этого не нужен: доверие держит подпись, а не сборка.
type SignedRecipient struct {
	Epoch     int64  `json:"epoch"`
	Recipient string `json:"recipient"`
	FPR       string `json:"fpr"`
	Signature string `json:"signature"`
}

// LatestEscrowRecipient отдаёт последнего опубликованного получателя.
// Возвращает nil, если ни одного ещё не публиковали (агент тогда работает по пину).
func (db *DB) LatestEscrowRecipient(ctx context.Context) (*SignedRecipient, error) {
	var r SignedRecipient
	err := db.pool.QueryRow(ctx, `
		SELECT epoch, recipient, fpr, signature
		FROM escrow_recipients ORDER BY epoch DESC LIMIT 1
	`).Scan(&r.Epoch, &r.Recipient, &r.FPR, &r.Signature)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// IsPublishedEscrowRecipient — публиковался ли когда-нибудь получатель с таким fpr.
//
// Нужен приёму эскроу: сервер обязан принимать блоб, запечатанный на ЛЮБОГО
// опубликованного получателя, а не только на того, что стоит у него в конфиге.
// Парк переходит на новый epoch не одномоментно (машина офлайн, машина ещё не
// перечитала ручку), поэтому сверка с единственным конфигом делает ротацию окном
// отказа: до смены конфига отлуп получают перешедшие, после — не перешедшие.
//
// Множество именно ПУБЛИКАЦИЙ, а не «что угодно»: строку сюда кладёт только
// деплойер своим релизным приватником, которого на сервере нет, и агент принимает
// её по той же подписи. Строки не удаляются — история ротаций и есть тот набор
// ключей, шеры которых оператор обязан хранить, чтобы вскрыть старый эскроу.
func (db *DB) IsPublishedEscrowRecipient(ctx context.Context, fpr string) (bool, error) {
	if fpr == "" {
		return false, nil
	}
	var ok bool
	err := db.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM escrow_recipients WHERE fpr = $1)`, fpr).Scan(&ok)
	return ok, err
}

// ErrEscrowEpochNotMonotonic — попытка опубликовать epoch не выше последнего.
var ErrEscrowEpochNotMonotonic = errors.New("escrow: epoch должен быть строго больше последнего опубликованного")

// PublishEscrowRecipient добавляет нового получателя.
//
// Монотонность epoch проверяется здесь, а не только на агенте: агент откатную
// публикацию отвергнет, но сервер не должен её и производить — иначе парк молча
// разъедется на две группы, и понять, кто на каком получателе, будет неоткуда.
func (db *DB) PublishEscrowRecipient(ctx context.Context, r SignedRecipient) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var last int64
	err = tx.QueryRow(ctx, `SELECT COALESCE(max(epoch), 0) FROM escrow_recipients`).Scan(&last)
	if err != nil {
		return err
	}
	if r.Epoch <= last {
		return ErrEscrowEpochNotMonotonic
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO escrow_recipients (epoch, recipient, fpr, signature) VALUES ($1, $2, $3, $4)
	`, r.Epoch, r.Recipient, r.FPR, r.Signature); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
