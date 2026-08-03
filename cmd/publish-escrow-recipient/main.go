// Команда публикует получателя эскроу, подписанного РЕЛИЗНЫМ ключом деплойера.
//
// Зачем отдельная команда, а не флаг у publish-release: там подписывается бинарь и его
// манифест, здесь — ключ кастодии. Смешивать в одном инструменте два разных артефакта
// с разными последствиями ошибки не стоит: опечатка в получателе означает, что ключи
// восстановления поедут не туда, и заметить это можно очень нескоро.
//
// Использование:
//
//	go run -tags enterprise ./cmd/publish-escrow-recipient \
//	  -recipient age1... -epoch 2 -key release_ed25519.pem
//
// Тег enterprise обязателен: без него нечем посчитать отпечаток получателя, а
// публиковать его «на слово» нельзя — см. resolveFingerprint.
//
// epoch обязан строго расти: агент держит его как anti-rollback floor, иначе откат на
// прежнего (возможно, скомпрометированного) получателя выглядел бы штатной публикацией.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Floodww/RoutineOps/internal/server/config"
	"github.com/Floodww/RoutineOps/internal/server/storage"
)

func main() {
	var (
		recipient = flag.String("recipient", "", "публичный age-recipient кастодии (age1...)")
		fpr       = flag.String("fpr", "", "отпечаток получателя (hex); можно не задавать — посчитается из recipient")
		epoch     = flag.Int64("epoch", 0, "номер публикации, строго больше предыдущего")
		keyPath   = flag.String("key", "", "путь к ed25519-приватнику релиза (PEM)")
	)
	flag.Parse()

	if *recipient == "" || *epoch <= 0 || *keyPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	if !strings.HasPrefix(*recipient, "age1") {
		fmt.Fprintln(os.Stderr, "recipient не похож на age-ключ (ожидается префикс age1)")
		os.Exit(1)
	}

	// Отпечаток считаем сами, а не берём со слов оператора: опечатка в -fpr давала
	// КОРРЕКТНО подписанную запись с чужим отпечатком. Агент такую отвергает
	// (filevault.NewSealer сверяет fpr с посчитанным) и молча уезжает на вшитый пин —
	// ротация не состоялась бы, а публикация выглядела успешной.
	derived, canDerive, err := derivedFingerprint(*recipient)
	if err != nil {
		fmt.Fprintln(os.Stderr, "разбор recipient:", err)
		os.Exit(1)
	}
	checked, err := resolveFingerprint(*fpr, derived, canDerive)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	*fpr = checked

	priv, err := loadEd25519PrivPEM(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load key:", err)
		os.Exit(1)
	}

	// Канон — поля через '\n' в фиксированном порядке. Тот же приём, что у манифеста
	// самообновления: подписываем ВСЮ тройку, иначе получателя можно было бы
	// переставить под чужой epoch.
	canon := fmt.Sprintf("%d\n%s\n%s", *epoch, *recipient, *fpr)
	sig := ed25519.Sign(priv, []byte(canon))

	cfg := config.Load("config.yaml")
	db, err := storage.Connect(context.Background(), cfg.DatabaseDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db:", err)
		os.Exit(1)
	}
	defer db.Close()

	err = db.PublishEscrowRecipient(context.Background(), storage.SignedRecipient{
		Epoch:     *epoch,
		Recipient: *recipient,
		FPR:       *fpr,
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "publish:", err)
		os.Exit(1)
	}
	fmt.Printf("опубликован получатель эскроу epoch=%d fpr=%s\n", *epoch, *fpr)
}

func loadEd25519PrivPEM(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("не PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("не ed25519-ключ")
	}
	return priv, nil
}

// resolveFingerprint решает, какой отпечаток уедет в подпись.
//
// Правило простое: считаем сами и, если оператор всё же задал -fpr, сверяем.
// Расхождение — отказ, а не «доверимся флагу»: именно из-за него публикация могла
// выглядеть успешной, пока парк оставался на прежнем получателе.
//
// Сборка без тега enterprise посчитать отпечаток не может, и тогда публикация
// запрещена вовсе: подписать непроверенный отпечаток — значит вернуть ровно ту
// тихую поломку, ради которой всё это и делается.
func resolveFingerprint(given, derived string, canDerive bool) (string, error) {
	if !canDerive {
		return "", errors.New("публикация отменена: эта сборка не умеет считать отпечаток получателя.\n" +
			"Пересоберите команду с тегом: go run -tags enterprise ./cmd/publish-escrow-recipient …")
	}
	if given != "" && !strings.EqualFold(strings.TrimSpace(given), derived) {
		return "", fmt.Errorf("публикация отменена: -fpr=%s не совпадает с отпечатком recipient (%s).\n"+
			"Похоже на опечатку: агент отверг бы такую запись и остался на прежнем получателе", given, derived)
	}
	return derived, nil
}
