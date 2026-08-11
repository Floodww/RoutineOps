// Command publish-release регистрирует новую сборку агента: считает sha256,
// подписывает дайджест ed25519-приватником релиза, копирует бинарь в releases-dir,
// вставляет запись в agent_releases. Используется CI на теге релиза.
//
// Пример:
//
//	publish-release \
//	  -binary ./agent_darwin_arm64 \
//	  -version v1.0.0 -os darwin -arch arm64 \
//	  -key release_ed25519.pem \
//	  -channel beta
//
// Канареечная выкатка (Q-52): сначала публикуют в beta, где сидит небольшая группа
// машин, а после обкатки повторяют ту же команду с -channel stable — это и есть
// продвижение (UPSERT переводит строку, второй сборки не нужно).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Floodww/RoutineOps/internal/server/config"
	"github.com/Floodww/RoutineOps/internal/server/storage"
)

func main() {
	var (
		binaryPath = flag.String("binary", "", "путь к собранному бинарю агента")
		version    = flag.String("version", "", "версия релиза (semver, напр. v1.0.0)")
		osName     = flag.String("os", "", "GOOS бинаря (darwin/linux/windows)")
		arch       = flag.String("arch", "", "GOARCH бинаря (amd64/arm64)")
		keyPath    = flag.String("key", "", "путь к ed25519-приватнику релиза (PEM)")
		// Канал по умолчанию — stable, и это осознанно НЕ beta: команду запускают
		// руками, и забытый флаг должен вести себя как раньше (публикация на парк),
		// а не тихо посадить релиз в канарейку, откуда его никто не ждёт.
		channel = flag.String("channel", storage.ChannelStable, "канал выкатки: stable|beta")
	)
	flag.Parse()

	if *binaryPath == "" || *version == "" || *osName == "" || *arch == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "all flags required: -binary -version -os -arch -key")
		os.Exit(2)
	}
	if !storage.ValidChannel(*channel) {
		fmt.Fprintf(os.Stderr, "неизвестный канал %q (ожидается stable|beta)\n", *channel)
		os.Exit(2)
	}

	// 🔴 Первым делом — то ли мы вообще публикуем (см. binaryguard.go). Проверка стоит ДО
	// подписи по той же причине, что и darwin-гейт ниже, но ловит случай грубее: файл,
	// который вообще не является бинарём. В поле это была скачанная ошибка API — 112 байт
	// JSON под именем агента, — и без этой проверки она уехала в канал подписанной.
	if err := requireExecutable(*binaryPath, *osName); err != nil {
		fmt.Fprintln(os.Stderr, "публикация отклонена:", err)
		os.Exit(1)
	}

	// darwin без cgo — заглушки вместо Cocoa-замка и Keychain, причём молча (см. cgoguard.go).
	// Отсекаем до подписи: подписанный битый бинарь уже не отличить от рабочего.
	if *osName == "darwin" {
		if err := requireCGODarwin(*binaryPath); err != nil {
			fmt.Fprintln(os.Stderr, "публикация darwin-бинаря отклонена:", err)
			os.Exit(1)
		}
	}

	binary, err := os.ReadFile(*binaryPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read binary:", err)
		os.Exit(1)
	}

	priv, err := loadEd25519PrivPEM(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load key:", err)
		os.Exit(1)
	}

	digest := sha256.Sum256(binary)
	sig := ed25519.Sign(priv, digest[:])
	sha256hex := hex.EncodeToString(digest[:])
	// C-signer/SEC-3: подписываем ВЕСЬ манифест, а не только sha256(бинарь) — иначе
	// компромет-сервер отдаёт старый валидно-подписанный билд под новой меткой версии
	// (downgrade-relabel). Канон — поля через '\n' в фикс. порядке version\nos\narch\nsha256;
	// агент (SEC-3) должен проверять ровно эту строку.
	manifestCanon := *version + "\n" + *osName + "\n" + *arch + "\n" + sha256hex
	manifestSig := ed25519.Sign(priv, []byte(manifestCanon))

	cfg := config.Load("config.yaml")
	if err := os.MkdirAll(cfg.ReleasesDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir releases:", err)
		os.Exit(1)
	}

	filename := fmt.Sprintf("agent_%s_%s_%s", *osName, *arch, *version)
	dst := filepath.Join(cfg.ReleasesDir, filename)
	if err := os.WriteFile(dst, binary, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "write release:", err)
		os.Exit(1)
	}

	db, err := storage.Connect(context.Background(), cfg.DatabaseDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "db connect:", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.RegisterAgentRelease(context.Background(), *osName, *arch, *version,
		filename, sha256hex, base64.StdEncoding.EncodeToString(sig),
		base64.StdEncoding.EncodeToString(manifestSig), *channel,
	); err != nil {
		fmt.Fprintln(os.Stderr, "register:", err)
		os.Exit(1)
	}

	fmt.Printf("published %s %s/%s [%s] → %s (sha256=%s)\n",
		*version, *osName, *arch, *channel, dst, hex.EncodeToString(digest[:]))
	if *channel == storage.ChannelStable {
		fmt.Println("канал stable: релиз уедет на ВЕСЬ парк этой платформы")
	} else {
		fmt.Println("канал beta: релиз уедет только на устройства beta-групп")
	}
}

func loadEd25519PrivPEM(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an ed25519 key")
	}
	return priv, nil
}
