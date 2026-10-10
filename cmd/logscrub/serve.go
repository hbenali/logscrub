package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/hbenali/logscrub/internal/detect"
	"github.com/hbenali/logscrub/internal/scrub"
	"github.com/hbenali/logscrub/internal/serve"
)

// runServeSignals runs the web UI until interrupted.
func runServeSignals(args []string, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runServe(ctx, args, stderr)
}

func runServe(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("logscrub serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		addr        = fs.String("addr", serve.DefaultAddr, "address to listen on (loopback by default)")
		allowRemote = fs.Bool("allow-remote", false, "allow a non-loopback address (the UI has no authentication)")
		configPath  = fs.String("config", "", "TOML rules file (same as the CLI)")
		noConfig    = fs.Bool("no-config", false, "do not read the per-user config file")
		keyFile     = fs.String("key-file", "", "file holding the pseudonym HMAC key (or set LOGSCRUB_KEY); default: random per run")
		maxBody     = fs.Int64("max-body-bytes", serve.DefaultMaxBodyBytes, "largest text accepted")
		maxLine     = fs.Int("max-line-bytes", scrub.DefaultMaxLineBytes, "longest line scanned in one piece")
		tokenFile   = fs.String("token-file", "", "file holding an access token required for the API (or set LOGSCRUB_TOKEN); --allow-remote generates one if none is given")
		maxKeyLines = fs.Int("max-private-key-lines", scrub.DefaultMaxPrivateKeyLines, "longest private key block masked line by line")
	)
	fs.Usage = func() {
		outf(stderr, "Usage: logscrub serve [flags]\n\nA local web UI: paste or drop a log, see what would be masked, download the cleaned text.\nText is processed in memory and never stored or sent anywhere else.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		outf(stderr, "logscrub serve: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if *maxLine < 1024 || *maxBody < 1024 || *maxKeyLines < 1 {
		outf(stderr, "logscrub serve: --max-line-bytes and --max-body-bytes must be at least 1024, --max-private-key-lines at least 1\n")
		return exitUsage
	}

	cfg, err := loadConfig(*configPath, *noConfig)
	if err != nil {
		outf(stderr, "logscrub: %v\n", err)
		return exitUsage
	}
	allow, rules, err := cfg.Compile()
	if err != nil {
		outf(stderr, "logscrub: %v\n", err)
		return exitUsage
	}
	on, err := selectDetectors(rules, cfg.Enable, cfg.Disable)
	if err != nil {
		outf(stderr, "logscrub: %v\n", err)
		return exitUsage
	}
	key, err := pseudonymKey("pseudonym", *keyFile)
	if err != nil {
		outf(stderr, "logscrub: %v\n", err)
		return exitUsage
	}
	token, generated, err := serveToken(*allowRemote, *tokenFile)
	if err != nil {
		outf(stderr, "logscrub: %v\n", err)
		return exitUsage
	}
	defaultOn := make([]string, len(on))
	for i, d := range on {
		defaultOn[i] = d.ID
	}

	err = serve.Run(ctx, serve.Options{
		Addr: *addr, AllowRemote: *allowRemote, MaxBodyBytes: *maxBody, MaxLineBytes: *maxLine, MaxPrivateKeyLines: *maxKeyLines,
		Detectors: append(detect.All(), rules...), DefaultOn: defaultOn,
		Allow: allow, Key: key, Version: orUnknown(version), Token: token, ShowToken: generated,
	}, stderr)
	if err != nil {
		outf(stderr, "logscrub: %v\n", err)
		return exitIOFail
	}
	return exitOK
}

// serveToken returns the API access token: from --token-file or LOGSCRUB_TOKEN,
// else a fresh random one when --allow-remote is used (generated is then true),
// else none (loopback use needs no token).
func serveToken(allowRemote bool, file string) (token string, generated bool, err error) {
	switch {
	case file != "":
		raw, rerr := readSmallFile(file)
		if rerr != nil {
			return "", false, rerr
		}
		token = string(bytes.TrimRight(raw, "\r\n"))
	case os.Getenv("LOGSCRUB_TOKEN") != "":
		token = os.Getenv("LOGSCRUB_TOKEN")
	case allowRemote:
		b := make([]byte, 16)
		if _, rerr := rand.Read(b); rerr != nil {
			return "", false, fmt.Errorf("random token: %w", rerr)
		}
		return hex.EncodeToString(b), true, nil
	default:
		return "", false, nil
	}
	if len(token) < serve.MinTokenBytes {
		return "", false, fmt.Errorf("the access token must be at least %d characters", serve.MinTokenBytes)
	}
	return token, false, nil
}
