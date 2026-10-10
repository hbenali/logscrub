package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/hbenali/logscrub/internal/config"
)

// atomicFile writes to a temporary file next to the target and renames it into
// place on Commit, so a failed run never leaves a half-written (or, worse, a
// replaced and truncated) file behind. The mode is 0600: cleaned logs can still
// be sensitive.
type atomicFile struct {
	f      *os.File
	target string
}

func newAtomicFile(target string, inputs []string) (*atomicFile, error) {
	if st, err := os.Stat(target); err == nil {
		if st.IsDir() {
			return nil, fmt.Errorf("--output %q is a directory", target)
		}
		for _, in := range inputs {
			if in == "-" {
				continue
			}
			if ist, err := os.Stat(in); err == nil && os.SameFile(st, ist) {
				return nil, errors.New("--output is also an input; refusing to overwrite the log being read")
			}
		}
	}
	f, err := os.CreateTemp(filepath.Dir(target), ".logscrub-*")
	if err != nil {
		return nil, fmt.Errorf("--output: %w", err)
	}
	return &atomicFile{f: f, target: target}, nil
}

func (a *atomicFile) Write(p []byte) (int, error) { return a.f.Write(p) }

// Commit closes the temporary file and moves it over the target.
func (a *atomicFile) Commit() error {
	if err := a.f.Close(); err != nil {
		_ = os.Remove(a.f.Name())
		return fmt.Errorf("--output: %w", err)
	}
	if err := os.Rename(a.f.Name(), a.target); err != nil {
		_ = os.Remove(a.f.Name())
		return fmt.Errorf("--output: %w", err)
	}
	return nil
}

// Abort discards the temporary file.
func (a *atomicFile) Abort() {
	_ = a.f.Close()
	_ = os.Remove(a.f.Name())
}

// userConfigPath is the per-user config file: $XDG_CONFIG_HOME/logscrub/config.toml,
// or the platform's user config directory. It is deliberately not looked up in
// the current directory: an allow-list in an untrusted checkout could make
// logscrub leak what it was asked to mask.
func userConfigPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		d, err := os.UserConfigDir()
		if err != nil {
			return ""
		}
		dir = d
	}
	return filepath.Join(dir, "logscrub", "config.toml")
}

// loadConfig returns the explicit --config, else the user-level file if it
// exists (unless --no-config), else an empty config.
func loadConfig(path string, noConfig bool) (config.Config, error) {
	if path == "" && !noConfig {
		if p := userConfigPath(); p != "" {
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				if runtime.GOOS != "windows" && st.Mode().Perm()&0o002 != 0 {
					return config.Config{}, fmt.Errorf("refusing %s: it is world-writable (chmod o-w, or pass --no-config)", p)
				}
				path = p
			}
		}
	}
	if path == "" {
		return config.Config{}, nil
	}
	c, err := config.Load(path)
	if err != nil {
		return config.Config{}, err
	}
	return *c, nil
}
