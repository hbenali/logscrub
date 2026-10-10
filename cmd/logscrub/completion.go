package main

import (
	"embed"
	"io"
)

//go:embed completions/*
var completionFS embed.FS

// completionFiles maps a shell to its embedded script.
var completionFiles = map[string]string{
	"bash": "completions/logscrub.bash",
	"zsh":  "completions/_logscrub",
	"fish": "completions/logscrub.fish",
}

// runCompletion prints the completion script for a shell.
func runCompletion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		outf(stderr, "Usage: logscrub completion bash|zsh|fish\n")
		return exitUsage
	}
	name, ok := completionFiles[args[0]]
	if !ok {
		outf(stderr, "logscrub: unknown shell %q (bash, zsh or fish)\n", args[0])
		return exitUsage
	}
	body, err := completionFS.ReadFile(name)
	if err != nil {
		outf(stderr, "logscrub: %v\n", err)
		return exitIOFail
	}
	if _, err := stdout.Write(body); err != nil {
		return exitIOFail
	}
	return exitOK
}
