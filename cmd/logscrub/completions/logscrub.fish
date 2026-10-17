# fish completion for logscrub. Install with:
#   logscrub completion fish > ~/.config/fish/completions/logscrub.fish
complete -c logscrub -f
complete -c logscrub -n '__fish_use_subcommand' -a serve -d 'local web UI'
complete -c logscrub -n '__fish_use_subcommand' -a restore -d 'put pseudonymised text back using a map file'
complete -c logscrub -n '__fish_use_subcommand' -a completion -d 'print a shell completion script'
complete -c logscrub -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'

# filter mode
complete -c logscrub -n '__fish_use_subcommand' -l check -d 'write nothing; exit 1 if anything would be masked'
complete -c logscrub -n '__fish_use_subcommand' -l report -d 'print counts per detector'
complete -c logscrub -n '__fish_use_subcommand' -l report-format -x -a 'text json sarif' -d 'format of --report'
complete -c logscrub -n '__fish_use_subcommand' -l enable -x -a '(logscrub --list-detectors 2>/dev/null | string replace -r "\s+.*" "")' -d 'detector ids to add'
complete -c logscrub -n '__fish_use_subcommand' -l disable -x -a '(logscrub --list-detectors 2>/dev/null | string replace -r "\s+.*" "")' -d 'detector ids to turn off'
complete -c logscrub -n '__fish_use_subcommand' -l list-detectors -d 'list detector ids and exit'
complete -c logscrub -n '__fish_use_subcommand' -l version -d 'print version and exit'
complete -c logscrub -n '__fish_use_subcommand' -l max-line-bytes -x -d 'longest line scanned in one piece'
complete -c logscrub -n '__fish_use_subcommand' -l max-private-key-lines -x -d 'longest private key block masked line by line'
complete -c logscrub -n '__fish_use_subcommand' -l mode -x -a 'marker pseudonym' -d 'replacement style'
complete -c logscrub -n '__fish_use_subcommand' -l key-file -r -d 'pseudonym HMAC key file'
complete -c logscrub -n '__fish_use_subcommand' -l config -r -d 'TOML rules file'
complete -c logscrub -n '__fish_use_subcommand' -l map-file -r -d 'with --mode pseudonym: record what each tag stands for'
complete -c logscrub -n '__fish_seen_subcommand_from restore' -l map-file -r -d 'map file to restore from'
complete -c logscrub -n '__fish_use_subcommand' -l no-config -d 'do not read the per-user config file'
complete -c logscrub -n '__fish_use_subcommand' -s o -l output -r -d 'write the cleaned text to this file'
complete -c logscrub -n '__fish_use_subcommand' -s i -l in-place -d 'rewrite each file with its cleaned text'
complete -c logscrub -n '__fish_use_subcommand' -l backup-suffix -x -d 'keep the original of each rewritten file under this suffix'
complete -c logscrub -n '__fish_use_subcommand' -s r -l recursive -d 'descend into directories'
complete -c logscrub -n '__fish_use_subcommand' -l include -x -d 'with --recursive: file name globs to process'
complete -c logscrub -n '__fish_use_subcommand' -l exclude -x -d 'with --recursive: file or directory name globs to skip'
complete -c logscrub -n '__fish_use_subcommand' -l help -d 'show help'
complete -c logscrub -n '__fish_use_subcommand' -F

# serve
complete -c logscrub -n '__fish_seen_subcommand_from serve' -l addr -x -d 'address to listen on'
complete -c logscrub -n '__fish_seen_subcommand_from serve' -l allow-remote -d 'allow a non-loopback address (an access token is then required)'
complete -c logscrub -n '__fish_seen_subcommand_from serve' -l token-file -r -d 'file holding the API access token'
complete -c logscrub -n '__fish_seen_subcommand_from serve' -l config -r -d 'TOML rules file'
complete -c logscrub -n '__fish_seen_subcommand_from serve' -l no-config -d 'do not read the per-user config file'
complete -c logscrub -n '__fish_seen_subcommand_from serve' -l key-file -r -d 'pseudonym HMAC key file'
complete -c logscrub -n '__fish_seen_subcommand_from serve' -l max-body-bytes -x -d 'largest text accepted'
complete -c logscrub -n '__fish_seen_subcommand_from serve' -l max-line-bytes -x -d 'longest line scanned in one piece'
complete -c logscrub -n '__fish_seen_subcommand_from serve' -l max-private-key-lines -x -d 'longest private key block masked line by line'
complete -c logscrub -n '__fish_seen_subcommand_from serve' -l help -d 'show help'
