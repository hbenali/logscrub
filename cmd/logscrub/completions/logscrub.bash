# bash completion for logscrub. Install with:
#   logscrub completion bash > ~/.local/share/bash-completion/completions/logscrub
_logscrub() {
    local cur prev sub="" i
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    for ((i = 1; i < COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            serve | completion) sub="${COMP_WORDS[i]}"; break ;;
        esac
    done

    local main_flags="--check --report --report-format --enable --disable --list-detectors --version --max-line-bytes --max-private-key-lines --mode --key-file --config --no-config --output -o --help"
    local serve_flags="--addr --allow-remote --config --no-config --key-file --token-file --max-body-bytes --max-line-bytes --max-private-key-lines --help"

    if [[ $sub == completion ]]; then
        COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur"))
        return
    fi
    case "$prev" in
        --mode) COMPREPLY=($(compgen -W "marker pseudonym" -- "$cur")); return ;;
        --report-format) COMPREPLY=($(compgen -W "text json sarif" -- "$cur")); return ;;
        --config | --key-file | --token-file | --output | -o) COMPREPLY=($(compgen -f -- "$cur")); return ;;
        --enable | --disable)
            COMPREPLY=($(compgen -W "$(logscrub --list-detectors 2>/dev/null | awk '{print $1}')" -- "$cur"))
            return ;;
    esac
    if [[ $cur == -* ]]; then
        if [[ $sub == serve ]]; then
            COMPREPLY=($(compgen -W "$serve_flags" -- "$cur"))
        else
            COMPREPLY=($(compgen -W "$main_flags" -- "$cur"))
        fi
    elif [[ -z $sub && $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=($(compgen -W "serve completion" -- "$cur") $(compgen -f -- "$cur"))
    elif [[ -z $sub ]]; then
        COMPREPLY=($(compgen -f -- "$cur"))
    fi
}
complete -F _logscrub logscrub
