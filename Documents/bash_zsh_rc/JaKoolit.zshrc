# Created by newuser for 5.9

# Enable Powerlevel10k instant prompt. Keep near top.
if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then
  source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"
fi

# Load completion system
autoload -Uz compinit
compinit

# Enable zsh-autosuggestions only if installed
if [[ -f /usr/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh ]]; then
  source /usr/share/zsh/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh
  ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=8'
fi

# eza aliases:
# - --icons      : show icons
# - --group-directories-first : show directories before files
# - -l / -a etc : keep familiar ls flags working (e.g. "ls -la")
alias ls='eza --icons --group-directories-first'
alias ll='eza -l --icons --group-directories-first'
alias la='eza -la --icons --group-directories-first'
alias lt='eza -T --icons --group-directories-first'  # Tree view with icons
alias l1='eza -1 --icons --group-directories-first'  # one-per-line
alias dfree='df -hTx tmpfs'
alias nerds='kitty +list-fonts --configured'

# Powerlevel10k theme (only if installed in that path)
if [[ -f /usr/share/zsh-theme-powerlevel10k/powerlevel10k.zsh-theme ]]; then
  source /usr/share/zsh-theme-powerlevel10k/powerlevel10k.zsh-theme
fi

# p10k config
[[ ! -f ~/.p10k.zsh ]] || source ~/.p10k.zsh
