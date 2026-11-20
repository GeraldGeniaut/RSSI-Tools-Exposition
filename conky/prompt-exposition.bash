# =============================================================================
#  Indicateur d'exposition dans le prompt bash — à ajouter à la fin de ~/.bashrc
#  Lit la première ligne du dernier relevé (aucun appel réseau, instantané).
#    stable   : rien n'est affiché
#    hausse   : [EXPO:hausse] en jaune
#    autre    : [EXPO:CRITIQUE] / [EXPO:ERREUR] en rouge
#  Voir docs/08-poste-conky.md
# =============================================================================
__expo() {
  local f="$HOME/.cache/crise-alertes/exposition.txt" l etat
  [ -r "$f" ] || return
  read -r l < "$f"
  etat=${l##*\$\{alignr\}\$\{color }; etat=${etat#*\}}; etat=${etat%%\$\{color\}*}
  case "$etat" in
    stable) ;;
    hausse) printf '\[\e[1;33m\][EXPO:hausse]\[\e[0m\] ' ;;
    *)      printf '\[\e[1;31m\][EXPO:%s]\[\e[0m\] ' "$etat" ;;
  esac
}
__set_prompt() { PS1="$(__expo)${__PS1_BASE}"; }
__PS1_BASE="${__PS1_BASE:-$PS1}"
PROMPT_COMMAND="__set_prompt${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
