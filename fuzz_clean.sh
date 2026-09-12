#!/bin/bash

# ============================================================
#   FUZZ_CLEAN.SH — Automated Content Discovery
#   Legge waf_scan_results.txt, estrae i target [OK] e
#   lancia ffuf su ciascuno salvando report JSON individuali.
#
#   Uso: ./fuzz_clean.sh [opzioni]
#
#   Opzioni:
#     -l  File di log WAF    (default: waf_scan_results.txt)
#     -w  Wordlist           (default: /usr/share/wordlists/dirb/common.txt)
#     -o  Directory output   (default: ./fuzz_results/)
#     -t  Threads ffuf       (default: 40)
#     -fc Codici da filtrare (default: 404,403,429)
#     -h  Mostra questo help
#
#   Dipendenze: ffuf, curl
# ============================================================

# ---------- Colori ANSI ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ---------- Default ----------
LOG_FILE="waf_scan_results.txt"
WORDLIST="/usr/share/wordlists/dirb/common.txt"
OUTPUT_DIR="./fuzz_results"
THREADS=40
FILTER_CODES="404,403,429"

# ---------- Contatori ----------
COUNT_OK=0
COUNT_FOUND=0
COUNT_ERROR=0

# ============================================================
# UTILITY
# ============================================================

print_banner() {
    echo -e "${BOLD}${CYAN}"
    echo "  ███████╗██╗   ██╗███████╗███████╗"
    echo "  ██╔════╝██║   ██║╚══███╔╝╚══███╔╝"
    echo "  █████╗  ██║   ██║  ███╔╝   ███╔╝ "
    echo "  ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  "
    echo "  ██║     ╚██████╔╝███████╗███████╗ "
    echo "  ╚═╝      ╚═════╝ ╚══════╝╚══════╝ CLEAN"
    echo -e "${RESET}${DIM}  Content Discovery — ffuf sui target [OK] del log WAF${RESET}"
    echo ""
}

step()  { echo -e "\n${BOLD}${MAGENTA}[STEP $1]${RESET} $2"; divider; }
ok()    { echo -e "  ${GREEN}[✔]${RESET} $*"; }
warn()  { echo -e "  ${YELLOW}[!]${RESET} $*"; }
err()   { echo -e "  ${RED}[✘]${RESET} $*"; }
info()  { echo -e "  ${CYAN}[*]${RESET} $*"; }
divider(){ echo -e "${DIM}  ──────────────────────────────────────────────────${RESET}"; }

usage() {
    echo -e "${BOLD}Uso:${RESET}"
    echo "  ./fuzz_clean.sh [opzioni]"
    echo ""
    echo -e "${BOLD}Opzioni:${RESET}"
    echo "  -l  File di log WAF    (default: waf_scan_results.txt)"
    echo "  -w  Wordlist           (default: /usr/share/wordlists/dirb/common.txt)"
    echo "  -o  Directory output   (default: ./fuzz_results/)"
    echo "  -t  Threads ffuf       (default: 40)"
    echo "  -fc Codici da filtrare (default: 404,403,429)"
    echo "  -h  Mostra questo help"
    echo ""
    exit 0
}

# ============================================================
# PARSING ARGOMENTI
# ============================================================
# Gestiamo -fc manualmente perché getopts non supporta opzioni
# a due caratteri; tutti gli altri con getopts standard.
args=("$@")
i=0
while [[ $i -lt ${#args[@]} ]]; do
    case "${args[$i]}" in
        -fc) i=$((i+1)); FILTER_CODES="${args[$i]}" ;;
        -l)  i=$((i+1)); LOG_FILE="${args[$i]}" ;;
        -w)  i=$((i+1)); WORDLIST="${args[$i]}" ;;
        -o)  i=$((i+1)); OUTPUT_DIR="${args[$i]}" ;;
        -t)  i=$((i+1)); THREADS="${args[$i]}" ;;
        -h)  usage ;;
        *)   err "Opzione non riconosciuta: ${args[$i]}"; exit 1 ;;
    esac
    i=$((i+1))
done

# ============================================================
# STEP 0 — PRE-FLIGHT
# ============================================================
preflight() {
    step "0" "Pre-flight — verifica dipendenze e configurazione"

    local fail=false

    # ffuf
    if command -v ffuf &>/dev/null; then
        ok "ffuf trovato: $(command -v ffuf)"
    else
        err "ffuf NON trovato nel PATH."
        echo -e "     ${DIM}Installalo con: go install github.com/ffuf/ffuf/v2@latest${RESET}"
        echo -e "     ${DIM}Oppure: https://github.com/ffuf/ffuf/releases${RESET}"
        fail=true
    fi

    # curl (usato per un quick-check prima di ogni fuzz)
    if command -v curl &>/dev/null; then
        ok "curl trovato: $(command -v curl)"
    else
        err "curl NON trovato nel PATH."
        fail=true
    fi

    $fail && { err "Pre-flight fallito. Installa le dipendenze mancanti."; exit 1; }
    echo ""
}

# ============================================================
# STEP 1 — VERIFICA FILE DI LOG
# ============================================================
check_log() {
    step "1" "Verifica file di log WAF"

    if [[ ! -f "$LOG_FILE" ]]; then
        err "File '${LOG_FILE}' non trovato nella directory corrente."
        echo -e "     ${DIM}Esegui prima bypass.sh per generarlo, oppure usa -l per specificare un percorso diverso.${RESET}"
        exit 1
    fi

    if [[ ! -s "$LOG_FILE" ]]; then
        err "Il file '${LOG_FILE}' esiste ma è vuoto."
        exit 1
    fi

    ok "File trovato: ${BOLD}${LOG_FILE}${RESET} ($(wc -l < "$LOG_FILE") righe)"
}

# ============================================================
# STEP 2 — ESTRAZIONE TARGET [OK]
# ============================================================
extract_ok_targets() {
    step "2" "Estrazione target con stato [OK]"

    # Il formato del log è:
    #   [OK] https://sub.domain.com
    #        HTTP 200 — Nessun WAF aggressivo rilevato
    #
    # Estraiamo la seconda colonna delle righe che iniziano con [OK]
    mapfile -t OK_TARGETS < <(
        grep -E "^\[OK\]" "$LOG_FILE" \
        | awk '{print $2}' \
        | grep -E "^https?://" \
        | sort -u
    )

    COUNT_OK=${#OK_TARGETS[@]}

    if [[ $COUNT_OK -eq 0 ]]; then
        warn "Nessun target con stato [OK] trovato in '${LOG_FILE}'."
        warn "Tutti i sottodomini risultano bloccati, con WAF o in errore."
        exit 0
    fi

    ok "Target [OK] estratti: ${BOLD}${GREEN}${COUNT_OK}${RESET}"
}

# ============================================================
# STEP 3 — RIEPILOGO TARGET PULITI
# ============================================================
show_targets() {
    step "3" "Lista target puliti"

    local idx=1
    for url in "${OK_TARGETS[@]}"; do
        echo -e "  ${DIM}${idx}.${RESET} ${CYAN}${url}${RESET}"
        idx=$((idx+1))
    done
    echo ""

    info "Wordlist   : ${BOLD}${WORDLIST}${RESET}"
    info "Output dir : ${BOLD}${OUTPUT_DIR}${RESET}"
    info "Threads    : ${BOLD}${THREADS}${RESET}"
    info "Filtri HTTP: ${BOLD}${FILTER_CODES}${RESET}"
    echo ""

    # Verifica wordlist
    if [[ ! -f "$WORDLIST" ]]; then
        warn "Wordlist '${WORDLIST}' non trovata."
        warn "Specifica un percorso valido con -w (es: -w ~/wordlists/common.txt)"
        exit 1
    fi
    ok "Wordlist trovata: $(wc -l < "$WORDLIST") entries"

    # Crea directory output se non esiste
    mkdir -p "$OUTPUT_DIR" || {
        err "Impossibile creare la directory '${OUTPUT_DIR}'."
        exit 1
    }
    ok "Directory output: ${BOLD}${OUTPUT_DIR}${RESET}"
}

# ============================================================
# STEP 4 — FUZZING
# ============================================================

# Converte un URL in un nome file sicuro
# https://sub.example.com → sub_example_com
url_to_filename() {
    local url="$1"
    echo "$url" \
        | sed 's|https\?://||' \
        | sed 's|[^a-zA-Z0-9._-]|_|g' \
        | sed 's|_\+|_|g' \
        | sed 's|^_||; s|_$||'
}

# Quick-check: testa se il target risponde prima di fuzzarlo
is_reachable() {
    local url="$1"
    curl -s -o /dev/null -w "%{http_code}" \
        --max-time 8 --connect-timeout 5 \
        -A "Mozilla/5.0" "$url" 2>/dev/null \
        | grep -qE "^[1-4][0-9]{2}$"
}

fuzz_all() {
    step "4" "Content Discovery con ffuf"

    local idx=0
    for url in "${OK_TARGETS[@]}"; do
        idx=$((idx+1))

        echo ""
        echo -e "${BOLD}${MAGENTA}  ── [${idx}/${COUNT_OK}]${RESET} ${CYAN}${BOLD}${url}${RESET}"
        divider

        # ---------- Costruzione percorsi ----------
        local slug
        slug=$(url_to_filename "$url")
        local json_out="${OUTPUT_DIR}/fuzz_${slug}.json"
        local tmp_stderr
        tmp_stderr=$(mktemp)

        # ---------- Quick-check raggiungibilità ----------
        info "Verifica raggiungibilità..."
        if ! is_reachable "$url"; then
            warn "Target non raggiungibile — saltato."
            COUNT_ERROR=$((COUNT_ERROR+1))
            rm -f "$tmp_stderr"
            continue
        fi
        ok "Target risponde — avvio fuzzing"

        # ---------- Costruzione URL di fuzzing ----------
        # Rimuove eventuale slash finale e appende /FUZZ
        local fuzz_url="${url%/}/FUZZ"
        info "Fuzz URL   : ${BOLD}${fuzz_url}${RESET}"
        info "Report JSON: ${BOLD}${json_out}${RESET}"
        echo ""

        # ---------- Esecuzione ffuf ----------
        # Opzioni usate:
        #   -u       URL con keyword FUZZ
        #   -w       wordlist
        #   -t       threads paralleli
        #   -fc      filtra codici HTTP inutili (404, 403, 429, ecc.)
        #   -o       file di output
        #   -of      formato output (json)
        #   -s       silent: sopprime il banner di ffuf
        #   -r       segui redirect
        #   -H       header User-Agent realistico
        #   -timeout timeout per singola richiesta (secondi)
        ffuf \
            -u       "${fuzz_url}" \
            -w       "${WORDLIST}" \
            -t       "${THREADS}" \
            -fc      "${FILTER_CODES}" \
            -o       "${json_out}" \
            -of      json \
            -s \
            -r \
            -H       "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            -H       "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
            -timeout 10 \
            2>"$tmp_stderr"

        local exit_code=$?
        local stderr_out
        stderr_out=$(cat "$tmp_stderr")
        rm -f "$tmp_stderr"

        # ---------- Valutazione risultato ----------
        if [[ $exit_code -ne 0 ]]; then
            warn "ffuf ha restituito codice ${exit_code}."
            [[ -n "$stderr_out" ]] && echo -e "     ${DIM}${stderr_out}${RESET}"
            COUNT_ERROR=$((COUNT_ERROR+1))
            continue
        fi

        # Conta i risultati nel JSON (campo "results")
        local hits=0
        if [[ -f "$json_out" ]] && command -v python3 &>/dev/null; then
            hits=$(python3 -c "
import json, sys
try:
    d = json.load(open('${json_out}'))
    print(len(d.get('results', [])))
except:
    print(0)
" 2>/dev/null)
        fi

        if [[ "$hits" -gt 0 ]]; then
            ok "${BOLD}${GREEN}${hits} path trovati${RESET} — report: ${json_out}"
            COUNT_FOUND=$((COUNT_FOUND + hits))
            # Mostra anteprima dei path trovati
            if command -v python3 &>/dev/null; then
                echo ""
                info "Anteprima risultati:"
                python3 -c "
import json
d = json.load(open('${json_out}'))
results = d.get('results', [])[:10]
for r in results:
    status = r.get('status', '?')
    length = r.get('length', '?')
    url    = r.get('url', '?')
    print(f'    \033[2m[{status}]\033[0m [{length}b] {url}')
" 2>/dev/null
                [[ "$hits" -gt 10 ]] && echo -e "    ${DIM}... e altri $((hits-10)) risultati nel JSON${RESET}"
            fi
        else
            warn "Nessun path interessante trovato (tutti filtrati)."
            # Rimuovi il JSON vuoto per non riempire la directory
            [[ -f "$json_out" ]] && rm -f "$json_out"
        fi

    done
}

# ============================================================
# RIEPILOGO FINALE
# ============================================================
print_summary() {
    echo ""
    echo -e "${BOLD}${CYAN}  ══════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}    PIPELINE COMPLETATA${RESET}"
    echo -e "${CYAN}  ══════════════════════════════════════════════════${RESET}"
    echo -e "  ${DIM}Target analizzati    :${RESET} ${BOLD}${COUNT_OK}${RESET}"
    echo -e "  ${DIM}Path totali trovati  :${RESET} ${BOLD}${GREEN}${COUNT_FOUND}${RESET}"
    echo -e "  ${DIM}Target in errore     :${RESET} ${BOLD}${RED}${COUNT_ERROR}${RESET}"
    echo -e "  ${DIM}Report JSON in       :${RESET} ${BOLD}${OUTPUT_DIR}/${RESET}"

    # Lista report generati
    local reports
    mapfile -t reports < <(find "$OUTPUT_DIR" -name "fuzz_*.json" 2>/dev/null | sort)
    if [[ ${#reports[@]} -gt 0 ]]; then
        echo ""
        info "Report generati:"
        for r in "${reports[@]}"; do
            echo -e "    ${DIM}→${RESET} ${r}"
        done
    fi

    echo -e "${CYAN}  ══════════════════════════════════════════════════${RESET}"
    echo ""
}

# ============================================================
# MAIN
# ============================================================
main() {
    print_banner
    preflight
    check_log
    extract_ok_targets
    show_targets
    fuzz_all
    print_summary
}

main