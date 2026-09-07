#!/usr/bin/env bash
# reality-sni-check.sh — vet candidate domains for use as REALITY dest/SNI
# Ubuntu 24.04 / OpenSSL 3.x
#
# Requires:  apt install -y openssl dnsutils curl jq
#
# Usage:
#   ./reality-sni-check.sh -f list.txt
#   ./reality-sni-check.sh -f list.txt -c DE -j 8 -o good.txt
#   ./reality-sni-check.sh www.hetzner.com swdist.apple.com

set -uo pipefail

TIMEOUT=8
JOBS=6
MY_COUNTRY=""
OUTFILE=""
LISTFILE=""
VERBOSE=0
IPINFO_TOKEN="${IPINFO_TOKEN:-}"

# ---------- shared CDN networks ----------
# Thousands of sites sit behind the same IPs here; not ideal as a REALITY dest.
CDN_RE='cloudflare|akamai|fastly|cloudfront|amazon|edgecast|stackpath|incapsula|imperva|sucuri|bunny|cdn77|limelight|edgio|azure|microsoft|leaseweb cdn|gcore|keycdn|qrator|ddos-guard'

# ================= single-domain check (internal mode) =================
if [[ "${1:-}" == "--check-one" ]]; then
  d="$2"; TIMEOUT="$3"; MY_COUNTRY="$4"; IPINFO_TOKEN="${5:-}"
  fails=(); warns=(); ip=""; org=""; cc=""; rtt=""

  emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
           "$d" "$1" "${ip:--}" "${cc:--}" "${org:--}" "${rtt:--}" "$2"; exit 0; }

  # 1) DNS
  ip=$(dig +short +time=3 +tries=1 A "$d" 2>/dev/null | grep -Ev '\.$' | head -1)
  [[ -z "$ip" ]] && emit FAIL "DNS: no A record"

  # 2) TCP/443 reachability + latency
  t0=$(date +%s%N)
  if ! timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$ip/443" 2>/dev/null; then
    emit FAIL "TCP: port 443 closed or unreachable"
  fi
  rtt=$(( ($(date +%s%N) - t0) / 1000000 ))
  (( rtt > 400 )) && warns+=("high latency ${rtt}ms")

  # 3) TLS 1.3 handshake with ALPN h2
  hs=$(timeout "$TIMEOUT" openssl s_client -connect "$ip:443" -servername "$d" \
         -tls1_3 -alpn h2 -verify_return_error </dev/null 2>&1)

  grep -qE 'New, TLSv1\.3|Protocol *: *TLSv1\.3' <<<"$hs" || fails+=("no TLSv1.3 support")
  grep -q 'ALPN protocol: h2' <<<"$hs" || fails+=("ALPN h2 not negotiated")
  grep -q 'Verify return code: 0 (ok)' <<<"$hs" || {
      vr=$(grep -m1 'Verify return code:' <<<"$hs" | sed 's/.*code: //')
      fails+=("invalid certificate (${vr:-unknown})")
  }

  # REALITY relies on an X25519 key exchange
  tk=$(grep -m1 'Server Temp Key:' <<<"$hs" | sed 's/.*Key: //;s/,.*//')
  [[ -n "$tk" && "$tk" != X25519* ]] && warns+=("temp key is $tk, not X25519")

  # 4) does the certificate actually cover this domain?
  san=$(sed -n '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' <<<"$hs" \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null \
        | tr ',' '\n' | sed -n 's/.*DNS://p' | tr -d ' ')
  if [[ -n "$san" ]]; then
    match=0
    while read -r n; do
      [[ -z "$n" ]] && continue
      [[ "$n" == "$d" ]] && { match=1; break; }
      if [[ "$n" == \*.* ]]; then
        base="${n#\*.}"
        [[ "$d" == *".$base" && "${d%%.*}.$base" == "$d" ]] && { match=1; break; }
      fi
    done <<<"$san"
    (( match )) || fails+=("certificate does not cover this domain")
  fi

  # 5) IP ownership — shared-CDN detection and country
  #    Primary: ipinfo.io (true geolocation). Fallback: Team Cymru over DNS,
  #    which has no rate limit and is not geo-blocked, but reports the
  #    registry country of the allocation rather than the physical location.
  src=""
  info=$(timeout 6 curl -s ${IPINFO_TOKEN:+-H "Authorization: Bearer $IPINFO_TOKEN"} \
         "https://ipinfo.io/$ip/json" 2>/dev/null)
  if [[ -n "$info" ]] && jq -e '.org' >/dev/null 2>&1 <<<"$info"; then
    org=$(jq -r '.org // "-"' <<<"$info" | cut -c1-40)
    cc=$(jq -r '.country // "-"' <<<"$info")
    src="geo"
  else
    # Team Cymru: <reversed-ip>.origin.asn.cymru.com TXT
    #   "24940 | 213.133.116.0/24 | DE | ripencc | 2005-06-13"
    IFS=. read -r o1 o2 o3 o4 <<<"$ip"
    ctxt=$(dig +short +time=3 +tries=2 TXT "$o4.$o3.$o2.$o1.origin.asn.cymru.com" \
           2>/dev/null | tr -d '"' | head -1)
    if [[ -n "$ctxt" ]]; then
      asn=$(awk -F'|' '{print $1}' <<<"$ctxt" | xargs | cut -d' ' -f1)
      cc=$(awk -F'|' '{print $3}'  <<<"$ctxt" | xargs)
      # AS<n>.asn.cymru.com TXT -> "24940 | DE | ripencc | ... | Hetzner Online GmbH, DE"
      nm=$(dig +short +time=3 +tries=2 TXT "AS${asn}.asn.cymru.com" \
           2>/dev/null | tr -d '"' | head -1 | awk -F'|' '{print $5}' | xargs)
      org=$(echo "AS${asn} ${nm}" | cut -c1-40)
      src="reg"
    fi
  fi

  if [[ -n "$src" ]]; then
    shopt -s nocasematch
    [[ "$org" =~ $CDN_RE ]] && warns+=("shared CDN: $org")
    shopt -u nocasematch
    [[ -n "$MY_COUNTRY" && "$cc" != "-" && -n "$cc" && "$cc" != "$MY_COUNTRY" ]] \
      && warns+=("country $cc differs from server $MY_COUNTRY")
    # mark registry-derived country so it is not read as geolocation
    [[ "$src" == "reg" ]] && cc="${cc}*"
  else
    warns+=("IP ownership lookup unavailable")
  fi

  # 6) redirect to a different domain
  loc=$(timeout "$TIMEOUT" curl -sI -o /dev/null -w '%{redirect_url}' \
        --max-time "$TIMEOUT" "https://$d" 2>/dev/null)
  if [[ -n "$loc" ]]; then
    host=$(sed -E 's#https?://##; s#/.*##; s#:.*##' <<<"$loc")
    [[ -n "$host" && "$host" != "$d" ]] && warns+=("redirects to $host")
  fi

  # ---------- verdict ----------
  if ((${#fails[@]})); then
    emit FAIL "$(IFS='; '; echo "${fails[*]}")"
  elif ((${#warns[@]})); then
    emit WARN "$(IFS='; '; echo "${warns[*]}")"
  else
    emit PASS "all criteria met"
  fi
fi

usage() {
  cat <<'EOF'
reality-sni-check.sh — vet domains for use as a REALITY dest/SNI

  -f FILE     domain list file (one per line, # for comments)
  -c CC       your server's country code, e.g. DE — checks geographic consistency
  -j N        parallel checks (default 6)
  -t SEC      timeout per check (default 8)
  -o FILE     write accepted domains to this file
  -v          show the reason behind every warning
  -h          this help

Example:
  ./reality-sni-check.sh -f list.txt -c DE -o good.txt

Criteria:
  REQUIRED  DNS resolves - TCP/443 open - TLSv1.3 - ALPN h2 - valid cert - cert covers domain
  WARNING   shared CDN - country mismatch - off-domain redirect - high latency - non-X25519 key
EOF
}

while getopts ":f:c:j:t:o:vh" opt; do
  case $opt in
    f) LISTFILE="$OPTARG" ;;
    c) MY_COUNTRY="${OPTARG^^}" ;;
    j) JOBS="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    v) VERBOSE=1 ;;
    h) usage; exit 0 ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 1 ;;
    :)  echo "Option -$OPTARG requires an argument" >&2; exit 1 ;;
  esac
done
shift $((OPTIND-1))

# ---------- required tools ----------
need_pkg=()
command -v openssl >/dev/null || need_pkg+=(openssl)
command -v dig     >/dev/null || need_pkg+=(dnsutils)
command -v curl    >/dev/null || need_pkg+=(curl)
command -v jq      >/dev/null || need_pkg+=(jq)
if ((${#need_pkg[@]})); then
  echo "Missing required tools. Run:" >&2
  echo "  apt update && apt install -y ${need_pkg[*]}" >&2
  exit 1
fi

# ================= main =================
domains=()
if [[ -n "$LISTFILE" ]]; then
  [[ -r "$LISTFILE" ]] || { echo "Cannot read file: $LISTFILE" >&2; exit 1; }
  while read -r line; do
    line="${line%%#*}"; line="$(tr -d '[:space:]' <<<"$line")"
    line="${line#http://}"; line="${line#https://}"; line="${line%%/*}"
    [[ -n "$line" ]] && domains+=("$line")
  done < "$LISTFILE"
fi
domains+=("$@")

((${#domains[@]})) || { echo "No domains given." >&2; usage; exit 1; }

# de-duplicate
mapfile -t domains < <(printf '%s\n' "${domains[@]}" | awk '!seen[$0]++')

echo "Checking ${#domains[@]} domains with $JOBS parallel workers..."
[[ -n "$MY_COUNTRY" ]] && echo "Server country: $MY_COUNTRY"
echo

TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
SELF="$(readlink -f "$0")"

printf '%s\n' "${domains[@]}" \
  | xargs -P "$JOBS" -I{} bash "$SELF" --check-one {} "$TIMEOUT" "$MY_COUNTRY" "$IPINFO_TOKEN" \
  > "$TMP" 2>/dev/null

# ---------- report ----------
G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'
printf "${B}%-34s %-6s %-16s %-4s %s${N}\n" "DOMAIN" "STATUS" "IP" "CC" "ORG"
printf '%.0s-' {1..100}; echo

for st in PASS WARN FAIL; do
  case $st in PASS) col=$G ;; WARN) col=$Y ;; FAIL) col=$R ;; esac
  while IFS=$'\t' read -r d s ip cc org rtt note; do
    [[ "$s" == "$st" ]] || continue
    printf "${col}%-34s %-6s${N} %-16s %-4s %s\n" "$d" "$s" "$ip" "$cc" "$org"
    if [[ "$st" == FAIL ]] || { [[ "$st" == WARN ]] && (( VERBOSE )); }; then
      printf "  ${col}\\_${N} %s\n" "$note"
    fi
  done < <(sort "$TMP")
done

p=$(grep -c $'\tPASS\t' "$TMP"); w=$(grep -c $'\tWARN\t' "$TMP"); f=$(grep -c $'\tFAIL\t' "$TMP")
echo
echo "${G}PASS: $p${N}   ${Y}WARN: $w${N}   ${R}FAIL: $f${N}"
grep -q '\*\t' "$TMP" && \
  echo "CC marked with * came from the registry allocation (Team Cymru), not geolocation."

if [[ -n "$OUTFILE" ]]; then
  awk -F'\t' '$2=="PASS" || $2=="WARN" {print $1}' "$TMP" | sort > "$OUTFILE"
  echo "Usable domains written to: $OUTFILE"
fi

cat <<'EOF'

Note: this script measures technical health, not whether a domain is blocked.
Every domain that passes here should also be tested from inside Iran:
    openssl s_client -connect DOMAIN:443 -servername DOMAIN -tls1_3 -alpn h2 </dev/null
Running this same script on a machine inside Iran will mark blocked domains as FAIL.
EOF
