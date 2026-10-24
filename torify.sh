#!/usr/bin/env bash
#
# torify.sh - leitet den TCP-Verkehr und DNS eines Debian/Ubuntu-Systems durch das
#             Tor-Netzwerk (SOCKS5-Proxy 127.0.0.1:9050), auf Wunsch zusaetzlich durch
#             einen externen Proxy hinter Tor. UDP geht direkt ins Netz.
#
# Funktionsweise
#   iptables kann Verbindungen nicht direkt an einen SOCKS5-Proxy uebergeben.
#   Deshalb sitzt redsocks als Uebersetzer dazwischen:
#
#     TCP   -> iptables REDIRECT -> redsocks :12346 -> SOCKS5 127.0.0.1:9050 -> Tor
#     DNS   -> iptables REDIRECT -> Tor-DNSPort 127.0.0.1:9053
#              (Tor transportiert ueber SOCKS5 kein UDP, daher der eigene DNS-Port)
#     UDP   -> direkt ins Netz, NICHT ueber Tor (IPv4 und IPv6, ausser DNS)
#     Rest  -> blockiert: ICMP und TCP ueber IPv6 (Kill-Switch)
#
#   Ausgenommen sind nur der Tor-Prozess selbst (Benutzer debian-tor), Loopback
#   und Antworten auf eingehende Verbindungen (damit z.B. eine SSH-Sitzung bleibt).
#
# Proxy-Kette Tor -> externer Proxy (--chain)
#     TCP   -> redsocks :12346 -> socat :12348 -> Tor -> externer Proxy -> Ziel
#     https -> redsocks :12346 -> socat TLS :12349 -> socat :12348 -> Tor -> Proxy -> Ziel
#
#   socat baut durch Tor einen Tunnel zum externen Proxy auf. redsocks spricht durch
#   diesen Tunnel das Protokoll des Proxys (SOCKS5 oder HTTP CONNECT, mit Login).
#   Beim Typ https legt ein zweites socat TLS darueber und prueft das Zertifikat des
#   Proxys gegen die System-CAs oder gegen --chain-cafile. Eine Option zum Abschalten
#   der Pruefung gibt es bewusst nicht, sonst koennte der Tor-Exit-Knoten mitlesen.
#   Der Proxy sieht nur eine Tor-Exit-Adresse, das Ziel nur die Adresse des Proxys.
#   DNS wird weiterhin ueber Tor aufgeloest. .onion-Adressen gehen direkt an Tor.
#   UDP geht auch in der Kette direkt ins Netz, nicht ueber Tor oder den Proxy.
#
# Nutzung
#   sudo ./torify.sh start [--allow-lan] [--no-install] [--chain HOST:PORT ...]
#   sudo ./torify.sh stop
#   sudo ./torify.sh restart [Optionen wie bei start]
#        ./torify.sh status
#        ./torify.sh check
#        ./torify.sh start --dry-run      zeigt nur an, was ausgefuehrt wuerde
#
#   --allow-lan            Verkehr ins lokale Netz (10/8, 172.16/12, 192.168/16, ...)
#                          direkt erlauben, z.B. fuer Drucker. DNS bleibt bei Tor.
#   --direct-dns           DNS ebenfalls direkt statt ueber Tor. Dann sieht der
#                          DNS-Server bzw. Provider jeden aufgerufenen Hostnamen.
#   --no-install           fehlende Pakete nicht automatisch per apt-get installieren
#   --chain HOST:PORT      externer Proxy hinter Tor (IPv4-Adresse oder Hostname)
#   --chain-type TYP       socks5 (Standard), http (HTTP CONNECT) oder
#                          https (HTTP CONNECT ueber TLS, empfohlen)
#   --chain-user NAME      Benutzername fuer den externen Proxy
#   --chain-pass PASSWORT  Passwort dazu. Fehlt es, fragt das Script danach.
#                          Ohne Terminal: Umgebungsvariable TORIFY_CHAIN_PASS.
#   --chain-cafile DATEI   nur bei https: eigene CA oder selbstsigniertes Zertifikat
#                          des Proxys (PEM) statt der System-CAs
#
#   Beispiele
#     sudo ./torify.sh start --chain 203.0.113.5:1080
#     sudo ./torify.sh start --chain proxy.example.org:443 --chain-type https --chain-user alice
#     sudo ./torify.sh start --chain 203.0.113.5:8443 --chain-type https --chain-cafile proxy-ca.pem
#
# Ports und Pfade lassen sich per Umgebungsvariable aendern, z.B.
#   sudo TOR_SOCKS_PORT=9150 ./torify.sh start
#   TOR_SOCKS_PORT (9050)  TOR_DNS_PORT (9053)  REDSOCKS_PORT (12346)  ONION_PORT (12347)
#   CHAIN_TUNNEL_PORT (12348)  CHAIN_TLS_PORT (12349)  TOR_VIRT_NET (10.192.0.0/10)
#   TORRC (/etc/tor/torrc)
#
# Einschraenkungen
#   - Nicht persistent: nach einem Neustart des Rechners laeuft der Verkehr wieder direkt.
#   - Erfasst nur lokal erzeugten Verkehr, nicht weitergeleiteten (Docker, VMs).
#   - UDP laeuft direkt und zeigt die echte IP-Adresse: QUIC (HTTP/3), WebRTC, VoIP,
#     Spiele, VPNs, NTP. Browser laden viele grosse Seiten per QUIC, also an Tor vorbei.
#   - Tor-DNS beantwortet nur A-, AAAA- und PTR-Anfragen.
#   - Programme mit AF_PACKET-Sockets (z.B. dhclient) umgehen netfilter grundsaetzlich.
#   - Kette: Viele HTTP-Proxys erlauben CONNECT nur zu Port 443, dann klappt
#     unverschluesseltes HTTP nicht. Manche Proxys sperren Verbindungen aus Tor.
#   - Kette mit socks5 oder http: Der Tor-Exit-Knoten sieht Login und Ziele, die an den
#     Proxy gehen, im Klartext. Mit --chain-type https ist diese Strecke verschluesselt.
#   - Kommandozeilen-Argumente wie --chain-pass sieht jeder lokale Benutzer per "ps".
#   - Anonymitaet entsteht dadurch nicht automatisch: Browser-Fingerprints, Logins und
#     Cookies verraten weiterhin viel. Zum anonymen Surfen den Tor Browser verwenden.

set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

# ------------------------------------------------------------------ Konfiguration
TOR_SOCKS_ADDR=127.0.0.1
TOR_SOCKS_PORT=${TOR_SOCKS_PORT:-9050}
TOR_DNS_PORT=${TOR_DNS_PORT:-9053}
REDSOCKS_PORT=${REDSOCKS_PORT:-12346}           # Eingang fuer allen TCP-Verkehr
ONION_PORT=${ONION_PORT:-12347}                 # .onion-Adressen, immer direkt zu Tor
CHAIN_TUNNEL_PORT=${CHAIN_TUNNEL_PORT:-12348}   # socat-Tunnel durch Tor zum externen Proxy
CHAIN_TLS_PORT=${CHAIN_TLS_PORT:-12349}         # socat: TLS zum Proxy (nur Typ https)
TOR_VIRT_NET=${TOR_VIRT_NET:-10.192.0.0/10}
TORRC=${TORRC:-/etc/tor/torrc}
TOR_USER=${TOR_USER:-}            # leer = automatisch erkennen (debian-tor)

# Proxy-Kette, wird ueber --chain gesetzt
CHAIN_HOST=''
CHAIN_PORT=''
CHAIN_TYPE=socks5
CHAIN_USER=''
CHAIN_PASS=${TORIFY_CHAIN_PASS:-}
CHAIN_PASS_SET=0                  # Passwort per Option oder Umgebung angegeben?
if [[ -n ${TORIFY_CHAIN_PASS+x} ]]; then CHAIN_PASS_SET=1; fi
CHAIN_PASS_FLAG=0                 # --chain-pass benutzt?
CHAIN_CAFILE=''                   # nur https: eigene CA statt der System-CAs
CHAIN_OPTS=0                      # irgendeine --chain-*-Option benutzt?

STATE_DIR=/run/torify
CHAIN=TORIFY
REDSOCKS_UNIT=torify-redsocks
CHAIN_UNIT=torify-chain
CHAIN_TLS_UNIT=torify-chain-tls
SYSTEM_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
CHECK_URL=https://check.torproject.org/api/ip
MARK_BEGIN="# BEGIN torify - von torify.sh verwaltet, wird bei 'stop' entfernt"
MARK_END="# END torify"
LAN_V4=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4 255.255.255.255/32)
LAN_V6=(fe80::/10 fc00::/7 ff00::/8)

ALLOW_LAN=0
DIRECT_DNS=0        # 1 = DNS nicht auf Tor umleiten (--direct-dns)
INSTALL=1
DRY_RUN=0
STARTING=0          # 1 waehrend 'start': bei einem Fehler wird alles zurueckgerollt
TOR_WAS_ACTIVE=1    # lief Tor schon vor 'start'? Entscheidet bei 'stop': Neustart oder Stopp
PROBE_IP=''
PROBE_TOR=0

sudo apt install -y socat redsocks

# ------------------------------------------------------------------ Hilfsfunktionen
if [[ -t 1 ]]; then
    C_G=$'\e[32m' C_Y=$'\e[33m' C_R=$'\e[31m' C_0=$'\e[0m'
else
    C_G='' C_Y='' C_R='' C_0=''
fi

info() { printf '%s==>%s %s\n' "$C_G" "$C_0" "$*"; }
ok()   { printf '  %s[ OK ]%s %s\n' "$C_G" "$C_0" "$*"; }
bad()  { printf '  %s[FEHL]%s %s\n' "$C_R" "$C_0" "$*"; }
warn() { printf '%sWarnung:%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
err()  { printf '%sFehler:%s %s\n' "$C_R" "$C_0" "$*" >&2; }
die()  { err "$*"; exit 1; }

# Fuehrt einen Befehl aus, im Dry-Run wird er nur angezeigt.
run() {
    if (( DRY_RUN )); then
        printf '[dry-run]'; printf ' %q' "$@"; printf '\n'
    else
        "$@"
    fi
}

# write_file PFAD [geheim] - schreibt stdin nach PFAD, "geheim" = nur fuer root lesbar
write_file() {
    if (( DRY_RUN )); then
        printf '[dry-run] schreibe %s:\n' "$1"
        sed 's/^/[dry-run]     /'
    elif [[ ${2:-} == geheim ]]; then
        rm -f "$1"
        ( umask 077; cat > "$1" )
    else
        cat > "$1"
    fi
}

ipt4() { run iptables -w "$@"; }
ipt6() { run ip6tables -w "$@"; }

has_systemd() { [[ -d /run/systemd/system ]]; }

valid_port() { [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && (( $1 < 65536 )); }

# port_listening tcp|udp PORT
port_listening() {
    local flags=-ltn
    [[ $1 == udp ]] && flags=-lun
    ss -H "$flags" "sport = :$2" 2>/dev/null | grep -q .
}

# wait_port tcp|udp PORT SEKUNDEN
wait_port() {
    local i
    for ((i = 0; i < $3; i++)); do
        port_listening "$1" "$2" && return 0
        sleep 1
    done
    return 1
}

require_root() {
    if (( ! DRY_RUN && EUID != 0 )); then
        die "Bitte als root ausfuehren: sudo $0 ..."
    fi
}

state_get() { sed -n "s/^$1=//p" "$STATE_DIR/state" 2>/dev/null || true; }

save_state() {
    local auth=nein
    [[ -n $CHAIN_USER ]] && auth=ja
    # Bewusst ohne Benutzername und Passwort: die Datei ist fuer alle lesbar.
    write_file "$STATE_DIR/state" <<EOF
TOR_WAS_ACTIVE=$TOR_WAS_ACTIVE
TOR_USER=$TOR_USER
ALLOW_LAN=$ALLOW_LAN
DIRECT_DNS=$DIRECT_DNS
CHAIN=${CHAIN_HOST:+$CHAIN_HOST:$CHAIN_PORT}
CHAIN_TYPE=$CHAIN_TYPE
CHAIN_AUTH=$auth
STARTED=$(date '+%Y-%m-%d %H:%M:%S')
EOF
}

# fetch URL TIMEOUT
fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- --timeout="$2" "$1"
    else
        return 127
    fi
}

exit_ip() { sed -nE 's/.*"IP":"([^"]*)".*/\1/p' <<<"$1"; }

# service_start UNIT BENUTZER BESCHREIBUNG BEFEHL...
# Startet einen Hintergrunddienst, unter systemd als transiente Unit.
service_start() {
    local unit=$1 user=$2 desc=$3 group
    shift 3
    group=$(id -gn "$user" 2>/dev/null || echo nogroup)
    if has_systemd; then
        local opts=(--quiet --unit="$unit" --description="$desc" --property=Restart=on-failure)
        if [[ $user != root ]]; then opts+=(--uid="$user" --gid="$group"); fi
        run systemctl reset-failed "$unit" 2>/dev/null || true
        run systemd-run "${opts[@]}" "$@"
    else
        local pre=()
        if [[ $user != root ]]; then pre=(setpriv --reuid="$user" --regid="$group" --clear-groups); fi
        if (( DRY_RUN )); then
            run nohup "${pre[@]}" "$@"
        else
            nohup "${pre[@]}" "$@" >/dev/null 2>&1 &
            echo "$!" > "$STATE_DIR/$unit.pid"
        fi
    fi
}

service_stop() {  # service_stop UNIT
    if has_systemd; then
        run systemctl stop "$1" 2>/dev/null || true
        run systemctl reset-failed "$1" 2>/dev/null || true
    fi
    if [[ -f $STATE_DIR/$1.pid ]]; then
        run kill "$(cat "$STATE_DIR/$1.pid")" 2>/dev/null || true
    fi
}

# ------------------------------------------------------------------ Proxy-Kette
# Prueft die --chain-Optionen und fragt bei Bedarf nach dem Passwort.
setup_chain() {   # setup_chain HOST:PORT  (leer = keine Kette)
    local spec=$1 v LC_ALL=C
    local host_re='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
    local private_re='^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|0\.|localhost$)'

    if [[ -z $spec ]]; then
        if (( CHAIN_OPTS )); then
            die "--chain-type, --chain-user, --chain-pass und --chain-cafile gehen nur zusammen mit --chain HOST:PORT."
        fi
        return 0
    fi

    [[ $spec == *:* ]] || die "--chain erwartet HOST:PORT, z.B. --chain 203.0.113.5:1080"
    CHAIN_HOST=${spec%:*}
    CHAIN_PORT=${spec##*:}
    if [[ ! $CHAIN_HOST =~ $host_re ]]; then
        die "Ungueltiger Proxy-Host '$CHAIN_HOST'. Erlaubt sind eine IPv4-Adresse oder ein Hostname."
    fi
    valid_port "$CHAIN_PORT" || die "Ungueltiger Proxy-Port: '$CHAIN_PORT'"
    if [[ $CHAIN_HOST =~ $private_re ]]; then
        die "Der Proxy $CHAIN_HOST muss aus dem Internet erreichbar sein, denn die Verbindung zu ihm baut ein Tor-Exit-Knoten auf."
    fi
    case $CHAIN_TYPE in
        socks5|http|https) ;;
        *) die "Unbekannter Proxy-Typ '$CHAIN_TYPE'. Moeglich sind socks5, http und https." ;;
    esac
    if [[ -n $CHAIN_CAFILE ]]; then
        [[ $CHAIN_TYPE == https ]] || die "--chain-cafile gibt es nur zusammen mit --chain-type https."
        [[ -f $CHAIN_CAFILE && -r $CHAIN_CAFILE ]] || die "CA-Datei '$CHAIN_CAFILE' ist nicht lesbar."
        grep -q -- '-----BEGIN CERTIFICATE-----' "$CHAIN_CAFILE" \
            || die "'$CHAIN_CAFILE' enthaelt kein Zertifikat im PEM-Format."
    fi

    if (( CHAIN_PASS_FLAG )) && [[ -z $CHAIN_USER ]]; then
        die "--chain-pass braucht auch --chain-user."
    fi
    if [[ -n $CHAIN_USER ]] && (( ! CHAIN_PASS_SET )); then
        if [[ -t 0 ]]; then
            read -rsp "Passwort fuer Proxy-Benutzer '$CHAIN_USER': " CHAIN_PASS
            echo >&2
        else
            die "Passwort fuer '$CHAIN_USER' fehlt: --chain-pass angeben oder TORIFY_CHAIN_PASS setzen."
        fi
    fi
    if [[ -z $CHAIN_USER ]]; then CHAIN_PASS=''; fi

    # Beide Werte landen in Anfuehrungszeichen in der redsocks-Konfiguration.
    for v in "$CHAIN_USER" "$CHAIN_PASS"; do
        if (( ${#v} > 255 )); then
            die "Benutzername und Passwort duerfen hoechstens 255 Bytes lang sein."
        fi
        if [[ $v == *[\"\\]* || $v == *[[:cntrl:]]* ]]; then
            die "Benutzername und Passwort duerfen keine Anfuehrungszeichen, Backslashes oder Steuerzeichen enthalten."
        fi
    done
    if [[ $CHAIN_TYPE == http* && $CHAIN_USER == *:* ]]; then
        die "Bei HTTP-Proxys darf der Benutzername keinen Doppelpunkt enthalten."
    fi
}

chain_desc() { printf '%s %s:%s' "$CHAIN_TYPE" "$CHAIN_HOST" "$CHAIN_PORT"; }

# socat nimmt Verbindungen auf 127.0.0.1:CHAIN_TUNNEL_PORT an und verbindet jede
# ueber Tor (SOCKS4A) mit dem externen Proxy. Bei SOCKS4A loest Tor einen Hostnamen
# des Proxys selbst auf, lokal entsteht keine DNS-Anfrage.
chain_start() {
    if [[ -z $CHAIN_HOST ]]; then return 0; fi
    local bin
    bin=$(command -v socat || echo /usr/bin/socat)
    info "Starte Tunnel: 127.0.0.1:$CHAIN_TUNNEL_PORT -> Tor -> $CHAIN_HOST:$CHAIN_PORT"
    service_start "$CHAIN_UNIT" nobody "torify: Tunnel durch Tor zum externen Proxy" \
        "$bin" "TCP-LISTEN:$CHAIN_TUNNEL_PORT,bind=127.0.0.1,reuseaddr,fork" \
        "SOCKS4A:$TOR_SOCKS_ADDR:$CHAIN_HOST:$CHAIN_PORT,socksport=$TOR_SOCKS_PORT"
    if (( ! DRY_RUN )); then
        wait_port tcp "$CHAIN_TUNNEL_PORT" 10 \
            || die "socat lauscht nicht auf Port $CHAIN_TUNNEL_PORT (Log: journalctl -u $CHAIN_UNIT)."
    fi
    if [[ $CHAIN_TYPE == https ]]; then chain_tls_start "$bin"; fi
}

# Typ https: ein zweites socat spricht TLS durch den Tunnel und prueft dabei das
# Zertifikat des Proxys samt Hostname bzw. IP-Adresse. Die CA-Datei wird immer
# ausdruecklich angegeben, damit das Verhalten nicht von der socat-Version abhaengt.
chain_tls_start() {   # chain_tls_start SOCAT
    local ca=$SYSTEM_CA_BUNDLE
    if [[ -n $CHAIN_CAFILE ]]; then
        ca=$STATE_DIR/chain-ca.pem          # Kopie, denn socat laeuft als nobody
        run install -m 0644 "$CHAIN_CAFILE" "$ca"
    elif [[ ! -r $ca ]]; then
        die "$ca fehlt. Paket ca-certificates installieren oder --chain-cafile angeben."
    fi
    info "Starte TLS: 127.0.0.1:$CHAIN_TLS_PORT -> HTTPS zu $CHAIN_HOST, Zertifikat wird gegen $ca geprueft"
    service_start "$CHAIN_TLS_UNIT" nobody "torify: TLS zum HTTPS-Proxy" \
        "$1" "TCP-LISTEN:$CHAIN_TLS_PORT,bind=127.0.0.1,reuseaddr,fork" \
        "OPENSSL:127.0.0.1:$CHAIN_TUNNEL_PORT,verify=1,commonname=$CHAIN_HOST,cafile=$ca"
    if (( ! DRY_RUN )); then
        wait_port tcp "$CHAIN_TLS_PORT" 10 \
            || die "socat (TLS) lauscht nicht auf Port $CHAIN_TLS_PORT (Log: journalctl -u $CHAIN_TLS_UNIT)."
    fi
}

# ------------------------------------------------------------------ Pakete
install_deps() {
    local pkgs=()
    command -v tor      >/dev/null 2>&1 || pkgs+=(tor)
    command -v redsocks >/dev/null 2>&1 || pkgs+=(redsocks)
    command -v iptables >/dev/null 2>&1 || pkgs+=(iptables)
    command -v ss       >/dev/null 2>&1 || pkgs+=(iproute2)
    if [[ -n $CHAIN_HOST ]] && ! command -v socat >/dev/null 2>&1; then pkgs+=(socat); fi
    if [[ $CHAIN_TYPE == https && -z $CHAIN_CAFILE && ! -e $SYSTEM_CA_BUNDLE ]]; then
        pkgs+=(ca-certificates)
    fi
    (( ${#pkgs[@]} )) || return 0

    if (( ! INSTALL )); then
        die "Fehlende Pakete: ${pkgs[*]} (automatische Installation ist mit --no-install aus)."
    fi
    command -v apt-get >/dev/null 2>&1 \
        || die "apt-get nicht gefunden. Das Script ist fuer Debian-basierte Systeme gedacht."

    info "Installiere fehlende Pakete: ${pkgs[*]}"
#    run apt-get update
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}"

    # Das Paket redsocks startet einen eigenen Dienst mit Standardkonfiguration,
    # den wir nicht brauchen. torify startet seine eigene Instanz.
    if [[ " ${pkgs[*]} " == *" redsocks "* ]] && has_systemd; then
        run systemctl --quiet disable --now redsocks.service || true
    fi
}

detect_tor_user() {
    if [[ -n $TOR_USER ]]; then return 0; fi
    local u
    for u in debian-tor tor _tor; do
        if id -u "$u" >/dev/null 2>&1; then TOR_USER=$u; return 0; fi
    done
    if (( DRY_RUN )); then TOR_USER=debian-tor; return 0; fi
    die "Systembenutzer von Tor (debian-tor) nicht gefunden. Ist das Paket tor installiert?"
}

# ------------------------------------------------------------------ Tor
tor_service() {
    if has_systemd; then run systemctl "$1" tor; else run service tor "$1"; fi
}

torrc_has_block() {
    grep -qxF "$MARK_BEGIN" "$TORRC" 2>/dev/null && grep -qxF "$MARK_END" "$TORRC"
}

torrc_remove_block() {
    if torrc_has_block; then
        run sed -i "/^# BEGIN torify - /,/^# END torify\$/d" "$TORRC"
    fi
}

torrc_block() {
    cat <<EOF
$MARK_BEGIN
DNSPort $TOR_SOCKS_ADDR:$TOR_DNS_PORT
AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion,.exit
VirtualAddrNetworkIPv4 $TOR_VIRT_NET
WarnUnsafeSocks 0
$MARK_END
EOF
}

tor_verify() {
    local out args=(-f "$TORRC" --verify-config)
    if [[ -f /usr/share/tor/tor-service-defaults-torrc ]]; then
        args=(--defaults-torrc /usr/share/tor/tor-service-defaults-torrc "${args[@]}")
    fi
    if ! out=$(tor "${args[@]}" 2>&1); then
        printf '%s\n' "$out" >&2
        return 1
    fi
}

tor_configure() {
    if [[ -f $TORRC ]]; then
        if grep -Eqi '^[[:space:]]*SafeSocks[[:space:]]+1' "$TORRC"; then
            die "In $TORRC ist 'SafeSocks 1' gesetzt. redsocks uebergibt Tor nur IP-Adressen, damit wuerde jede Verbindung abgelehnt."
        fi
        if grep -qxF "$MARK_BEGIN" "$TORRC" && ! torrc_has_block; then
            die "$TORRC enthaelt einen unvollstaendigen torify-Block. Bitte von Hand entfernen."
        fi
    elif (( ! DRY_RUN )); then
        die "$TORRC nicht gefunden."
    fi

    torrc_remove_block      # Reste eines abgebrochenen Laufs
    info "Ergaenze $TORRC um DNSPort $TOR_SOCKS_ADDR:$TOR_DNS_PORT"
    if (( DRY_RUN )); then
        torrc_block | write_file "$TORRC (anhaengen)"
    else
        # Datei muss mit Zeilenumbruch enden, sonst klebt der Block an der letzten Zeile
        if [[ -s $TORRC && -n $(tail -c1 "$TORRC") ]]; then echo >> "$TORRC"; fi
        torrc_block >> "$TORRC"
        tor_verify || die "Tor lehnt die Konfiguration ab (Ausgabe siehe oben)."
    fi

    info "Starte Tor neu ..."
    tor_service restart
    if (( ! DRY_RUN )); then
        wait_port tcp "$TOR_SOCKS_PORT" 30 \
            || die "Tor lauscht nicht auf $TOR_SOCKS_ADDR:$TOR_SOCKS_PORT. SocksPort in $TORRC pruefen."
        wait_port udp "$TOR_DNS_PORT" 30 \
            || die "Tor lauscht nicht auf $TOR_SOCKS_ADDR:$TOR_DNS_PORT (Port belegt?)."
    fi
}

# ------------------------------------------------------------------ redsocks
# Ziel des Haupteingangs: Tor direkt, oder in der Kette der socat-Tunnel zum Proxy.
redsocks_upstream() {
    if [[ -z $CHAIN_HOST ]]; then
        printf '    ip = %s;\n    port = %s;\n    type = socks5;\n' "$TOR_SOCKS_ADDR" "$TOR_SOCKS_PORT"
        return 0
    fi
    local type=socks5 port=$CHAIN_TUNNEL_PORT
    case $CHAIN_TYPE in
        http)  type=http-connect ;;
        https) type=http-connect; port=$CHAIN_TLS_PORT ;;     # TLS macht socat davor
    esac
    printf '    ip = 127.0.0.1;\n    port = %s;\n    type = %s;\n' "$port" "$type"
    if [[ -n $CHAIN_USER ]]; then
        printf '    login = "%s";\n    password = "%s";\n' "$CHAIN_USER" "$CHAIN_PASS"
    fi
}

redsocks_conf() {
    # redsocks verbindet sich nur mit 127.0.0.1, braucht also keine Rechte.
    # log_info bleibt aus, sonst landet jedes Verbindungsziel im Syslog.
    local user=nobody
    id -u redsocks >/dev/null 2>&1 && user=redsocks
    cat <<EOF
base {
    log_debug = off;
    log_info = off;
    log = "syslog:daemon";
    daemon = off;
    user = $user;
    group = $(id -gn "$user" 2>/dev/null || echo nogroup);
    redirector = iptables;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = $REDSOCKS_PORT;
$(redsocks_upstream)
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = $ONION_PORT;
    ip = $TOR_SOCKS_ADDR;
    port = $TOR_SOCKS_PORT;
    type = socks5;
}
EOF
}

redsocks_start() {
    local bin p target conf=$STATE_DIR/redsocks.conf
    bin=$(command -v redsocks || echo /usr/sbin/redsocks)

    if (( DRY_RUN )); then
        redsocks_conf | sed -E 's/^( *password = ).*/\1"********";/' | write_file "$conf"
    else
        redsocks_conf | write_file "$conf" geheim     # kann ein Passwort enthalten
        "$bin" -t -c "$conf" >/dev/null || die "redsocks lehnt die Konfiguration $conf ab."
    fi

    target="SOCKS5 $TOR_SOCKS_ADDR:$TOR_SOCKS_PORT (Tor)"
    [[ -n $CHAIN_HOST ]] && target="Tunnel :$CHAIN_TUNNEL_PORT -> Tor -> $(chain_desc)"
    info "Starte redsocks: 127.0.0.1:$REDSOCKS_PORT -> $target"
    service_start "$REDSOCKS_UNIT" root "torify: redsocks -> Tor" "$bin" -c "$conf"

    if (( ! DRY_RUN )); then
        for p in "$REDSOCKS_PORT" "$ONION_PORT"; do
            wait_port tcp "$p" 10 \
                || die "redsocks lauscht nicht auf Port $p (Log: journalctl -t redsocks)."
        done
    fi
}

# ------------------------------------------------------------------ Firewall
# Protokolliert (gedrosselt) und verwirft alles, was bis hier nicht erlaubt wurde.
reject_rules() {  # reject_rules ipt4|ipt6 ICMP-TYP
    "$1" -A "$CHAIN" -m limit --limit 6/min --limit-burst 10 \
        -j LOG --log-prefix "torify-blocked: " --log-uid
    "$1" -A "$CHAIN" -p tcp -j REJECT --reject-with tcp-reset
    "$1" -A "$CHAIN" -j REJECT --reject-with "$2"
}

firewall_up() {
    local net
    firewall_down       # Reste eines frueheren Laufs entfernen

    info "Setze iptables-Regeln (IPv4) ..."
    # nat: lokal erzeugte TCP-Verbindungen und DNS-Anfragen umleiten. Sonstiges UDP
    # wird hier nicht angefasst und geht direkt hinaus.
    ipt4 -t nat -N "$CHAIN"
    ipt4 -t nat -A "$CHAIN" -m owner --uid-owner "$TOR_USER" -j RETURN
    ipt4 -t nat -A "$CHAIN" -d 127.0.0.0/8 -j RETURN
    ipt4 -t nat -A "$CHAIN" -m addrtype --dst-type LOCAL -j RETURN
    if (( DIRECT_DNS )); then
        ipt4 -t nat -A "$CHAIN" -p tcp --dport 53 -j RETURN       # auch DNS ueber TCP direkt
    else
        # DNS ueber Tor, auch mit --allow-lan. Deshalb vor der LAN-Ausnahme.
        ipt4 -t nat -A "$CHAIN" -p udp --dport 53 -j REDIRECT --to-ports "$TOR_DNS_PORT"
        ipt4 -t nat -A "$CHAIN" -p tcp --dport 53 --syn -j REDIRECT --to-ports "$REDSOCKS_PORT"
    fi
    # virtuelle Adressen, auf die Tor .onion-Namen abbildet (liegen in 10.0.0.0/8)
    ipt4 -t nat -A "$CHAIN" -d "$TOR_VIRT_NET" -p tcp --syn -j REDIRECT --to-ports "$ONION_PORT"
    if (( ALLOW_LAN )); then
        for net in "${LAN_V4[@]}"; do ipt4 -t nat -A "$CHAIN" -d "$net" -j RETURN; done
    fi
    ipt4 -t nat -A "$CHAIN" -p tcp --syn -j REDIRECT --to-ports "$REDSOCKS_PORT"
    ipt4 -t nat -I OUTPUT 1 -j "$CHAIN"

    # filter: TCP nur ueber Tor, UDP direkt, alles andere verwerfen (Kill-Switch).
    ipt4 -N "$CHAIN"
    ipt4 -A "$CHAIN" -m conntrack --ctstate INVALID -j DROP
    ipt4 -A "$CHAIN" -o lo -j ACCEPT
    # Umgeleitete Pakete haben hier schon das Ziel 127.0.0.1, "-o" zeigt aber noch
    # das urspruengliche Interface (z.B. eth0). Ziele in 127/8 verlassen den Rechner nie.
    ipt4 -A "$CHAIN" -d 127.0.0.0/8 -j ACCEPT
    ipt4 -A "$CHAIN" -m owner --uid-owner "$TOR_USER" -j ACCEPT
    # nur Antworten auf eingehende Verbindungen, keine schon offenen ausgehenden
    ipt4 -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT
    # UDP geht direkt hinaus, DHCP eingeschlossen. DNS wurde oben schon auf Tor
    # umgeleitet und hat hier das Ziel 127.0.0.1, ausser mit --direct-dns.
    ipt4 -A "$CHAIN" -p udp -j ACCEPT
    if (( DIRECT_DNS )); then ipt4 -A "$CHAIN" -p tcp --dport 53 -j ACCEPT; fi
    if (( ALLOW_LAN )); then
        for net in "${LAN_V4[@]}"; do ipt4 -A "$CHAIN" -d "$net" -j ACCEPT; done
    fi
    reject_rules ipt4 icmp-port-unreachable
    ipt4 -I OUTPUT 1 -j "$CHAIN"

    firewall6_up
}

# TCP ueber IPv6 kann redsocks nicht umleiten, es wird blockiert. Programme weichen
# dann auf IPv4 aus, das ueber Tor laeuft. UDP geht auch ueber IPv6 direkt hinaus.
firewall6_up() {
    local net t
    if [[ ! -e /proc/net/if_inet6 ]]; then
        info "IPv6 ist im Kernel deaktiviert, keine IPv6-Regeln noetig."
        return 0
    fi
    info "Setze ip6tables-Regeln (TCP ueber IPv6 wird blockiert, UDP geht direkt) ..."
    ipt6 -N "$CHAIN"
    ipt6 -A "$CHAIN" -m conntrack --ctstate INVALID -j DROP
    ipt6 -A "$CHAIN" -o lo -j ACCEPT
    ipt6 -A "$CHAIN" -m owner --uid-owner "$TOR_USER" -j ACCEPT
    ipt6 -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT
    # Nachbar- und Router-Erkennung, ohne sie erreicht UDP den Router nicht.
    # Diese Pakete verlassen das lokale Netzsegment nicht.
    for t in router-solicitation neighbour-solicitation neighbour-advertisement; do
        ipt6 -A "$CHAIN" -p ipv6-icmp --icmpv6-type "$t" -j ACCEPT
    done
    if (( DIRECT_DNS )); then
        ipt6 -A "$CHAIN" -p tcp --dport 53 -j ACCEPT
    else
        # DNS ueber IPv6 wuerde Tor umgehen. Der Resolver weicht auf IPv4 aus,
        # und das wird auf Tor umgeleitet.
        ipt6 -A "$CHAIN" -p udp --dport 53 -j REJECT --reject-with icmp6-adm-prohibited
        ipt6 -A "$CHAIN" -p tcp --dport 53 -j REJECT --reject-with tcp-reset
    fi
    ipt6 -A "$CHAIN" -p udp -j ACCEPT
    if (( ALLOW_LAN )); then
        for net in "${LAN_V6[@]}"; do ipt6 -A "$CHAIN" -d "$net" -j ACCEPT; done
    fi
    reject_rules ipt6 icmp6-adm-prohibited
    ipt6 -I OUTPUT 1 -j "$CHAIN"
}

firewall_down() {
    if (( DRY_RUN )); then
        echo "[dry-run] entferne Kette $CHAIN aus nat/filter (IPv4) und filter (IPv6)"
        return 0
    fi
    local t
    for t in nat filter; do
        while iptables -w -t "$t" -D OUTPUT -j "$CHAIN" 2>/dev/null; do :; done
        iptables -w -t "$t" -F "$CHAIN" 2>/dev/null || true
        iptables -w -t "$t" -X "$CHAIN" 2>/dev/null || true
    done
    if command -v ip6tables >/dev/null 2>&1; then
        while ip6tables -w -D OUTPUT -j "$CHAIN" 2>/dev/null; do :; done
        ip6tables -w -F "$CHAIN" 2>/dev/null || true
        ip6tables -w -X "$CHAIN" 2>/dev/null || true
    fi
}

# ------------------------------------------------------------------ Pruefung
# probe SEKUNDEN - fragt check.torproject.org ab, setzt PROBE_IP und PROBE_TOR (1/0)
probe() {
    local out
    out=$(fetch "$CHECK_URL" "$1" 2>/dev/null) || return 1
    PROBE_IP=$(exit_ip "$out")
    [[ -n $PROBE_IP ]] || return 1
    PROBE_TOR=0
    if [[ $out == *'"IsTor":true'* ]]; then PROBE_TOR=1; fi
}

# report_probe KETTE - bewertet das Ergebnis von probe. KETTE leer = reiner Tor-Modus.
report_probe() {
    if [[ -z $1 ]]; then
        if (( PROBE_TOR )); then ok "Verkehr laeuft ueber Tor, Exit-IP: $PROBE_IP"; return 0; fi
        bad "Verkehr laeuft NICHT ueber Tor, sichtbare IP: $PROBE_IP"
        return 1
    fi
    if (( PROBE_TOR )); then
        bad "Verkehr kommt direkt aus einem Tor-Exit ($PROBE_IP), der Proxy $1 wird nicht genutzt"
        return 1
    fi
    if [[ $PROBE_IP == "${1%:*}" ]]; then
        ok "Ziele sehen die Adresse des externen Proxys: $PROBE_IP"
    else
        ok "Ziele sehen $PROBE_IP. Das ist kein Tor-Exit, also die Ausgangsadresse des Proxys $1."
    fi
}

wait_for_connection() {
    if (( DRY_RUN )); then return 0; fi
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        info "Verbindung pruefen mit: $0 check"
        return 0
    fi
    info "Warte auf die erste Verbindung (hoechstens 90 s) ..."
    local deadline=$((SECONDS + 90))
    while (( SECONDS < deadline )); do
        if probe 15; then
            report_probe "${CHAIN_HOST:+$CHAIN_HOST:$CHAIN_PORT}" || true
            return 0
        fi
        sleep 3
    done
    warn "Noch keine Verbindung moeglich. Spaeter pruefen mit: $0 check"
}

# ------------------------------------------------------------------ Ablauf
teardown() {
    firewall_down
    service_stop "$REDSOCKS_UNIT"
    service_stop "$CHAIN_TLS_UNIT"
    service_stop "$CHAIN_UNIT"
    if torrc_has_block; then
        torrc_remove_block || warn "Konnte den torify-Block nicht aus $TORRC entfernen."
        if [[ $TOR_WAS_ACTIVE == 1 ]]; then
            info "Starte Tor mit der urspruenglichen Konfiguration neu ..."
            tor_service restart || warn "Neustart von Tor fehlgeschlagen."
        else
            info "Stoppe Tor (lief vor 'start' noch nicht) ..."
            tor_service stop || warn "Stoppen von Tor fehlgeschlagen."
        fi
    fi
    run rm -f "$STATE_DIR/state" "$STATE_DIR/redsocks.conf" "$STATE_DIR/chain-ca.pem" \
        "$STATE_DIR/$REDSOCKS_UNIT.pid" "$STATE_DIR/$CHAIN_UNIT.pid" "$STATE_DIR/$CHAIN_TLS_UNIT.pid"
    run rmdir "$STATE_DIR" 2>/dev/null || true
}

on_exit() {
    local rc=$?
    if (( STARTING )); then
        STARTING=0
        set +e
        err "Start fehlgeschlagen, mache alle Aenderungen rueckgaengig."
        teardown
    fi
    exit "$rc"
}

cmd_start() {
    local p ports=("$REDSOCKS_PORT" "$ONION_PORT")
    require_root
    if [[ -f $STATE_DIR/state ]]; then
        die "torify ist bereits aktiv. Neu starten mit: sudo $0 restart"
    fi
    [[ -f /etc/debian_version ]] || warn "Kein Debian-basiertes System erkannt."

    TOR_WAS_ACTIVE=0
    if port_listening tcp "$TOR_SOCKS_PORT"; then TOR_WAS_ACTIVE=1; fi
    install_deps            # braucht noch das normale Netz
    detect_tor_user
    if [[ -n $CHAIN_HOST ]]; then ports+=("$CHAIN_TUNNEL_PORT"); fi
    if [[ $CHAIN_TYPE == https ]]; then ports+=("$CHAIN_TLS_PORT"); fi
    for p in "${ports[@]}"; do
        if port_listening tcp "$p"; then
            die "Port $p ist schon belegt. Aendern ueber REDSOCKS_PORT, ONION_PORT, CHAIN_TUNNEL_PORT oder CHAIN_TLS_PORT."
        fi
    done

    STARTING=1
    run install -d -m 0755 "$STATE_DIR"
    save_state
    tor_configure
    chain_start
    redsocks_start
    firewall_up
    STARTING=0

    local dns="DNS ueber Tor"
    if (( DIRECT_DNS )); then dns="DNS direkt"; fi
    if [[ -n $CHAIN_HOST ]]; then
        info "torify ist aktiv: TCP laeuft ueber Tor und dann ueber $(chain_desc). $dns, UDP direkt, alles andere wird blockiert."
    else
        info "torify ist aktiv: TCP laeuft ueber Tor. $dns, UDP direkt, alles andere wird blockiert."
    fi
    warn "UDP laeuft direkt und zeigt die echte IP-Adresse, z.B. bei QUIC (HTTP/3), WebRTC und VoIP."
    if (( ALLOW_LAN )); then info "Das lokale Netz ist direkt erreichbar (--allow-lan)."; fi
    wait_for_connection
}

cmd_stop() {
    require_root
    if [[ -f $STATE_DIR/state ]]; then
        TOR_WAS_ACTIVE=$(state_get TOR_WAS_ACTIVE)
        TOR_WAS_ACTIVE=${TOR_WAS_ACTIVE:-1}
    else
        info "torify war nicht aktiv, entferne eventuelle Reste."
    fi
    info "Entferne Firewall-Regeln. Der Verkehr laeuft ab jetzt wieder direkt, NICHT ueber Tor."
    teardown
    info "torify ist deaktiviert."
}

check_port() {  # check_port tcp|udp PORT NAME
    if port_listening "$1" "$2"; then
        ok "$3 lauscht auf 127.0.0.1:$2/$1"
    else
        bad "$3 lauscht nicht auf Port $2/$1"
        return 1
    fi
}

cmd_status() {
    local rc=0 lan=nein dns='ueber Tor' chain=''
    if [[ -f $STATE_DIR/state ]]; then
        [[ $(state_get ALLOW_LAN) == 1 ]] && lan=ja
        [[ $(state_get DIRECT_DNS) == 1 ]] && dns=direkt
        ok "torify aktiv seit $(state_get STARTED), LAN direkt erreichbar: $lan"
        ok "DNS: $dns, UDP: direkt (nicht ueber Tor)"
        chain=$(state_get CHAIN)
        if [[ -n $chain ]]; then
            ok "Proxy-Kette: Tor -> $(state_get CHAIN_TYPE) $chain, Anmeldung: $(state_get CHAIN_AUTH)"
        fi
    else
        bad "torify ist nicht aktiv"
        rc=3
    fi
    if (( EUID == 0 )); then
        if iptables -w -t nat -C OUTPUT -j "$CHAIN" 2>/dev/null \
            && iptables -w -C OUTPUT -j "$CHAIN" 2>/dev/null; then
            ok "iptables-Regeln (IPv4) gesetzt"
        else
            bad "iptables-Regeln (IPv4) fehlen"; rc=3
        fi
        if [[ -e /proc/net/if_inet6 ]]; then
            if ip6tables -w -C OUTPUT -j "$CHAIN" 2>/dev/null; then
                ok "ip6tables-Regeln gesetzt (TCP ueber IPv6 blockiert)"
            else
                bad "ip6tables-Regeln fehlen"; rc=3
            fi
        fi
    else
        warn "Firewall-Regeln lassen sich nur als root pruefen (sudo $0 status)."
    fi
    check_port tcp "$TOR_SOCKS_PORT" "Tor SOCKS5"            || rc=3
    check_port udp "$TOR_DNS_PORT"   "Tor DNSPort"           || rc=3
    check_port tcp "$REDSOCKS_PORT"  "redsocks"              || rc=3
    check_port tcp "$ONION_PORT"     "redsocks fuer .onion"  || rc=3
    if [[ -n $chain ]]; then
        check_port tcp "$CHAIN_TUNNEL_PORT" "Tunnel zum Proxy (socat)" || rc=3
        if [[ $(state_get CHAIN_TYPE) == https ]]; then
            check_port tcp "$CHAIN_TLS_PORT" "TLS zum Proxy (socat)" || rc=3
        fi
    fi
    return "$rc"
}

cmd_check() {
    local out rc=0 chain
    chain=$(state_get CHAIN)
    info "Pruefe Verbindung ueber $CHECK_URL ..."
    if probe 30; then
        report_probe "$chain" || rc=1
    else
        bad "check.torproject.org nicht erreichbar (Tor oder Proxy noch nicht bereit, oder curl/wget fehlt)"
        rc=1
    fi

    # In der Kette zusaetzlich Tor allein pruefen, direkt ueber den SOCKS-Port.
    if [[ -n $chain ]] && command -v curl >/dev/null 2>&1; then
        out=$(curl -fsS --max-time 30 --socks5-hostname "$TOR_SOCKS_ADDR:$TOR_SOCKS_PORT" \
            "$CHECK_URL" 2>/dev/null) || true
        if [[ $out == *'"IsTor":true'* ]]; then
            ok "Tor selbst funktioniert, Exit-IP: $(exit_ip "$out")"
        else
            bad "Tor ist ueber $TOR_SOCKS_ADDR:$TOR_SOCKS_PORT nicht erreichbar"; rc=1
        fi
    fi

    # UDP soll direkt hinausgehen: ein Paket an eine Dokumentationsadresse (RFC 5737).
    if (printf x >/dev/udp/192.0.2.1/9) 2>/dev/null; then
        ok "UDP geht direkt hinaus (nicht ueber Tor)"
    else
        warn "UDP laesst sich nicht senden. Blockiert eine andere Firewall, oder fehlt die Route?"
    fi
    # TCP ueber IPv6 wuerde Tor umgehen und muss sofort abgewiesen werden (RFC 3849).
    if [[ -e /proc/net/if_inet6 ]]; then
        local v6=0
        timeout 5 bash -c 'exec 3<>/dev/tcp/2001:db8::1/9' 2>/dev/null || v6=$?
        case $v6 in
            0|124) bad "TCP ueber IPv6 wird NICHT blockiert"; rc=1 ;;
            *)     ok "TCP ueber IPv6 wird blockiert" ;;
        esac
    fi
    return "$rc"
}

usage() {
    cat <<EOF
Nutzung: sudo $0 {start|stop|restart|status|check} [Optionen]

  start     TCP und DNS durch Tor leiten, UDP direkt durchlassen
            (installiert bei Bedarf: tor, redsocks, iptables, socat)
  stop      alle Aenderungen rueckgaengig machen
  restart   stop und danach start
  status    zeigen, ob alle Bestandteile laufen
  check     ueber check.torproject.org pruefen, wo der Verkehr herauskommt

Optionen:
  --allow-lan            lokales Netz direkt erlauben (DNS bleibt bei Tor)
  --direct-dns           DNS direkt statt ueber Tor (verraet die Hostnamen)
  --no-install           keine Pakete installieren
  --dry-run              nur anzeigen, was ausgefuehrt wuerde
  -h, --help             diese Hilfe

Proxy-Kette Tor -> externer Proxy:
  --chain HOST:PORT      externer Proxy (IPv4-Adresse oder Hostname)
  --chain-type TYP       socks5 (Standard), http oder https (TLS zum Proxy)
  --chain-user NAME      Benutzername (optional)
  --chain-pass PASSWORT  Passwort (optional, sonst Abfrage oder TORIFY_CHAIN_PASS)
  --chain-cafile DATEI   nur https: eigene CA bzw. Proxy-Zertifikat (PEM)

Beispiel:
  sudo $0 start --chain 203.0.113.5:1080 --chain-user alice
  sudo $0 start --chain proxy.example.org:443 --chain-type https --chain-user alice

Umgebungsvariablen: TOR_SOCKS_PORT ($TOR_SOCKS_PORT), TOR_DNS_PORT ($TOR_DNS_PORT),
  REDSOCKS_PORT ($REDSOCKS_PORT), ONION_PORT ($ONION_PORT), CHAIN_TUNNEL_PORT ($CHAIN_TUNNEL_PORT),
  CHAIN_TLS_PORT ($CHAIN_TLS_PORT),
  TOR_VIRT_NET ($TOR_VIRT_NET), TORRC ($TORRC), TORIFY_CHAIN_PASS
EOF
}

main() {
    local cmd="" chain_spec="" p dup
    while (( $# )); do
        case $1 in
            --*=*) set -- "${1%%=*}" "${1#*=}" "${@:2}"; continue ;;   # --opt=wert
        esac
        case $1 in
            start|stop|restart|status|check) cmd=$1 ;;
            --allow-lan)    ALLOW_LAN=1 ;;
            --direct-dns)   DIRECT_DNS=1 ;;
            --no-install)   INSTALL=0 ;;
            --dry-run|-n)   DRY_RUN=1 ;;
            --chain|--chain-type|--chain-user|--chain-pass|--chain-cafile)
                if (( $# < 2 )); then die "$1 braucht einen Wert."; fi
                case $1 in
                    --chain)      [[ -n $2 ]] || die "--chain braucht HOST:PORT."; chain_spec=$2 ;;
                    --chain-type) CHAIN_TYPE=$2; CHAIN_OPTS=1 ;;
                    --chain-user) CHAIN_USER=$2; CHAIN_OPTS=1 ;;
                    --chain-pass) CHAIN_PASS=$2; CHAIN_PASS_SET=1; CHAIN_PASS_FLAG=1; CHAIN_OPTS=1 ;;
                    --chain-cafile) CHAIN_CAFILE=$2; CHAIN_OPTS=1 ;;
                esac
                shift ;;
            -h|--help|help) usage; return 0 ;;
            *) err "Unbekanntes Argument: $1"; usage >&2; return 2 ;;
        esac
        shift
    done
    if [[ -z $cmd ]]; then usage >&2; return 2; fi

    for p in "$TOR_SOCKS_PORT" "$TOR_DNS_PORT" "$REDSOCKS_PORT" "$ONION_PORT" "$CHAIN_TUNNEL_PORT" \
        "$CHAIN_TLS_PORT"; do
        valid_port "$p" || die "Ungueltiger Port: $p"
    done
    dup=$(printf '%s\n' "$TOR_SOCKS_PORT" "$TOR_DNS_PORT" "$REDSOCKS_PORT" "$ONION_PORT" \
        "$CHAIN_TUNNEL_PORT" "$CHAIN_TLS_PORT" | sort | uniq -d)
    [[ -z $dup ]] || die "Port $dup ist mehrfach vergeben."

    if [[ $cmd == start || $cmd == restart ]]; then
        setup_chain "$chain_spec"
    fi

    trap on_exit EXIT
    trap 'exit 130' INT TERM

    case $cmd in
        start)   cmd_start ;;
        stop)    cmd_stop ;;
        restart) cmd_stop; cmd_start ;;
        status)  cmd_status ;;
        check)   cmd_check ;;
    esac
}

# Nur ausfuehren, wenn direkt aufgerufen (nicht beim Einbinden per "source").
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
