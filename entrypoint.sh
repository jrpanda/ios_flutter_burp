#!/bin/bash
# OpenVPN server + transparent redirection to Burp, which runs on the HOST.
#
# The container acts as "tun0 + iptables": the client connects over the VPN and
# the DNAT sends its traffic to Burp without configuring a proxy on the device.
# That is what you need for apps that ignore the system proxy (Flutter/dart:io,
# among others). Since Burp runs on the same host, there is no socat and no
# double NAT.
#
# Based on https://blog.nviso.eu/2020/06/12/intercepting-flutter-traffic-on-ios/
set -euo pipefail

log()  { printf '\033[1;36m[ovpn-burp]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ovpn-burp]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[ovpn-burp] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
trap 'rc=$?; printf "\033[1;31m[ovpn-burp] ERROR:\033[0m failed (rc=%s) at line %s -> %s\n" "$rc" "$LINENO" "$BASH_COMMAND" >&2' ERR

# ---------------------------------------------------------------- config (env)
: "${VPN_NET:=10.8.0.0}"
: "${VPN_MASK:=255.255.255.0}"
: "${VPN_CIDR:=10.8.0.0/24}"
: "${VPN_PORT:=1194}"
: "${VPN_PROTO:=udp}"
: "${VPN_DNS:=1.1.1.1,1.0.0.1}"
: "${CLIENT_NAME:=iphone}"
: "${BURP_PORT:=8080}"
: "${BURP_HOST:=}"              # empty => the container gateway (= the host)
: "${INTERCEPT_PORTS:=80,443}"
: "${BLOCK_QUIC:=1}"
: "${MTU:=1400}"
: "${MSSFIX:=1360}"
: "${DATA:=/data}"
# Comma-separated domains that public DNS can't resolve (e.g. internal .loc) and
# that reach Burp's upstream proxy. dnsmasq answers them with DUMMY_IP so the app
# fires the SYN and the DNAT catches it; Burp forwards by Host/SNI, so the IP is
# irrelevant. Empty = disabled (classic behaviour: push VPN_DNS directly).
: "${INTERNAL_DOMAINS:=}"
: "${DUMMY_IP:=198.51.100.1}"  # any VPN-routed IP; only needs to trigger the DNAT

VPN_GW="${VPN_NET%.*}.1"        # server tun0 address (= local DNS when enabled)
PKI="$DATA/pki"
TC_KEY="$DATA/tc.key"
CONF="$DATA/server.conf"
OUT="$DATA/clients"
EASYRSA_DIR="$DATA/easy-rsa"

# ------------------------------------------------------------------------ PKI
init_pki() {
    log "generating PKI (once only, persisted in ./data/pki)"
    rm -rf "$EASYRSA_DIR"
    cp -r /usr/share/easy-rsa "$EASYRSA_DIR"
    cd "$EASYRSA_DIR"
    # NOTE: EASYRSA_REQ_CN only applies to build-ca; build-server-full and
    # build-client-full reject it ("does not support setting an external
    # commonName"), so it is NOT exported globally.
    export EASYRSA_BATCH=1 EASYRSA_PKI="$PKI" EASYRSA_ALGO=ec \
           EASYRSA_CURVE=prime256v1 EASYRSA_CERT_EXPIRE=3650 \
           EASYRSA_CA_EXPIRE=3650
    log "  $(./easyrsa --version 2>/dev/null | grep -i version | head -1) / $(openvpn --version 2>/dev/null | head -1 | cut -d\  -f1-2)"
    log "  step 1/5 init-pki";            ./easyrsa --batch init-pki
    log "  step 2/5 build-ca";            EASYRSA_REQ_CN="ovpn-burp-ca" ./easyrsa --batch build-ca nopass
    log "  step 3/5 server certificate";  ./easyrsa --batch build-server-full server nopass
    log "  step 4/5 client certificate";  ./easyrsa --batch build-client-full "$CLIENT_NAME" nopass
    log "  step 5/5 tls-crypt key"
    # 2.6 deprecated `--genkey secret`; try both forms
    openvpn --genkey secret "$TC_KEY" || openvpn --genkey tls-crypt "$TC_KEY"
    [[ -s "$TC_KEY" ]] || die "could not generate $TC_KEY"
    log "PKI ready"
}

new_client() {
    local name="$1"
    [[ -f "$PKI/issued/$name.crt" ]] && { warn "client '$name' already exists"; return 0; }
    cd "$EASYRSA_DIR"
    EASYRSA_BATCH=1 EASYRSA_PKI="$PKI" EASYRSA_CERT_EXPIRE=3650 \
        ./easyrsa build-client-full "$name" nopass
}

pem() { sed -n '/BEGIN/,/END/p' "$1"; }

write_ovpn() {
    local name="$1"
    local out="$OUT/$name.ovpn"
    mkdir -p "$OUT"
    {
        cat <<EOF
client
dev tun
proto $VPN_PROTO
remote $REMOTE_HOST $VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
tun-mtu $MTU
mssfix $MSSFIX
verb 3
EOF
        echo "<ca>";        pem "$PKI/ca.crt";                echo "</ca>"
        echo "<cert>";      pem "$PKI/issued/$name.crt";      echo "</cert>"
        echo "<key>";       pem "$PKI/private/$name.key";     echo "</key>"
        echo "<tls-crypt>"; pem "$TC_KEY";                    echo "</tls-crypt>"
    } > "$out"
    chmod 0644 "$out"
    log "client profile -> ./data/clients/$name.ovpn  (remote $REMOTE_HOST:$VPN_PORT/$VPN_PROTO)"
}

write_server_conf() {
    cat > "$CONF" <<EOF
dev tun
proto $VPN_PROTO
port $VPN_PORT
topology subnet
server $VPN_NET $VPN_MASK
push "redirect-gateway def1 bypass-dhcp"
$(if [[ -n "$INTERNAL_DOMAINS" ]]; then
      echo "push \"dhcp-option DNS $VPN_GW\""
  else
      for d in ${VPN_DNS//,/ }; do echo "push \"dhcp-option DNS $d\""; done
  fi)
ca $PKI/ca.crt
cert $PKI/issued/server.crt
key $PKI/private/server.key
dh none
ecdh-curve prime256v1
tls-crypt $TC_KEY
auth SHA256
data-ciphers AES-256-GCM
tun-mtu $MTU
mssfix $MSSFIX
keepalive 10 60
duplicate-cn
persist-key
persist-tun
status $DATA/status.log
verb 3
EOF
    [[ "$VPN_PROTO" == "udp" ]] && echo "explicit-exit-notify 1" >> "$CONF"
}

# Local resolver on tun0: answers INTERNAL_DOMAINS with DUMMY_IP and forwards the
# rest to VPN_DNS. bind-dynamic lets it attach to tun0 once OpenVPN creates it.
write_dnsmasq_conf() {
    {
        echo "interface=tun0"
        echo "bind-dynamic"
        echo "no-resolv"
        echo "no-hosts"
        echo "log-queries"
        local d
        for d in ${INTERNAL_DOMAINS//,/ }; do echo "address=/$d/$DUMMY_IP"; done
        for d in ${VPN_DNS//,/ };         do echo "server=$d";             done
    } > "$DATA/dnsmasq.conf"
}

# -------------------------------------------------------------------- iptables
setup_nat() {
    iptables -t nat -F
    iptables -F FORWARD

    # 1) Transparent redirection to Burp (on the host).
    local p
    for p in ${INTERCEPT_PORTS//,/ }; do
        iptables -t nat -A PREROUTING -i tun0 -p tcp --dport "$p" \
                 -j DNAT --to-destination "$BURP_HOST:$BURP_PORT"
        log "intercepting tcp/$p -> $BURP_HOST:$BURP_PORT"
    done

    # 2) Internet access for everything else (DNS, other ports), and so the
    #    host knows how to return the DNAT-ed packets.
    iptables -t nat -A POSTROUTING -s "$VPN_CIDR" -j MASQUERADE

    # 3) QUIC out of the way: otherwise the app can bypass the proxy over udp/443.
    if [[ "$BLOCK_QUIC" == "1" ]]; then
        iptables -A FORWARD -i tun0 -p udp --dport 443 \
                 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null \
            || iptables -A FORWARD -i tun0 -p udp --dport 443 -j DROP
        log "udp/443 (QUIC) blocked -> forces fallback to TLS over TCP"
    fi
}

# ------------------------------------------------------------------------ main
case "${1:-run}" in
    client)
        [[ -n "${2:-}" ]] || die "usage: entrypoint.sh client <name>"
        [[ -f "$PKI/ca.crt" ]] || die "no PKI yet; start the container first"
        : "${REMOTE_HOST:?REMOTE_HOST is required}"
        new_client "$2"; write_ovpn "$2"
        exit 0
        ;;
    nat)
        # re-apply only the rules, without restarting OpenVPN (./vpnburp intercept on)
        GATEWAY="$(ip route show default | awk '{print $3; exit}')"
        [[ -n "$BURP_HOST" ]] || BURP_HOST="$GATEWAY"
        setup_nat
        exit 0
        ;;
    run) ;;
    *) exec "$@" ;;
esac

: "${REMOTE_HOST:?REMOTE_HOST is required (the host LAN IP, the one the device sees)}"
[[ -e /dev/net/tun ]] || die "/dev/net/tun is not available inside the container"

UPLINK="$(ip route show default | awk '{print $5; exit}')"
GATEWAY="$(ip route show default | awk '{print $3; exit}')"
[[ -n "$GATEWAY" ]] || die "cannot find the container gateway"
[[ -n "$BURP_HOST" ]] || BURP_HOST="$GATEWAY"
log "uplink=$UPLINK  host(gateway)=$GATEWAY  burp=$BURP_HOST:$BURP_PORT"

[[ -f "$PKI/ca.crt" && -f "$TC_KEY" ]] || init_pki
[[ -f "$PKI/issued/$CLIENT_NAME.crt" ]] || new_client "$CLIENT_NAME"

write_server_conf
write_ovpn "$CLIENT_NAME"      # always regenerated: picks up REMOTE_HOST changes
setup_nat

# Early warning if Burp is not listening where we expect it.
if ! (exec 3<>"/dev/tcp/$BURP_HOST/$BURP_PORT") 2>/dev/null; then
    warn "nothing is listening on $BURP_HOST:$BURP_PORT"
    warn "in Burp, open a Proxy listener on $BURP_HOST:$BURP_PORT with 'Support invisible proxying' ENABLED"
fi

if [[ -n "$INTERNAL_DOMAINS" ]]; then
    write_dnsmasq_conf
    dnsmasq --conf-file="$DATA/dnsmasq.conf"
    log "dnsmasq up on $VPN_GW:53 -> internal [$INTERNAL_DOMAINS] => $DUMMY_IP, rest via $VPN_DNS"
fi

log "starting OpenVPN on $VPN_PROTO/$VPN_PORT (network $VPN_CIDR)"
exec openvpn --config "$CONF"
