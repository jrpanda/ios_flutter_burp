# ios_flutter_burp

dockerized version of [Intercepting Flutter traffic on iOS](https://blog.nviso.eu/2020/06/12/intercepting-flutter-traffic-on-ios/) (the original post uses kali)

thx claudio

## installation

```bash
git clone https://github.com/jrpanda/ios_flutter_burp.git
cd ios_flutter_burp
./vpnburp up
./vpnburp serve
```

on your iphone, download and install the .ovpn file

easy way: open with [OpenVPN](https://apps.apple.com/app/openvpn-connect/id590379981)

## usage

```bash
./vpnburp <command>

  up               build and start the VPN, regenerate the .ovpn with the current LAN IP
  down             stop and remove the container (the PKI is kept in ./data)
  check            diagnostics: tun, Burp reachable, tun0, IP to connect to
  status           container state and connected VPN clients
  logs             live OpenVPN logs
  serve [port]     serve the .ovpn over HTTP (+QR) to download it from the device
  client <name>    generate an extra .ovpn profile
  rules            show the active iptables rules inside the container
  intercept on|off toggle only the DNAT to Burp, without touching the VPN
  sniff [dns|syn]  what the client resolves and which connections it opens on tun0
  shell            shell inside the container
```
