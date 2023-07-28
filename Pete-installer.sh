#!/bin/bash
# Script created by Bonveio
# Do not resell and redistribute this script
# Project by BonvScripts <https://github.com/Bonveio/BonvScripts>

# Decrypt pa more
# %d/%m/:%S

clear
cd ~
export DEBIAN_FRONTEND=noninteractive

function ip_address(){
  local IP="$( ip addr | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -Ev "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$(curl -4s ipv4.icanhazip.com)"
  [ -z "${IP}" ] && IP="$(curl -4s ipinfo.io/ip)"
  [ ! -z "${IP}" ] && echo "${IP}" || echo '0.0.0.0'
}

function BONV-MSG(){
 printf "%b\n" "\e[38;5;192m (｡◕‿◕｡)\e[0m\e[38;5;121m Bonveio Debian VPS Installer\e[0m"
 echo -e " v20201227 stable"
 echo -e ""
 echo -e " Updates: https://t.me/BonvScripts"
 echo -e ""
}

function InsEssentials(){
apt update 2>/dev/null
apt upgrade -y 2>/dev/null
printf "%b\n" "\e[32m[\e[0mInfo\e[32m]\e[0m\e[97m Please wait..\e[0m"
apt autoremove --fix-missing -y > /dev/null 2>&1
apt remove --purge apache* ufw -y > /dev/null 2>&1
timedatectl set-timezone Asia/Manila > /dev/null 2>&1

apt install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt lsof -y 2>/dev/null

if [[ "$(command -v firewall-cmd)" ]]; then
 apt remove --purge firewalld -y
 apt autoremove -y -f
fi

apt install iptables-persistent -y -f
systemctl restart netfilter-persistent &>/dev/null
systemctl enable netfilter-persistent &>/dev/null

apt install tuned -y -f > /dev/null 2>&1
 if [[ "$(command -v tuned-adm)" ]]; then
  systemctl enable tuned &>/dev/null
  systemctl restart tuned &>/dev/null
  tuned-adm profile throughput-performance 2>/dev/null
 fi

apt install dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid jq tcpdump dsniff grepcidr screenfetch -y 2>/dev/null

apt install perl libnet-ssleay-perl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl shared-mime-info -y 2>/dev/null

gem install lolcat 2>/dev/null
apt autoremove --fix-missing -y &>/dev/null

rm -rf /etc/apt/sources.list.d/openvpn*
echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" > /etc/apt/sources.list.d/openvpn.list
apt-key del E158C569 &> /dev/null

wget -qO - https://raw.githubusercontent.com/Bonveio/BonvScripts/master/openvpn-repo.gpg | apt-key add - &>/dev/null

apt update 2>/dev/null
apt install openvpn git build-essential libssl-dev libnss3-dev cmake -y 2>/dev/null
apt autoremove --fix-missing -y &>/dev/null
apt clean 2>/dev/null

if [[ "$(command -v squid)" ]]; then
 if [[ "$(squid -v | grep -Ec '(V|v)ersion\s3.5.23')" -lt 1 ]]; then
  apt remove --purge squid -y -f 2>/dev/null
#  wget "http://security.debian.org/debian-security/pool/updates/main/s/squid3/squid_3.5.23-5+deb9u5_amd64.deb" -qO squid.deb
# use mirror squid 3.5 coz bonchan's link is dead
  wget -N --no-check-certificate -q -O squid.deb "http://script.ce7ven.com/files/squid.deb"
  dpkg -i squid.deb
  rm -f squid.deb
 else
  echo -e "Squid v3.5.23 already installed"
 fi
else
 apt install libecap3 squid-common squid-langpack -y -f 2>/dev/null
# wget "http://security.debian.org/debian-security/pool/updates/main/s/squid3/squid_3.5.23-5+deb9u5_amd64.deb" -qO squid.deb
# use mirror squid 3.5 coz bonchan's link is dead
  wget -N --no-check-certificate -q -O squid.deb "http://script.ce7ven.com/files/squid.deb"
 dpkg -i squid.deb
 rm -f squid.deb
fi

if [[ "$(command -v privoxy)" ]]; then
 apt remove privoxy -y -f 2>/dev/null
 wget -qO /tmp/privoxy.deb 'https://download.sourceforge.net/project/ijbswa/Debian/3.0.28%20%28stable%29%20stretch/privoxy_3.0.28-1_amd64.deb'
 dpkg -i  --force-overwrite /tmp/privoxy.deb
 rm -f /tmp/privoxy.deb
fi

## Running FFSend installation in background
rm -rf {/usr/bin/ffsend,/usr/local/bin/ffsend}
printf "%b\n" "\e[32m[\e[0mInfo\e[32m]\e[0m\e[97m running FFSend installation on background\e[0m"
screen -S ffsendinstall -dm bash -c "curl -4skL "https://github.com/timvisee/ffsend/releases/download/v0.2.65/ffsend-v0.2.65-linux-x64-static" -o /usr/bin/ffsend && chmod a+x /usr/bin/ffsend"
hostnamectl set-hostname localhost &> /dev/null
printf "%b\n" "\e[32m[\e[0mInfo\e[32m]\e[0m\e[97m running DDoS-deflate installation on background\e[0m"
cat <<'ddosEOF'> /tmp/install-ddos.bash
#!/bin/bash
if [[ -e /etc/ddos ]]; then
 printf "%s\n" "DDoS-deflate already installed" && exit 1
else
 curl -4skL "https://github.com/jgmdev/ddos-deflate/archive/master.zip" -o ddos.zip
 unzip -qq ddos.zip
 rm -rf ddos.zip
 cd ddos-deflate-master
 echo -e "/r/n/r/n"
 ./install.sh &> /dev/null
 cd .. && rm -rf ddos-deflate-master
 systemctl start ddos &> /dev/null
 systemctl enable ddos &> /dev/null
fi
ddosEOF
screen -S ddosinstall -dm bash -c "bash /tmp/install-ddos.bash && rm -f /tmp/install-ddos.bash"

printf "%b\n" "\e[32m[\e[0mInfo\e[32m]\e[0m\e[97m running Iptables configuration on background\e[0m"
cat <<'iptEOF'> /tmp/iptables-config.bash
#!/bin/bash
function ip_address(){
  local IP="$( ip addr | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -Ev "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$(curl -4s ipv4.icanhazip.com)"
  [ -z "${IP}" ] && IP="$(curl -4s ipinfo.io/ip)"
  [ ! -z "${IP}" ] && echo "${IP}" || echo 'ipaddress'
}
IPADDR="$(ip_address)"
PNET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
CIDR="172.29.0.0/16"
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X
iptables -A INPUT -s $IPADDR -p tcp -m multiport --dport 1:65535 -j ACCEPT
iptables -A INPUT -s $IPADDR -p udp -m multiport --dport 1:65535 -j ACCEPT
iptables -A INPUT -p tcp --dport 25 -j REJECT   
iptables -A FORWARD -p tcp --dport 25 -j REJECT
iptables -A OUTPUT -p tcp --dport 25 -j REJECT
iptables -I FORWARD -s $CIDR -j ACCEPT
iptables -t nat -A POSTROUTING -s $CIDR -o $PNET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $CIDR -o $PNET -j SNAT --to-source $IPADDR
iptables -A INPUT -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A INPUT -m string --algo bm --string ".torrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "torrent" -j REJECT
iptables -A INPUT -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A INPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A INPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A FORWARD -m string --algo bm --string ".torrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "torrent" -j REJECT
iptables -A FORWARD -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A OUTPUT -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A OUTPUT -m string --algo bm --string ".torrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "torrent" -j REJECT
iptables -A OUTPUT -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables-save > /etc/iptables/rules.v4
iptEOF
screen -S configIptables -dm bash -c "bash /tmp/iptables-config.bash && rm -f /tmp/iptables-config.bash"


}


function ConfigOpenSSH(){
echo -e "[\e[32mInfo\e[0m] Configuring OpenSSH Service"
if [[ "$(cat < /etc/ssh/sshd_config | grep -c 'BonvScripts')" -eq 0 ]]; then
 cp /etc/ssh/sshd_config /etc/ssh/backup.sshd_config
fi
cat <<'EOFOpenSSH' > /etc/ssh/sshd_config
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
Port 22
Port 225
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key
#KeyRegenerationInterval 3600
#ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
PermitRootLogin yes
StrictModes yes
#RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
#RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
#GatewayPorts yes
PrintMotd no
PrintLastLog yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
Banner /etc/banner
TCPKeepAlive yes
ClientAliveInterval 120
ClientAliveCountMax 2
AllowTcpForwarding yes
UseDNS no
EOFOpenSSH

curl -4skL "http://script.ce7ven.com/files/banner" -o /etc/banner

sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password && sed -i 's|use_authtok ||g' /etc/pam.d/common-password

echo -e "[\e[33mNotice\e[0m] Restarting OpenSSH Service.."
systemctl restart ssh &> /dev/null
}

function ConfigDropbear(){
echo -e "[\e[32mInfo\e[0m] Configuring Dropbear.."
cat <<'EOFDropbear' > /etc/default/dropbear
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
NO_START=0
DROPBEAR_PORT=555
DROPBEAR_EXTRA_ARGS="-p 701"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
EOFDropbear

echo -e "[\e[33mNotice\e[0m] Restarting Dropbear Service.."
systemctl enable dropbear &>/dev/null
systemctl restart dropbear &>/dev/null
}


function ConfigStunnel(){
if [[ ! "$(command -v stunnel4)" ]]; then
 StunnelDir='stunnel'
 else
 StunnelDir='stunnel4'
fi
echo -e "[\e[32mInfo\e[0m] Configuring Stunnel.."
cat <<'EOFStunnel1' > "/etc/default/$StunnelDir"
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
EOFStunnel1

rm -f /etc/stunnel/*
echo -e "[\e[32mInfo\e[0m] Cloning Stunnel.pem.."
openssl req -new -x509 -days 9999 -nodes -subj "/C=GB/ST=Greater Manchester/L=Salford/O=Sectigo Limited/CN=Sectigo RSA Domain Validation Secure Server CA" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null

echo -e "[\e[32mInfo\e[0m] Creating Stunnel server config.."
cat <<'EOFStunnel3' > /etc/stunnel/stunnel.conf
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = 442
connect = 127.0.0.1:701

[openssh]
accept = 444
connect = 127.0.0.1:225

[openvpn]
accept = 445
connect = 127.0.0.1:179
EOFStunnel3

echo -e "[\e[33mNotice\e[0m] Restarting Stunnel.."
systemctl restart "$StunnelDir"
}


function ConfigProxy(){
echo -e "[\e[32mInfo\e[0m] Configuring Privoxy.."
rm -f /etc/privoxy/config*
cat <<'EOFprivoxy' > /etc/privoxy/config
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 127.0.0.1:25800
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
max-client-connections 4000
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
EOFprivoxy
cat <<'EOFprivoxy2' > /etc/privoxy/user.action
{ +block }
/

{ -block }
IP-ADDRESS
127.0.0.1
EOFprivoxy2
sed -i "s|IP-ADDRESS|$(ip_address)|g" /etc/privoxy/user.action
echo -e "[\e[32mInfo\e[0m] Configuring Squid.."
rm -rf /etc/squid/sq*
cat <<'EOFsquid' > /etc/squid/squid.conf
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298

acl VPN dst IP-ADDRESS/32
http_access allow VPN
http_access deny all
http_port 0.0.0.0:8000
http_port 0.0.0.0:8080
acl bonv src 0.0.0.0/0.0.0.0
no_cache deny bonv
dns_nameservers 1.1.1.1 1.0.0.1
visible_hostname localhost
EOFsquid
sed -i "s|IP-ADDRESS|$(ip_address)|g" /etc/squid/squid.conf

echo -e "[\e[33mNotice\e[0m] Restarting Privoxy Service.."
systemctl restart privoxy
echo -e "[\e[33mNotice\e[0m] Restarting Squid Service.."
systemctl restart squid

echo -e "[\e[32mInfo\e[0m] Configuring OHPServer"
if [[ ! -e /etc/ohpserver ]]; then
 mkdir /etc/ohpserver
 else
 rm -rf /etc/ohpserver/*
fi
curl -4skL "https://github.com/lfasmpao/open-http-puncher/releases/download/0.1/ohpserver-linux32.zip" -o /etc/ohpserver/ohp.zip
unzip -qq /etc/ohpserver/ohp.zip -d /etc/ohpserver
rm -rf /etc/ohpserver/ohp.zip
chmod +x /etc/ohpserver/ohpserver

cat <<'Ohp1' > /etc/ohpserver/run
#!/bin/bash
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
# OHPServer startup script
/etc/ohpserver/ohpserver -port 8085 -proxy 127.0.0.1:25800 -tunnel 127.0.0.1:701 > /etc/ohpserver/dropbear.log &
/etc/ohpserver/ohpserver -port 8086 -proxy 127.0.0.1:25800 -tunnel 127.0.0.1:225 > /etc/ohpserver/openssh.log &
/etc/ohpserver/ohpserver -port 8087 -proxy 127.0.0.1:25800 -tunnel 127.0.0.1:179 > /etc/ohpserver/openvpn.log &
/etc/ohpserver/ohpserver -port 8088 -proxy 127.0.0.1:25800 -tunnel 127.0.0.1:25980 > /etc/ohpserver/openvpn.log
Ohp1
chmod +x /etc/ohpserver/run

cat <<'Ohp2' > /etc/ohpserver/stop
#!/bin/bash
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
# OHPServer stop script
lsof -t -i tcp:8085 -s tcp:listen | xargs kill 2>/dev/null ### Dropbear
lsof -t -i tcp:8086 -s tcp:listen | xargs kill 2>/dev/null ### OpenSSH
lsof -t -i tcp:8087 -s tcp:listen | xargs kill 2>/dev/null ### OpenVPN TCP RSA
lsof -t -i tcp:8088 -s tcp:listen | xargs kill 2>/dev/null ### OpenVPN TCP EC
Ohp2
chmod +x /etc/ohpserver/stop

cat <<'EOFohp' > /lib/systemd/system/ohpserver.service
[Unit]
Description=OpenHTTP Puncher Server
Wants=network.target
After=network.target

[Service]
ExecStart=/bin/bash /etc/ohpserver/run 2>/dev/null
ExecStop=/bin/bash /etc/ohpserver/stop 2>/dev/null
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOFohp
systemctl daemon-reload &>/dev/null
systemctl restart ohpserver.service &>/dev/null
systemctl enable ohpserver.service &>/dev/null
}


function ConfigWebmin(){
printf "%b\n" "\e[1;32m[\e[0mInfo\e[1;32m]\e[0m\e[97m running Webmin installation on background\e[0m"
cat <<'webminEOF'> /tmp/install-webmin.bash
#!/bin/bash
if [[ -e /etc/webmin ]]; then
 echo 'Webmin already installed' && exit 1
fi
rm -rf /etc/apt/sources.list.d/webmin*
echo 'deb https://download.webmin.com/download/repository sarge contrib' > /etc/apt/sources.list.d/webmin.list
apt-key del 1719003ACE3E5A41E2DE70DFD97A3AE911F63C51 &> /dev/null
wget -qO - https://download.webmin.com/jcameron-key.asc | apt-key add - &> /dev/null
apt update &> /dev/null
apt install webmin -y &> /dev/null
sed -i "s|\(ssl=\).\+|\10|" /etc/webmin/miniserv.conf
lsof -t -i tcp:10000 -s tcp:listen | xargs kill 2>/dev/null
systemctl restart webmin &> /dev/null
systemctl enable webmin &> /dev/null
webminEOF
screen -S webmininstall -dm bash -c "bash /tmp/install-webmin.bash && rm -f /tmp/install-webmin.bash"
}

function ConfigOpenVPN(){
echo -e "[\e[32mInfo\e[0m] Configuring OpenVPN server.."
if [[ ! -e /etc/openvpn ]]; then
 mkdir -p /etc/openvpn
 else
 rm -rf /etc/openvpn/*
fi
mkdir -p /etc/openvpn/server
mkdir -p /etc/openvpn/client

cat <<'EOFovpn1' > /etc/openvpn/server/server_tcp.conf
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
port 179
dev tun
proto tcp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/bonvscripts.crt
key /etc/openvpn/bonvscripts.key
dh none
persist-tun
persist-key
persist-remote-ip
duplicate-cn
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin PLUGIN_AUTH_PAM /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4080
topology subnet
server 172.29.0.0 255.255.240.0
push "redirect-gateway def1"
keepalive 5 30
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
EOFovpn1
cat <<'EOFovpn2' > /etc/openvpn/server/server_udp.conf
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
port 25222
dev tun
proto udp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/bonvscripts.crt
key /etc/openvpn/bonvscripts.key
dh none
persist-tun
persist-key
persist-remote-ip
duplicate-cn
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
float
fast-io
reneg-sec 0
plugin PLUGIN_AUTH_PAM /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4080
topology subnet
server 172.29.16.0 255.255.240.0
push "redirect-gateway def1"
keepalive 5 30
status /etc/openvpn/udp_stats.log
log /etc/openvpn/udp.log
verb 2
script-security 2
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
EOFovpn2
cat <<'EOFovpn3' > /etc/openvpn/server/ec_server_tcp.conf
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
port 25980
proto tcp
dev tun
ca /etc/openvpn/ec_ca.crt
cert /etc/openvpn/ec_bonvscripts.crt
key /etc/openvpn/ec_bonvscripts.key
dh none
persist-tun
persist-key
persist-remote-ip
duplicate-cn
cipher none
ncp-disable
auth none
compress lz4
push "compress lz4"
tun-mtu 1500
reneg-sec 0
plugin PLUGIN_AUTH_PAM /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4080
topology subnet
server 172.29.32.0 255.255.240.0
push "redirect-gateway def1"
keepalive 5 30
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
status /etc/openvpn/ec_tcp_stats.log
log /etc/openvpn/ec_tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
EOFovpn3
cat <<'EOFovpn4' > /etc/openvpn/server/ec_server_udp.conf
# ©BonvScripts
# https://t.me/BonvScripts 
# https://phcorner.net/threads/739298
# EC type OpenVPN Server
# Built for Performance
port 25985
proto udp
dev tun
ca /etc/openvpn/ec_ca.crt
cert /etc/openvpn/ec_bonvscripts.crt
key /etc/openvpn/ec_bonvscripts.key
dh none
persist-tun
persist-key
persist-remote-ip
duplicate-cn
cipher none
ncp-disable
auth none
compress lz4
push "compress lz4"
tun-mtu 1500
float
fast-io
reneg-sec 0
plugin PLUGIN_AUTH_PAM /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4080
topology subnet
server 172.29.48.0 255.255.240.0
push "redirect-gateway def1"
keepalive 5 30
tls-server
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
status /etc/openvpn/ec_udp_stats.log
log /etc/openvpn/ec_udp.log
verb 2
script-security 2
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
EOFovpn4

mkdir /etc/openvpn/easy-rsa
mkdir /etc/openvpn/easy-rsa-ec

curl -4skL "https://raw.githubusercontent.com/Bonveio/BonvScripts/master/bonvscripts-easyrsa.zip" -o /etc/openvpn/easy-rsa/rsa.zip 2> /dev/null
curl -4skL "https://raw.githubusercontent.com/Bonveio/BonvScripts/master/bonvscripts-easyrsa-ec.zip" -o /etc/openvpn/easy-rsa-ec/rsa.zip 2> /dev/null

unzip -qq /etc/openvpn/easy-rsa/rsa.zip -d /etc/openvpn/easy-rsa
unzip -qq /etc/openvpn/easy-rsa-ec/rsa.zip -d /etc/openvpn/easy-rsa-ec

rm -f /etc/openvpn/easy-rsa/rsa.zip
rm -f /etc/openvpn/easy-rsa-ec/rsa.zip

cd /etc/openvpn/easy-rsa
chmod +x easyrsa
./easyrsa build-server-full server nopass &> /dev/null
cp pki/ca.crt /etc/openvpn/ca.crt
cp pki/issued/server.crt /etc/openvpn/bonvscripts.crt
cp pki/private/server.key /etc/openvpn/bonvscripts.key

cd /etc/openvpn/easy-rsa-ec
chmod +x easyrsa
./easyrsa build-server-full server nopass &> /dev/null
cp pki/ca.crt /etc/openvpn/ec_ca.crt
cp pki/issued/server.crt /etc/openvpn/ec_bonvscripts.crt
cp pki/private/server.key /etc/openvpn/ec_bonvscripts.key

cd ~/ && echo '' > /var/log/syslog

cat <<'NUovpn' > /etc/openvpn/server/server.conf
 ### Do not overwrite this script if you didnt know what youre doing ###
 #
 # New Update are now released, OpenVPN Server
 # are now running both TCP and UDP Protocol. (Both are only running on IPv4)
 # But our native server.conf are now removed and divided
 # Into two different configs base on their Protocols:
 #  * OpenVPN TCP (located at /etc/openvpn/server/server_tcp.conf
 #  * OpenVPN UDP (located at /etc/openvpn/server/server_udp.conf
 # 
 # Also other logging files like
 # status logs and server logs
 # are moved into new different file names:
 #  * OpenVPN TCP Server logs (/etc/openvpn/server/tcp.log)
 #  * OpenVPN UDP Server logs (/etc/openvpn/server/udp.log)
 #  * OpenVPN TCP Status logs (/etc/openvpn/server/tcp_stats.log)
 #  * OpenVPN UDP Status logs (/etc/openvpn/server/udp_stats.log)
 #
 # Since config file name changes, systemctl/service identifiers are changed too.
 # To restart TCP Server: systemctl restart openvpn-server@server_tcp
 # To restart UDP Server: systemctl restart openvpn-server@server_udp
 #
 # Server ports are configured base on env vars
 # executed/raised from this script (OpenVPN_TCP_Port/OpenVPN_UDP_Port)
 #
 # Enjoy the new update
 # Script Updated by Bonveio
NUovpn

wget -qO /etc/openvpn/b.zip 'https://raw.githubusercontent.com/Bonveio/BonvScripts/master/openvpn_plugin64'
unzip -qq /etc/openvpn/b.zip -d /etc/openvpn
rm -f /etc/openvpn/b.zip

ovpnPluginPam="$(find /usr -iname 'openvpn-*.so' | grep 'auth-pam' | head -n1)"
if [[ -z "$ovpnPluginPam" ]]; then
 sed -i "s|PLUGIN_AUTH_PAM|/etc/openvpn/openvpn-auth-pam.so|g" /etc/openvpn/server/*.conf
else
 sed -i "s|PLUGIN_AUTH_PAM|$ovpnPluginPam|g" /etc/openvpn/server/*.conf
fi

sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf
sed -i '/#net.ipv4.ip_forward.*/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.d/*
sed -i '/#net.ipv4.ip_forward.*/d' /etc/sysctl.d/*
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf
sysctl --system &> /dev/null

if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

sed -i 's|ExecStart=.*|ExecStart=/usr/sbin/openvpn --status %t/openvpn-server/status-%i.log --status-version 2 --suppress-timestamps --config %i.conf|g' /lib/systemd/system/openvpn-server\@.service
systemctl daemon-reload

echo -e "[\e[33mNotice\e[0m] Restarting OpenVPN Service.."
systemctl restart openvpn-server &> /dev/null
systemctl start openvpn-server@server_tcp &>/dev/null
systemctl start openvpn-server@server_udp &>/dev/null
systemctl enable openvpn-server@server_tcp &> /dev/null
systemctl enable openvpn-server@server_udp &> /dev/null

systemctl start openvpn-server@ec_server_tcp &> /dev/null
systemctl start openvpn-server@ec_server_udp &> /dev/null
systemctl enable openvpn-server@ec_server_tcp &> /dev/null
systemctl enable openvpn-server@ec_server_udp &> /dev/null
}

install_hysteria(){
clear
echo 'Installing hysteria.'
{
wget -N --no-check-certificate -q -O ~/install_server.sh https://raw.githubusercontent.com/apernet/hysteria/master/install_server.sh; chmod +x ~/install_server.sh; ./install_server.sh

rm -f /etc/hysteria/config.json

echo '{
  "listen": ":5666",
  "cert": "/etc/hysteria/server.crt",
  "key": "/etc/hysteria/server.key",
  "up_mbps": 100,
  "down_mbps": 100,
  "disable_udp": false,
  "obfs": "dex",
  "auth": {
    "mode": "passwords",
    "config": ["mtkvpn"]
  }
}
' >> /etc/hysteria/config.json


chmod 755 /etc/hysteria/config.json


sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216

wget -O /usr/bin/badvpn-udpgw "https://apk.admin-boyes.com/setup/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw
ps x | grep 'udpvpn' | grep -v 'grep' || screen -dmS udpvpn /usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 10000 --max-connections-for-client 10 --client-socket-sndbuf 10000
} &>/dev/null
}

create_hostname() {
clear
echo 'Creating hostname.'
{
cat << EOF > /etc/hysteria/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=PH, ST=MA, L=Antipolo City, O=TKNetwork, OU=TKNerwork, CN=TKNetwork CA/name=TKNetwork/emailAddress=ericlaylay@gmail.com
        Validity
            Not Before: Sep 20 03:54:08 2022 GMT
            Not After : Sep 17 03:54:08 2032 GMT
        Subject: C=PH, ST=CA, L=Antipolo City, O=TKNetwork, OU=TKNerwork, CN=TKNetwork/name=TKNetwork/emailAddress=ericlaylay@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:b5:eb:a1:de:45:39:54:a9:12:db:91:b0:68:ac:
                    77:39:7e:4d:ee:5c:ae:6c:2f:57:a7:70:a6:19:39:
                    19:b0:46:75:6d:50:81:9d:3c:43:5a:21:49:84:b1:
                    fa:68:67:2e:05:ba:ec:e1:08:3b:70:07:77:32:03:
                    19:65:7c:af:d5:10:97:8a:3a:af:11:66:ee:42:b2:
                    90:b5:1a:34:28:55:76:0f:a3:ac:f3:e9:1d:fc:d7:
                    5f:7c:89:50:3b:7e:0f:49:61:97:b7:79:b5:c6:29:
                    2a:c5:e3:ef:38:43:77:12:cb:06:d0:e1:2c:4a:38:
                    fe:0a:33:ec:2c:b7:79:bf:b9:fa:d7:ea:2c:9f:02:
                    4f:10:eb:0a:6f:05:5a:50:01:dc:50:93:71:03:b9:
                    63:34:53:9e:30:9d:23:64:66:e8:9c:73:19:85:39:
                    b6:79:b4:55:1d:9d:2a:e0:df:4c:b2:5a:c2:e9:0e:
                    59:a2:3a:70:34:6a:9c:8a:09:34:1d:5e:29:a9:b6:
                    5b:16:ce:9e:c5:6c:50:d6:4d:10:09:60:f6:c9:00:
                    81:29:e3:a1:4c:10:fb:fe:a5:14:d6:b5:2a:e0:72:
                    50:2f:50:dc:bc:34:8d:ca:e2:fb:78:06:4d:b5:cd:
                    fe:9a:cd:2a:b7:c9:79:32:66:4a:bf:d3:d0:04:25:
                    9e:d5
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Cert Type: 
                SSL Server
            Netscape Comment: 
                Easy-RSA Generated Server Certificate
            X509v3 Subject Key Identifier: 
                28:1D:A2:5E:3A:50:2C:3A:E0:B0:54:57:D6:11:02:FC:D6:1F:FF:35
            X509v3 Authority Key Identifier: 
                keyid:DB:6B:D9:7E:CC:36:11:1E:67:E8:45:B0:07:26:88:17:F6:8B:F3:AB
                DirName:/C=PH/ST=MA/L=Antipolo City/O=TKNetwork/OU=TKNerwork/CN=TKNetwork CA/name=TKNetwork/emailAddress=ericlaylay@gmail.com
                serial:52:67:60:3D:A2:29:17:35:5F:CA:B9:4A:8E:E2:80:74:F3:CE:64:EB

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:[server]
    Signature Algorithm: sha256WithRSAEncryption
         0c:5a:d1:93:48:73:de:35:f0:1b:b5:88:71:be:ce:04:e0:f7:
         c3:b1:ef:48:05:2f:20:ff:68:6c:e6:10:0f:d2:65:6b:57:e4:
         cc:36:af:4c:ec:d4:0c:46:4c:76:5a:7d:20:74:92:67:41:5f:
         74:27:3b:48:39:51:65:ff:86:3b:1b:6a:15:b1:11:99:45:cd:
         03:0e:e2:46:5d:c0:19:e0:07:0c:18:1e:6e:a1:f6:f2:32:b5:
         3d:91:27:0a:e8:ae:e5:22:a0:f1:87:9f:b8:ba:d8:eb:6b:2b:
         82:8d:e4:2e:66:0a:2a:1f:f6:bb:ee:6a:92:8f:c7:77:0d:ee:
         68:96:58:ce:52:c5:6a:c5:7a:24:fd:ee:83:ba:0b:4e:28:b6:
         92:60:f1:ce:24:bc:9e:a5:ca:73:d3:cc:69:48:a4:8b:31:c3:
         7f:41:d1:31:2d:1e:e8:c7:4f:5d:d6:c1:e8:8d:b7:44:49:0a:
         5a:6c:ea:44:a3:70:19:12:2d:a9:d1:90:bd:3a:3d:4b:85:c0:
         35:d0:03:94:1f:de:68:1c:a0:5d:f0:b9:6c:40:68:97:1a:25:
         c1:5a:a0:cc:a9:51:68:d5:37:be:74:e4:23:0a:fd:74:92:54:
         9e:2f:fc:65:56:d1:27:3b:05:01:b4:c1:b4:a9:10:8d:70:30:
         a0:b6:74:55
-----BEGIN CERTIFICATE-----
MIIFazCCBFOgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBqjELMAkGA1UEBhMCUEgx
CzAJBgNVBAgTAk1BMRYwFAYDVQQHEw1BbnRpcG9sbyBDaXR5MRIwEAYDVQQKEwlU
S05ldHdvcmsxEjAQBgNVBAsTCVRLTmVyd29yazEVMBMGA1UEAxMMVEtOZXR3b3Jr
IENBMRIwEAYDVQQpEwlUS05ldHdvcmsxIzAhBgkqhkiG9w0BCQEWFGVyaWNsYXls
YXlAZ21haWwuY29tMB4XDTIyMDkyMDAzNTQwOFoXDTMyMDkxNzAzNTQwOFowgacx
CzAJBgNVBAYTAlBIMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNQW50aXBvbG8gQ2l0
eTESMBAGA1UEChMJVEtOZXR3b3JrMRIwEAYDVQQLEwlUS05lcndvcmsxEjAQBgNV
BAMTCVRLTmV0d29yazESMBAGA1UEKRMJVEtOZXR3b3JrMSMwIQYJKoZIhvcNAQkB
FhRlcmljbGF5bGF5QGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBALXrod5FOVSpEtuRsGisdzl+Te5crmwvV6dwphk5GbBGdW1QgZ08Q1oh
SYSx+mhnLgW67OEIO3AHdzIDGWV8r9UQl4o6rxFm7kKykLUaNChVdg+jrPPpHfzX
X3yJUDt+D0lhl7d5tcYpKsXj7zhDdxLLBtDhLEo4/goz7Cy3eb+5+tfqLJ8CTxDr
Cm8FWlAB3FCTcQO5YzRTnjCdI2Rm6JxzGYU5tnm0VR2dKuDfTLJawukOWaI6cDRq
nIoJNB1eKam2WxbOnsVsUNZNEAlg9skAgSnjoUwQ+/6lFNa1KuByUC9Q3Lw0jcri
+3gGTbXN/prNKrfJeTJmSr/T0AQlntUCAwEAAaOCAZswggGXMAkGA1UdEwQCMAAw
EQYJYIZIAYb4QgEBBAQDAgZAMDQGCWCGSAGG+EIBDQQnFiVFYXN5LVJTQSBHZW5l
cmF0ZWQgU2VydmVyIENlcnRpZmljYXRlMB0GA1UdDgQWBBQoHaJeOlAsOuCwVFfW
EQL81h//NTCB6gYDVR0jBIHiMIHfgBTba9l+zDYRHmfoRbAHJogX9ovzq6GBsKSB
rTCBqjELMAkGA1UEBhMCUEgxCzAJBgNVBAgTAk1BMRYwFAYDVQQHEw1BbnRpcG9s
byBDaXR5MRIwEAYDVQQKEwlUS05ldHdvcmsxEjAQBgNVBAsTCVRLTmVyd29yazEV
MBMGA1UEAxMMVEtOZXR3b3JrIENBMRIwEAYDVQQpEwlUS05ldHdvcmsxIzAhBgkq
hkiG9w0BCQEWFGVyaWNsYXlsYXlAZ21haWwuY29tghRSZ2A9oikXNV/KuUqO4oB0
885k6zATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBaAwEwYDVR0RBAww
CoIIW3NlcnZlcl0wDQYJKoZIhvcNAQELBQADggEBAAxa0ZNIc9418Bu1iHG+zgTg
98Ox70gFLyD/aGzmEA/SZWtX5Mw2r0zs1AxGTHZafSB0kmdBX3QnO0g5UWX/hjsb
ahWxEZlFzQMO4kZdwBngBwwYHm6h9vIytT2RJwroruUioPGHn7i62OtrK4KN5C5m
Ciof9rvuapKPx3cN7miWWM5SxWrFeiT97oO6C04otpJg8c4kvJ6lynPTzGlIpIsx
w39B0TEtHujHT13WweiNt0RJClps6kSjcBkSLanRkL06PUuFwDXQA5Qf3mgcoF3w
uWxAaJcaJcFaoMypUWjVN7505CMK/XSSVJ4v/GVW0Sc7BQG0wbSpEI1wMKC2dFU=
-----END CERTIFICATE-----
EOF

cat << EOF > /etc/hysteria/server.key
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC166HeRTlUqRLb
kbBorHc5fk3uXK5sL1encKYZORmwRnVtUIGdPENaIUmEsfpoZy4FuuzhCDtwB3cy
AxllfK/VEJeKOq8RZu5CspC1GjQoVXYPo6zz6R381198iVA7fg9JYZe3ebXGKSrF
4+84Q3cSywbQ4SxKOP4KM+wst3m/ufrX6iyfAk8Q6wpvBVpQAdxQk3EDuWM0U54w
nSNkZuiccxmFObZ5tFUdnSrg30yyWsLpDlmiOnA0apyKCTQdXimptlsWzp7FbFDW
TRAJYPbJAIEp46FMEPv+pRTWtSrgclAvUNy8NI3K4vt4Bk21zf6azSq3yXkyZkq/
09AEJZ7VAgMBAAECggEBALI+EPcKtEVy8vsXH9UvRhGa4xhszqlJKYTxJo0IGVdR
cbSNcLFyXjts6e+Nwl+Q2NLcd0N1IWd+qRbjWnrJVC5ad2AEZ4uRYlkPRCFtbzUl
putj3w2Mlsko7HHEyEvCE5A+grxOD//8TeBemAB0ebJ8Ik1+kjqW5LFydjDKBAwI
sYjXpYGkMST9rqG82EToQn9jL5Ncby35Ls3owzWDfd/1Y4NQmk6gO09spoMzWJpS
mSiV+w83QxxJtOgT00O9NuDz9skotW3v2xWTZue0BzMirCTQWPiFRL1476/O9KYD
KUBAcWynC/PE4ub0lMfaesdrggjRoDYvaQp3xLx/6HECgYEA4siN9t7Ogwhf/4X7
BAN+2OSRWRW8tn9wzzNAPzhjs8igm4W+C4lQtMmW9eFOHuRj6TiWp4w36m4cs5VF
eK39mp3/nyd9l68bFjGxw3XZsI/5bTGgcrSVAAAGp65xadI3+1Ozy7OmFoRF/Gkv
X7+/DyWz5nb9yAH/N69vPpVek8sCgYEAzVt4qpMc5tX6tMxCAC1ZUFo8fwSZndmk
jDTgb2G2O1YIqrYHqVjtwMQiDxvBGdkVJuy8QQQHM6YCD3o1Jq56bjvY1IlumXCW
0YeKfSeqfXN/nBCkyZxa79DkQSPeYEjFTFABVe/SEEcasn8HrlyygtFT+nLCcEz/
V1ekP5Mmg98CgYEApsGOEh9XfuZjoIKmRxdC6L15WyYus4sWKmWnMlWGiqZV4sX/
LoB0BdvN01MunGyYQt/Hd8AVRZ5eIHb8tHZL6quPUTo6kZTCuBkme3Fm9vuHDxHU
x0Od5HggbKBK6OMZIwczR+/7iscMp0O5ABEArmSs2iRZC/7b6dhoVn6DIu0CgYA+
tOvHylxM8JI5mxWcUDyxmJxYfOMbnFXuqkbOPBwVSlQjLKpyP8F512o/Cs6QQgV/
eVKS19QLJWoDp+GLCkRAXO39GGo5WHP1T1oulWouHJKe6UYoeiIakMLiUT2aUR5O
CzAdObn/VncEgl2qFIw9/gWSuHA/MoPV++EfuKNOKQKBgDbyYfG3JESaLpaEiPED
UQDv4iVBzaqA3sMpmpA2YRIUZE4ZzSuiVMxGHfhAvueuiMwyzqsLe0BOgCNtJDg3
o4CmMhs3Wlw5FiOru1LxQY//65wi5q8+rNF4DR3oUKoVGb1PD3Gm8ZsxirhMOCrc
sKKWTJk08giHse+yqTKQ05uR
-----END PRIVATE KEY-----
EOF


chmod 755 /etc/hysteria/config.json
chmod 755 /etc/hysteria/server.crt
chmod 755 /etc/hysteria/server.key
}
}

install_firewall_kvm () {
clear
echo "Installing iptables."
echo "net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.eth0.rp_filter=0" >> /etc/sysctl.conf
sysctl -p
{
iptables -F
iptables -t nat -A PREROUTING -i eth0 -p udp -m udp --dport 10000:50000 -j DNAT --to-destination :5666
iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o "$server_interface" -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.20.0.0/22 -o "$server_interface" -j SNAT --to-source "$server_ip"
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o "$server_interface" -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.30.0.0/22 -o "$server_interface" -j SNAT --to-source "$server_ip"
iptables -t filter -A INPUT -p udp -m udp --dport 20100:20900 -m state --state NEW -m recent --update --seconds 30 --hitcount 10 --name DEFAULT --mask 255.255.255.255 --rsource -j DROP
iptables -t filter -A INPUT -p udp -m udp --dport 20100:20900 -m state --state NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource
iptables-save > /etc/iptables_rules.v4
ip6tables-save > /etc/iptables_rules.v6
}&>/dev/null
}

installBBR() {
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    apt install linux-generic-hwe-20.04
    grub-set-default 0
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
    INSTALL_BBR=true
}

install_rclocal(){
  {     
    echo "[Unit]
Description=teamkidlat service
Documentation=http://teamkidlat.com

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/rc.local
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/teamkidlat.service

echo '#!/bin/sh -e
iptables-restore < /etc/iptables_rules.v4
ip6tables-restore < /etc/iptables_rules.v6
sysctl -p
systemctl restart hysteria-server.service
ps x | grep 'udpvpn' | grep -v 'grep' || screen -dmS udpvpn /usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 10000 --max-connections-for-client 10 --client-socket-sndbuf 10000
screen -dmS webinfo php -S 0.0.0.0:5623 -t /root/.web/
exit 0' >> /etc/rc.local

sudo chmod +x /etc/rc.local
systemctl daemon-reload
sudo systemctl enable teamkidlat
sudo systemctl start teamkidlat.service
    
mkdir -m 777 /root/.web
echo "Made with love by: Dexter Eskalarte... " >> /root/.web/index.php

echo "
hysteria_port=5666" >> /root/.ports


sed -i "s|SERVERIP|$server_ip|g" /etc/.counter
  }&>/dev/null
}

function ConfigMenu(){
echo -e "[\e[32mInfo\e[0m] Creating Menu scripts.."

cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squi*,edit_stunne*,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,screenfetch,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock,*_gtm_noload}
wget -q 'https://raw.githubusercontent.com/Bonveio/BonvScripts/master/menuV1.zip'
unzip -qq -o menuV1.zip
rm -f menuV1.zip
chmod +x ./*
dos2unix -q ./*
cd ~
}

function ConfigSyscript(){
echo -e "[\e[32mInfo\e[0m] Creating Startup scripts.."
if [[ ! -e /etc/bonveio ]]; then
 mkdir -p /etc/bonveio
fi
cat <<'EOFSH' > /etc/bonveio/startup.sh
#!/bin/bash
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
#
export DEBIAN_FRONTEND=noninteractive
#apt clean
screen -dmS delexpuser bash /usr/local/sbin/delete_expired &>/dev/null
screen -dmS ws-http-8880 python ~/.ws-http-8880.py &>/dev/null
screen -dmS ws-http-2052 python ~/.ws-http-2052.py &>/dev/null
screen -dmS ws-http-2082 python ~/.ws-http-2082.py &>/dev/null
screen -dmS ws-http-2086 python ~/.ws-http-2086.py &>/dev/null
screen -dmS ws-http-2095 python ~/.ws-http-2095.py &>/dev/null
screen -dmS ws-http-8280 python ~/.ws-http-8280.py &>/dev/null
screen -dmS ws-http-80 python ~/.ws-http-80.py &>/dev/null
screen -dmS ws-ssl-8443 python ~/.ws-ssl-8443.py &>/dev/null
screen -dmS ws-ssl-2053 python ~/.ws-ssl-2053.py &>/dev/null
screen -dmS ws-ssl-2087 python ~/.ws-ssl-2087.py &>/dev/null
screen -dmS ws-ssl-2096 python ~/.ws-ssl-2096.py &>/dev/null
screen -dmS ws-ssl-443 python ~/.ws-ssl-443.py &>/dev/null
screen -dmS openvpn-http-8283 python ~/.openvpn-http-8283.py &>/dev/null
screen -dmS openvpn-http-8284 python ~/.openvpn-http-8284.py &>/dev/null
screen -dmS openvpn-ssl-8444 python ~/.openvpn-ssl-8444.py &>/dev/null
screen -dmS openvpn-ssl-8445 python ~/.openvpn-ssl-8445.py &>/dev/null

bash /root/.services
EOFSH
chmod +x /etc/bonveio/startup.sh

echo 'clear' > /etc/profile.d/bonv.sh
echo 'screenfetch -p -A Debian | sed -r "/^\s*$/d" ' >> /etc/profile.d/bonv.sh
chmod +x /etc/profile.d/bonv.sh

echo "[Unit]
Description=Bonveio Startup Script
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/bonveio/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/bonveio.service
chmod +x /etc/systemd/system/bonveio.service
systemctl daemon-reload
systemctl start bonveio
systemctl enable bonveio &> /dev/null

#sed -i '/0\s*4\s*.*/d' /etc/cron.d/*
#sed -i '/0\s*4\s*.*/d' /etc/crontab
sed -i '/*.root\sreboot$/d' /etc/cron.d/*
sed -i '/*.root\sreboot$/d' /etc/crontab
echo -e "\r\n" >> /etc/crontab
echo -e "0 4\t* * *\troot\treboot" >> /etc/cron.d/reboot_sys
printf "%s" "0 */4  * * *  root  /usr/bin/screen -S delexpuser -dm bash -c '/usr/local/sbin/delete_expired'" > /etc/cron.d/autodelete_expireduser
systemctl restart cron
}

function ConfigNginxOvpn(){
echo -e "[\e[32mInfo\e[0m] Configuring Nginx configs.."

cat <<'EOFnginx' > /etc/nginx/conf.d/bonveio-ovpn-config.conf
# BonvScripts
# https://t.me/BonvScripts
# Please star my Repository: https://github.com/Bonveio/BonvScripts
# https://phcorner.net/threads/739298
#
server {
 listen 0.0.0.0:86;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
EOFnginx

rm -rf /etc/nginx/sites-*
rm -rf /usr/share/nginx/html
rm -rf /var/www/openvpn
mkdir -p /var/www/openvpn

echo -e "[\e[32mInfo\e[0m] Creating OpenVPN client configs.."

cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">

<!-- Simple OVPN Download site by Ce7ven -->

<head><meta charset="utf-8" /><title>MyScriptName OVPN Config Download</title><meta name="description" content="MyScriptName Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top mb-5" height="150"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group">

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> TCP Protocol</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/tcp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP OHP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> TCP Protocol via OHP</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/tcp_ohp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP EC <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> TCP Protocol Elliptic Curve</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/tcp_ec.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP OHP EC <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> TCP Protocol Elliptic Curve via OHP</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/tcp_ohp_ec.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>UDP <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> UDP Protocol</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/udp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

<li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>UDP EC <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><small> UDP Protocol Elliptic Curve</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/udp_ec.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li>

</ul></div></div></div></div></body></html>
mySiteOvpn

sed -i "s|MyScriptName|BonvScripts|g" /var/www/openvpn/index.html
sed -i "s|NGINXPORT|86|g" /var/www/openvpn/index.html
sed -i "s|IP-ADDRESS|$(ip_address)|g" /var/www/openvpn/index.html

######
cat <<"EOFtcp" > /var/www/openvpn/tcp.ovpn

# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
# 

client
dev tun
persist-tun
proto tcp
remote IP-ADDRESS 179
http-proxy IP-ADDRESS 8000
persist-remote-ip
resolv-retry infinite
connect-retry 0 1
remote-cert-tls server
nobind
reneg-sec 0
keysize 0
rcvbuf 0
sndbuf 0
verb 2
comp-lzo
auth none
auth-nocache
cipher none
setenv CLIENT_CERT 0
http-proxy-option VERSION 1.1
http-proxy-option AGENT Chrome/80.0.3987.87
http-proxy-option CUSTOM-HEADER Host redirect.googlevideo.com
http-proxy-option CUSTOM-HEADER X-Forward-Host redirect.googlevideo.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For redirect.googlevideo.com
http-proxy-option CUSTOM-HEADER Referrer redirect.googlevideo.com
auth-user-pass
EOFtcp

cat <<"EOFohp1" > /var/www/openvpn/tcp_ohp.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
# Experimental Config only
# Examples demonstrated below on how to Play with OHPServer
#

client
dev tun
persist-tun
proto tcp

# We can play this one, put any host on the line
# remote anyhost.com anyport
# remote www.google.com.ph 443
#
# We can also play with CRLFs
#remote "HEAD https://ajax.googleapis.com HTTP/1.1/r/n/r/n"
# Every types of Broken remote line setups/crlfs/payload are accepted, just put them inside of double-quotes
remote "https://www.phcorner.net"
## use this line to modify OpenVPN remote port (this will serve as our fake ovpn port)
port 443

# This proxy uses as our main forwarder for OpenVPN tunnel.
http-proxy IP-ADDRESS 8087

# We can also play our request headers here, everything are accepted, put them inside of a double-quotes.
http-proxy-option VERSION 1.1
http-proxy-option CUSTOM-HEADER ""
http-proxy-option CUSTOM-HEADER "Host: www.ce7ven.com%2F"
http-proxy-option CUSTOM-HEADER "X-Forwarded-Host: www.digicert.net%2F"
http-proxy-option CUSTOM-HEADER ""

persist-remote-ip
resolv-retry infinite
connect-retry 0 1
remote-cert-tls server
nobind
reneg-sec 0
keysize 0
rcvbuf 0
sndbuf 0
verb 2
comp-lzo
auth none
auth-nocache
cipher none
setenv CLIENT_CERT 0
auth-user-pass
EOFohp1

cat <<"EOFudp" > /var/www/openvpn/udp.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
# Example UDP Client. 
#
client
dev tun
persist-tun
proto udp
remote IP-ADDRESS 25222
persist-remote-ip
resolv-retry infinite
connect-retry 0 1
remote-cert-tls server
nobind
float
fast-io
reneg-sec 0
keysize 0
rcvbuf 0
sndbuf 0
verb 2
comp-lzo
auth none
auth-nocache
cipher none
setenv CLIENT_CERT 0
auth-user-pass
EOFudp

cat <<"EOFec" > /var/www/openvpn/tcp_ec.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
# 

client
dev tun
persist-tun
proto tcp
remote IP-ADDRESS 25980
http-proxy IP-ADDRESS 8000
persist-remote-ip
resolv-retry infinite
connect-retry 0 1
remote-cert-tls server
nobind
reneg-sec 0
keysize 0
rcvbuf 0
sndbuf 0
verb 2
comp-lzo
auth none
auth-nocache
cipher none
setenv CLIENT_CERT 0
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
http-proxy-option VERSION 1.1
http-proxy-option AGENT Chrome/80.0.3987.87
http-proxy-option CUSTOM-HEADER Host redirect.googlevideo.com
http-proxy-option CUSTOM-HEADER X-Forward-Host redirect.googlevideo.com
http-proxy-option CUSTOM-HEADER X-Forwarded-For redirect.googlevideo.com
http-proxy-option CUSTOM-HEADER Referrer redirect.googlevideo.com
auth-user-pass
EOFec

cat <<"EOFohpec" > /var/www/openvpn/tcp_ohp_ec.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
# Experimental Config only
# Examples demonstrated below on how to Play with OHPServer
#

client
dev tun
persist-tun
proto tcp

# We can play this one, put any host on the line
# remote anyhost.com anyport
# remote www.google.com.ph 443
#
# We can also play with CRLFs
#remote "HEAD https://ajax.googleapis.com HTTP/1.1/r/n/r/n"
# Every types of Broken remote line setups/crlfs/payload are accepted, just put them inside of double-quotes
remote "https://www.phcorner.net"
## use this line to modify OpenVPN remote port (this will serve as our fake ovpn port)
port 443

# This proxy uses as our main forwarder for OpenVPN tunnel.
http-proxy IP-ADDRESS 8088

# We can also play our request headers here, everything are accepted, put them inside of a double-quotes.
http-proxy-option VERSION 1.1
http-proxy-option CUSTOM-HEADER ""
http-proxy-option CUSTOM-HEADER "Host: www.ce7ven.com%2F"
http-proxy-option CUSTOM-HEADER "X-Forwarded-Host: www.digicert.net%2F"
http-proxy-option CUSTOM-HEADER ""

persist-remote-ip
resolv-retry infinite
connect-retry 0 1
remote-cert-tls server
nobind
reneg-sec 0
keysize 0
rcvbuf 0
sndbuf 0
verb 2
comp-lzo
auth none
auth-nocache
cipher none
setenv CLIENT_CERT 0
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
auth-user-pass
EOFohpec

cat <<"EOFudpec" > /var/www/openvpn/udp_ec.ovpn
# OpenVPN Server build vOPENVPN_SERVER_VERSION
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
#
# Example UDP Client. 
#
client
dev tun
persist-tun
proto udp
remote IP-ADDRESS 25985
persist-remote-ip
resolv-retry infinite
connect-retry 0 1
remote-cert-tls server
nobind
float
fast-io
reneg-sec 0
keysize 0
rcvbuf 0
sndbuf 0
verb 2
comp-lzo
auth none
auth-nocache
cipher none
setenv CLIENT_CERT 0
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
auth-user-pass
EOFudpec

sed -i "s|IP-ADDRESS|$(ip_address)|g" /var/www/openvpn/*.ovpn

echo -e "<ca>\n$(cat /etc/openvpn/ca.crt)\n</ca>" >> /var/www/openvpn/tcp.ovpn

echo -e "<ca>\n$(cat /etc/openvpn/ca.crt)\n</ca>" >> /var/www/openvpn/tcp_ohp.ovpn

echo -e "<ca>\n$(cat /etc/openvpn/ca.crt)\n</ca>" >> /var/www/openvpn/udp.ovpn

echo -e "<ca>\n$(cat /etc/openvpn/ec_ca.crt)\n</ca>" >> /var/www/openvpn/tcp_ec.ovpn

echo -e "<ca>\n$(cat /etc/openvpn/ec_ca.crt)\n</ca>" >> /var/www/openvpn/tcp_ohp_ec.ovpn

echo -e "<ca>\n$(cat /etc/openvpn/ec_ca.crt)\n</ca>" >> /var/www/openvpn/udp_ec.ovpn

sed -i "s|OPENVPN_SERVER_VERSION|$(openvpn --version | cut -d" " -f2 | head -n1)|g" /var/www/openvpn/*.ovpn
sed -i "s|OPENVPN_SERVER_LOCATION|$(curl -4s http://ipinfo.io/country), $(curl -4s http://ipinfo.io/region)|g" /var/www/openvpn/*.ovpn
sed -i "s|OPENVPN_SERVER_ISP|$(curl -4s http://ipinfo.io/org | sed -e 's/[^ ]* //')|g" /var/www/openvpn/*.ovpn

cd /var/www/openvpn
zip -r Configs.zip *.ovpn &> /dev/null
cd

echo -e "[\e[33mNotice\e[0m] Restarting Nginx Service.."
systemctl restart nginx
}

function UnistAll(){
 echo -e " Removing dropbear"
 sed -i '/Port 225/d' /etc/ssh/sshd_config
 sed -i '/Banner .*/d' /etc/ssh/sshd_config
 systemctl restart ssh
 systemctl stop dropbear
 apt remove --purge dropbear -y
 rm -f /etc/default/dropbear
 rm -rf /etc/dropbear/*
 echo -e " Removing stunnel"
 systemctl stop stunnel &> /dev/null
 systemctl stop stunnel4 &> /dev/null
 apt remove --purge stunnel -y
 rm -rf /etc/stunnel/*
 rm -rf /etc/default/stunnel*
 echo -e " Removing webmin"
 systemctl stop webmin
 apt remove --purge webmin -y
 rm -rf /etc/webmin/*;
 rm -f /etc/apt/sources.list.d/webmin*;
 echo -e " Removing OpenVPN server and client config download site"
 systemctl stop openvpn-server@server_tcp &>/dev/null
 systemctl stop openvpn-server@server_udp &>/dev/null
 systemctl stop openvpn-server@ec_server_tcp &>/dev/null
 systemctl stop openvpn-server@ec_server_udp &>/dev/null
 systemctl disable openvpn-server@server_tcp &>/dev/null
 systemctl disable openvpn-server@server_udp &>/dev/null
 systemctl disable openvpn-server@ec_server_tcp &>/dev/null
 systemctl disable openvpn-server@ec_server_udp &>/dev/null
 apt remove --purge openvpn -y -f
 rm -rf /etc/openvpn/*
 rm -rf /var/www/openvpn
 rm -f /etc/apt/sources.list.d/openvpn*
 rm -rf /etc/nginx/conf.d/bonveio-ovpn-config*
 systemctl restart nginx &> /dev/null
 echo -e "Removing squid"
 apt remove --purge squid -y
 rm -rf /etc/squid/*
 echo -e "Removing privoxy"
 apt remove --purge privoxy -y
 rm -rf /etc/privoxy/*
 systemctl stop badvpn-udpgw.service &>/dev/null
 systemctl disable badvpn-udpgw.service &>/dev/null
 rm -rf /usr/local/{share/man/man7/badvpn*,share/man/man8/badvpn*,bin/badvpn-*}
 echo -e " Finalizing.."
 rm -rf /etc/bonveio
 rm -rf /etc/banner
 systemctl disable bonveio &> /dev/null
 rm -rf /etc/systemd/system/bonveio.service
 rm -rf /etc/cron.d/b_reboot_job
 rm -rf /etc/cron.d/reboot_sys
 rm -rf /etc/cron.d/autodelete_expireduser
 systemctl restart cron &> /dev/null
 rm -rf /usr/local/sbin/{accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squi*,edit_stunne*,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock,activate_gtm_noload,deactivate_gtm_noload}
 rm -rf /etc/profile.d/bonv.sh
 rm -rf /tmp/*
 apt autoremove -y -f
 rm -rf /etc/ohpserver
 systemctl stop ohpserver.service &> /dev/null
 systemctl disable ohpserver.service &> /dev/null
 systemctl stop ohpserver-autorecon.service &>/dev/null
 systemctl disable ohpserver-autorecon.service &>/dev/null
 rm -rf /etc/systemd/system/ohpserver-autorecon.service
 rm -rf /lib/systemd/system/ohpserver.service
 rm -rf /lib/systemd/system/badvpn-udpgw.service
 systemctl daemon-reload &>/dev/null
 echo 3 > /proc/sys/vm/drop_caches
}

function CondomSocks(){
#Adding condom
 wget --no-check-certificate http://script.ce7ven.com/files/ws-http-8880.py -O ~/.ws-http-8880.py
 wget --no-check-certificate http://script.ce7ven.com/files/ws-http-2052.py -O ~/.ws-http-2052.py
 wget --no-check-certificate http://script.ce7ven.com/files/ws-http-2082.py -O ~/.ws-http-2082.py
 wget --no-check-certificate http://script.ce7ven.com/files/ws-http-2086.py -O ~/.ws-http-2086.py
 wget --no-check-certificate http://script.ce7ven.com/files/ws-http-2095.py -O ~/.ws-http-2095.py
 wget --no-check-certificate http://script.ce7ven.com/files/ws-http-8280.py -O ~/.ws-http-8280.py
 wget --no-check-certificate http://script.ce7ven.com/files/ws-http-80.py -O ~/.ws-http-80.py
 wget --no-check-certificate http://script.ce7ven.com/files/ws-ssl-8443.py -O ~/.ws-ssl-8443.py
 wget --no-check-certificate http://script.ce7ven.com/files/ws-ssl-2053.py -O ~/.ws-ssl-2053.py
 wget --no-check-certificate http://script.ce7ven.com/files/ws-ssl-2087.py -O ~/.ws-ssl-2087.py
 wget --no-check-certificate http://script.ce7ven.com/files/ws-ssl-2096.py -O ~/.ws-ssl-2096.py
 wget --no-check-certificate http://script.ce7ven.com/files/ws-ssl-443.py -O ~/.ws-ssl-443.py
 
 wget --no-check-certificate http://script.ce7ven.com/files/openvpn-http-8283.py -O ~/.openvpn-http-8283.py
 wget --no-check-certificate http://script.ce7ven.com/files/openvpn-http-8284.py -O ~/.openvpn-http-8284.py
 wget --no-check-certificate http://script.ce7ven.com/files/openvpn-ssl-8444.py -O ~/.openvpn-ssl-8444.py
 wget --no-check-certificate http://script.ce7ven.com/files/openvpn-ssl-8445.py -O ~/.openvpn-ssl-8445.py
 
 dos2unix ~/.ws-http-8880.py
 dos2unix ~/.ws-http-2052.py
 dos2unix ~/.ws-http-2082.py
 dos2unix ~/.ws-http-2086.py
 dos2unix ~/.ws-http-2095.py
 dos2unix ~/.ws-http-8280.py
 dos2unix ~/.ws-http-80.py
 dos2unix ~/.ws-ssl-8443.py
 dos2unix ~/.ws-ssl-2053.py
 dos2unix ~/.ws-ssl-2087.py
 dos2unix ~/.ws-ssl-2096.py
 dos2unix ~/.ws-ssl-443.py
 
 dos2unix ~/.openvpn-http-8283.py
 dos2unix ~/.openvpn-http-8284.py
 dos2unix ~/.openvpn-ssl-8444.py
 dos2unix ~/.openvpn-ssl-8445.py
 
 chmod +x ~/.ws-http-8880.py
 chmod +x ~/.ws-http-2052.py
 chmod +x ~/.ws-http-2082.py
 chmod +x ~/.ws-http-2086.py
 chmod +x ~/.ws-http-2095.py
 chmod +x ~/.ws-http-8280.py
 chmod +x ~/.ws-http-80.py
 chmod +x ~/.ws-ssl-8443.py
 chmod +x ~/.ws-ssl-2053.py
 chmod +x ~/.ws-ssl-2087.py
 chmod +x ~/.ws-ssl-2096.py
 chmod +x ~/.ws-ssl-443.py
 
 chmod +x ~/.openvpn-http-8283.py
 chmod +x ~/.openvpn-http-8284.py
 chmod +x ~/.openvpn-ssl-8444.py
 chmod +x ~/.openvpn-ssl-8445.py
}

function SlowDNS(){
cd ~
apt install -y dos2unix debconf-utils pwgen mlocate dh-make

MYIP=$(wget -qO- icanhazip.com);
genA=$(echo "$(pwgen 10 1)" | tr '[:upper:]' '[:lower:]')
genNS=$(echo "$(pwgen 5 1)" | tr '[:upper:]' '[:lower:]')
secretkey='server'
dnsresolverName="1.1.1.1"
dnsresolverType="udp"
dnsresolver="1.1.1.1:53"

dnsdomain=ce7ven.com
dnszone=92a82d9c36eba7eefd52fad8c7e16c52

arecord="$genA.$dnsdomain"
nsrecord="$genNS.$dnsdomain"
hostname=$arecord
domain=$nsrecord

#install slowdns
curl -X POST "https://api.cloudflare.com/client/v4/zones/$dnszone/dns_records" -H "X-Auth-Email: petev814@gmail.com" -H "X-Auth-Key: 107cd282870039989143af4e6ec631b6c5b9e" -H "Content-Type: application/json" --data '{"type":"A","name":"'"$(echo $arecord)"'","content":"'"$(curl -s https://api.ipify.org)"'","ttl":1,"priority":0,"proxied":false}' &>/dev/null
curl -X POST "https://api.cloudflare.com/client/v4/zones/$dnszone/dns_records" -H "X-Auth-Email: petev814@gmail.com" -H "X-Auth-Key: 107cd282870039989143af4e6ec631b6c5b9e" -H "Content-Type: application/json" --data '{"type":"NS","name":"'"$(echo $nsrecord)"'","content":"'"$(echo $arecord)"'","ttl":1,"priority":0,"proxied":false}' &>/dev/null

cd /usr/local
wget https://golang.org/dl/go1.16.2.linux-amd64.tar.gz
tar xvf go1.16.2.linux-amd64.tar.gz
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH

sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding yes/g' /etc/ssh/sshd_config

export DNSDIR=/etc/.dnsquest
export DNSCONFIG=/root/.dns
mkdir -m 777 /etc/.dnsquest
mkdir -m 777 $DNSCONFIG
cd $DNSDIR
git clone https://www.bamsoftware.com/git/dnstt.git

cd $DNSDIR/dnstt/dnstt-server
go build
./dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
cp server.key server.pub $DNSCONFIG
cp dnstt-server $DNSDIR

cd $DNSDIR/dnstt/dnstt-client
go build
cp dnstt-client $DNSDIR

echo "domain=$domain
privkey=`cat /root/.dns/server.key`
pubkey=`cat /root/.dns/server.pub`
os=$serverDistro
dnsresolvertype=$dnsresolverType
dnsresolver=$dnsresolver" >> $DNSCONFIG/config

cd ~
cat <<'EOFservices' > /root/.services
#!/bin/bash
source /root/.dns/config
screen -dmS slowdns1 /etc/.dnsquest/dnstt-server -udp :5300 -privkey $privkey $domain 127.0.0.1:22 &>/dev/null
if [[ $dnsresolvertype == "doh" ]]
then
screen -dmS slowdns2 /etc/.dnsquest/dnstt-client -doh $dnsresolver -pubkey $pubkey $domain 127.0.0.1:2222 &>/dev/null	
else
screen -dmS slowdns2 /etc/.dnsquest/dnstt-client -udp $dnsresolver -pubkey $pubkey $domain 127.0.0.1:2222 &>/dev/null
fi
EOFservices
chmod +x /root/.services

echo "Hi! this is your server information, Happy Surfing!

IP : $MYIP
SSH : 22
SSH via DNS : 2222
SQUID : 8080
SERVER DOMAIN: $hostname

-----------------------
DNS NS : $domain
DNS RESOLVER : $dnsresolverName
DNS PUBLIC KEY : $(cat /root/.dns/server.pub)
-----------------------

Panel : https://ce7ven.com

For issues or suggestions please open an issue on github.

" >> /var/www/openvpn/$secretkey.txt

iptables -I INPUT -p udp --dport 5300 -j ACCEPT &>/dev/null;
iptables -t nat -I PREROUTING -i $(ip route get 8.8.8.8 | awk '/dev/ {f=NR} f&&NR-1==f' RS=" ") -p udp --dport 53 -j REDIRECT --to-ports 5300 &>/dev/null;
ip6tables -I INPUT -p udp --dport 5300 -j ACCEPT &>/dev/null;
ip6tables -t nat -I PREROUTING -i $(ip route get 8.8.8.8 | awk '/dev/ {f=NR} f&&NR-1==f' RS=" ") -p udp --dport 53 -j REDIRECT --to-ports 5300 &>/dev/null;
iptables-save > /etc/iptables/rules.v4
iptables-restore -t < /etc/iptables/rules.v4
netfilter-persistent save
netfilter-persistent reload
}

function InstallScript(){
if [[ ! -e /dev/net/tun ]]; then
 BONV-MSG
 echo -e "[\e[1;31m×\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi

rm -rf /root/.bash_history && echo '' > /var/log/syslog && history -c

## Start Installation
clear
clear
BONV-MSG
echo -e ""
InsEssentials
ConfigOpenSSH
ConfigDropbear
ConfigStunnel
ConfigProxy
ConfigWebmin
ConfigOpenVPN
install_hysteria
create_hostname
install_firewall_kvm
installBBR
install_rclocal
ConfigMenu
ConfigSyscript
ConfigNginxOvpn
CondomSocks
SlowDNS

echo -e "[\e[32mInfo\e[0m] Finalizing installation process.."
ln -fs /usr/share/zoneinfo/Asia/Manila /etc/localtime
sed -i '/\/bin\/false/d' /etc/shells
sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
echo '/bin/false' >> /etc/shells
echo '/usr/sbin/nologin' >> /etc/shells
sleep 1
######

clear
clear
clear
bash /etc/profile.d/bonv.sh
BONV-MSG
echo -e ""
echo -e "\e[38;5;46m=\e[0m\e[38;5;46m=\e[0m\e[38;5;47m S\e[0m\e[38;5;47mu\e[0m\e[38;5;48mc\e[0m\e[38;5;48m\e[0m\e[38;5;49mc\e[0m\e[38;5;49me\e[0m\e[38;5;50ms\e[0m\e[38;5;50ms\e[0m\e[38;5;51m I\e[0m\e[38;5;51mn\e[0m\e[38;5;50ms\e[0m\e[38;5;50mt\e[0m\e[38;5;49ma\e[0m\e[38;5;49ml\e[0m\e[38;5;48ml\e[0m\e[38;5;48ma\e[0m\e[38;5;47mt\e[0m\e[38;5;47mi\e[0m\e[38;5;46mo\e[0m\e[38;5;46mn \e[0m\e[38;5;47m=\e[0m\e[38;5;47m=\e[0m"
echo -e ""
echo -e "\e[92m Service Ports\e[0m\e[97m:\e[0m"
echo -e "\e[92m OpenSSH\e[0m\e[97m: 22, 225\e[0m"
echo -e "\e[92m Stunnel\e[0m\e[97m: 442, 443\e[0m"
echo -e "\e[92m Dropbear\e[0m\e[97m: 550, 555\e[0m"
echo -e "\e[92m Squid\e[0m\e[97m: 8000, 8080\e[0m"
echo -e "\e[92m OpenVPN\e[0m\e[97m: 110(TCP), 25222(UDP)\e[0m"
echo -e "\e[92m OpenVPN EC\e[0m\e[97m: 25980(TCP), 25985(UDP)\e[0m"
echo -e "\e[92m NGiNX\e[0m\e[97m: 86\e[0m"
echo -e "\e[92m Webmin\e[0m\e[97m: 10000\e[0m"
echo -e "\e[92m BadVPN-udpgw\e[0m\e[97m: 7300\e[0m"
echo -e ""
echo -e "\e[97m NEW! OHPServer builds\e[0m"
echo -e "\e[97m (Good for Payload bugging and any related HTTP Experiments)\e[0m"
echo -e "\e[92m OHP+Dropbear\e[0m\e[97m: 8085\e[0m"
echo -e "\e[92m OHP+OpenSSH\e[0m\e[97m: 8086\e[0m"
echo -e "\e[92m OHP+OpenVPN\e[0m\e[97m: 8087\e[0m"
echo -e "\e[92m OHP+OpenVPN Elliptic Curve\e[0m\e[97m: 8088\e[0m"
echo -e ""
echo -e "\e[97m Websockets\e[0m"
echo -e "\e[92m Dropbear(WS-HTTP)\e[0m\e[97m: 8880, 2052, 2082, 2086, 2095, 8280, 80\e[0m"
echo -e "\e[92m Dropbear(WS-SSL)\e[0m\e[97m: 8443, 2053, 2087, 2096, 443\e[0m"
echo -e "\e[92m OpenVPN(WS-HTTP)\e[0m\e[97m: 8283, 8284\e[0m"
echo -e "\e[92m OpenVPN(WS-SSL)\e[0m\e[97m: 8444, 8445\e[0m"
echo -e ""
echo -e ""
echo -e "\e[92m OpenVPN Configs Download Site\e[0m\e[97m:\e[0m"
echo -e "\e[97m http://$(ip_address):86\e[0m"
echo -e ""
echo -e "\e[92m All OpenVPN Configs Archive\e[0m\e[97m:\e[0m"
echo -e "\e[97m http://$(ip_address)/Configs.zip\e[0m"
echo -e ""
echo -e ""
echo -e " * Script by Bonveio"
echo -e " * OHPServer by lfasmpao"
echo -e " ©BonvScripts"
echo -e ""
echo -e " [Note] DO NOT RESELL THIS SCRIPT"
echo -e " This script is under project of\n https://github.com/Bonveio/BonvScripts"
echo -e ""
rm -f ~/.installer
rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
reboot
}

source /etc/os-release > /dev/null 2>&1
if [[ "$ID" != 'debian' ]]; then
 BONV-MSG
 echo -e "[\e[1;31mError\e[0m] This script is for Debian only, exting..." 
 exit 1
fi

if [[ "$VERSION_ID" -lt 9 ]]; then
 BONV-MSG
 echo -e "[\e[1;31mError\e[0m] This script is supported only on Debian 9 stretch above." 
 exit 1
fi

if [[ $EUID -ne 0 ]]; then
 BONV-MSG
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

case $1 in
 install)
 BONV-MSG
 InstallScript
 exit 1
 ;;
 uninstall|remove)
 BONV-MSG
 UnistAll
 clear
 BONV-MSG
 echo -e ""
 echo -e " Uninstallation complete."
 rm -f DebianVPS-*
 exit 1
 ;;
 help|--help|-h)
 BONV-MSG
 echo -e " install = Install script"
 echo -e " uninstall = Remove all services installed by this script"
 echo -e " help = show this help message"
 exit 1
 ;;
 *)
 BONV-MSG
 echo -e " Starting Installation"
 echo -e " CRTL + C if you wish to cancel it"
 sleep 5
 InstallScript
 exit 1
 ;;
esac
