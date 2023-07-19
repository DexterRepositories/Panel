#!/bin/bash
# Auto Script for Multi OS By Mtknetwork 2023
RED='\033[01;31m';
RESET='\033[0m';
GREEN='\033[01;32m';
WHITE='\033[01;37m';
YELLOW='\033[00;33m';

echo -e "                $GREEN Choose Your Category $RESET"
echo '                                                            
    ██████╗ ███████╗██╗  ██╗████████╗███████╗██████╗        
    ██╔══██╗██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗       
    ██║  ██║█████╗   ╚███╔╝    ██║   █████╗  ██████╔╝       
    ██║  ██║██╔══╝   ██╔██╗    ██║   ██╔══╝  ██╔══██╗       
    ██████╔╝███████╗██╔╝ ██╗   ██║   ███████╗██║  ██║       
    ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝       
'     
PS3='Choose or Type a Plan: '
options=("OVPN/SSH-WEBSOCKET-PREMIUM" "OVPN/SSH-WEBSOCKET-VIP" "OVPN/SSH-WEBSOCKET-PRIVATE" "HYSTERIA-PURE" "SLOWDNS-PURE" "SLOWDNS/SSH-WEBSOCKET" "QUIT")
select opt in "${options[@]}"; do
case "$opt,$REPLY" in
OVPN/SSH-WEBSOCKET-PREMIUM,*|*,OVPN/SSH-WEBSOCKET-PREMIUM) 
echo "";
echo -e "                $GREEN 1) OVPN+SSH WEBSOCKET PREMIUM Selected$RESET";
sleep 2s
clear
wget -O premium "https://raw.githubusercontent.com/DexterRepositories/Panel/main/premium"
chmod +x ~/premium && sed -i -e 's/\r$//' ~/premium && ./premium
echo "";
break ;;

OVPN/SSH-WEBSOCKET-VIP,*|*,OVPN/SSH-WEBSOCKET-VIP) 
echo "";
echo -e "                $GREEN 2) OVPN+SSH WEBSOCKET VIP Selected$RESET";
sleep 2s
clear
wget -O vip "https://raw.githubusercontent.com/DexterRepositories/Panel/main/vip"
chmod +x ~/vip && sed -i -e 's/\r$//' ~/vip && ./vip
echo "";
break ;;

OVPN/SSH-WEBSOCKET-PRIVATE,*|*,OVPN/SSH-WEBSOCKET-PRIVATE) 
echo "";
echo -e "                $GREEN 3) OVPN+SSH WEBSOCKET PRIVATE Selected$RESET";
sleep 2s
clear
wget -O private "https://raw.githubusercontent.com/DexterRepositories/Panel/main/private"
chmod +x ~/private && sed -i -e 's/\r$//' ~/private && ./private
echo "";
break ;;

HYSTERIA-PURE,*|*,HYSTERIA-PURE) 
echo "";
echo -e "                $GREEN 4) HYSTERIA PURE Selected$RESET";
sleep 2s
clear
wget -O udppure "https://github.com/DexterRepositories/Hysteria/blob/main/udppure"
chmod +x ~/udppure && sed -i -e 's/\r$//' ~/udppure && ./udppure
echo "";
break ;;

SLOWDNS-PURE,*|*,SLOWDNS-PURE) 
echo "";
echo -e "                $GREEN 5) SLOWDNS PURE Selected$RESET";
sleep 2s
clear
wget -O setup "https://raw.githubusercontent.com/DexterRepositories/Slowdns/main/installer/setup"
chmod +x ~/setup && sed -i -e 's/\r$//' ~/setup && ./setup
echo "";
break ;;

SLOWDNS/SSH-WEBSOCKET,*|*,SLOWDNS/SSH-WEBSOCKET) 
echo "";
echo -e "                $GREEN 6) SLOWDNS+SSH WEBSOCKET Selected$RESET";
sleep 2s
clear
wget -O install "https://raw.githubusercontent.com/DexterRepositories/Script/main/install"
chmod +x ~/install && sed -i -e 's/\r$//' ~/install && ./install
echo "";
break ;;

QUIT,*|*,QUIT) echo -e " $RED   Installation Cancelled!$RESET";
echo -e "                $RED   Rebuild your vps and correct the process.$RESET";
rm installer.sh
exit;
break ;; *)
echo "";
echo -e "                $RED   Invalid: Just choose what you want$RESET";
esac
done
