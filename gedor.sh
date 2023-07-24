sudo apt update && sudo apt install iptables ipset netfilter-persistent nftables
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -t raw -F
iptables -N SAMP-DDOS
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p tcp --syn -m limit --limit 2/s --limit-burst 30 -j ACCEPT
iptables -A INPUT -p udp -s 0/0 -i ppp0 --dport 7777 -j DROP
iptables -A INPUT -p ICMP --icmp-type echo-request -m length --length 60:65535 -j ACCEPT
iptables -A FORWARD -p icmp --icmp-type echo-request -m connlimit --connlimit 1/s -j accept
iptables -A FORWARD -p icmp --icmp-type echo-request -j DROP
iptables -A INPUT -p udp --dport 7777 -i eth0 -m state --state NEW -m recent --update --seconds 3 --hitcount 3 -j DROP
iptables -t nat -A PREROUTING -p udp --dport 7777 -s 127.0.0.1 -m string --algo bm --string 'SAMP' -j REDIRECT --to-port 7777
iptables -t nat -A PREROUTING -p udp --dport 7777 -m string --algo bm --string 'SAMP' -j REDIRECT --to-port 7777
iptables -I INPUT -p udp --dport 7777 -m string --algo bm --string 'SAMP' -m hashlimit ! --hashlimit-upto 3/sec --hashlimit-burst 3/sec --hashlimit-mode srcip --hashlimit-name query -j DROP
iptables -I INPUT -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|081e77da|' -m recent --name test ! --rcheck  -m recent --name test --set   -j  DROP
iptables -I INPUT -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|081e77da|'  -m recent --name test --rcheck --seconds 2  --hitcount 1     -j DROP 
iptables -I INPUT  -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e63|'  -m recent --name limitC7777 ! --rcheck  -m recent --name limitC7777 --set -j DROP
iptables -I INPUT  -p udp --dport 7777   -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e63|' -m recent --name limitC7777 --rcheck  --seconds 2 --hitcount 1   -j DROP
iptables -I INPUT  -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e69|'  -m recent --name limitI7777 ! --rcheck  -m recent --name limitI7777 --set 
iptables -I INPUT  -p udp --dport 7777   -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e69|' -m recent --name limitI7777 --rcheck  --seconds 2 --hitcount 1   -j DROP
iptables -I INPUT  -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e72|'  -m recent --name limitR7777 ! --rcheck  -m recent --name limitR7777 --set -j DROP
iptables -I INPUT -p udp --dport 7777 -m string --algo kmp --hex-string '|53414d50|' -m string --algo kmp --hex-string '|611e72|' -m recent --name limitR7777 --rcheck --seconds 2 --hitcount 1 -j DROP
iptables -I INPUT -p tcp -m state --state NEW --dport 80 -m recent \
--name slowloris --set
iptables -I INPUT -p tcp -m state --state NEW --dport 80 -m recent \
--name slowloris --update --seconds 15 --hitcount 10 -j DROP
iptables -A INPUT -p udp --dport 7777-m ttl --ttl-eq=128-j SAMP-DDOS 
iptables -A SAMP-DDOS -p udp --dport 7777-m length --length 17:604-j DROP
iptables -A INPUT -p udp --dport 7777 -m limit --limit 1/s --limit-burst 1 -j REJECT
iptables -A INPUT -p udp --dport 7777 -m limit --limit 1/s --limit-burst 2 -j DROP
iptables -A INPUT -p udp --dport 7777 -m geoip ! --src-cc ID,MY -j REJECT
iptables -A INPUT -p udp --dport 7777 -m geoip ! --src-cc ID,MY -j DROP
iptables -A INPUT -p udp --dport 7777 -m geoip ! --src-cc US,CN,SG -j REJECT
iptables -A INPUT -p udp --dport 7777 -m geoip ! --src-cc US,CN,SG -j DROP
iptables -A OUTPUT -p udp --dport 7777 -m geoip ! --src-cc ID,MY -j REJECT
iptables -A OUTPUT -p udp --dport 7777 -m geoip ! --src-cc ID,MY -j DROP
iptables -A OUTPUT -p udp --dport 7777 -m geoip ! --src-cc US,CN,SG -j REJECT
iptables -A OUTPUT -p udp --dport 7777 -m geoip ! --src-cc US,CN,SG -j DROP
iptables -A FORWARD -p udp --dport 7777 -m geoip ! --src-cc ID,MY -j REJECT
iptables -A FORWARD -p udp --dport 7777 -m geoip ! --src-cc ID,MY -j DROP
iptables -A FORWARD -p udp --dport 7777 -m geoip ! --src-cc US,CN,SG -j REJECT
iptables -A FORWARD -p udp --dport 7777 -m geoip ! --src-cc US,CN,SG -j DROP
iptables -A INPUT -p udp --dport 30000:65535 -m geoip ! --src-cc ID,MY,US,CN,SC -j REJECT
iptables -A INPUT -p udp --dport 1:7776 -j REJECT
iptables -A INPUT -p udp --dport 7778:30000 -j REJECT
iptables -t nat -A PREROUTING -p udp --dport 7777 -s 127.0.0.1 -m string --algo bm --string 'SAMP' -j REDIRECT --to-port 7777
iptables -t nat -A PREROUTING -p udp --dport 7777 -m string --algo bm --string 'SAMP' -j REDIRECT --to-port 7777
iptables -I INPUT -p udp --dport 7777 -m string --algo bm --string 'SAMP' -m hashlimit ! --hashlimit-upto 3/sec --hashlimit-burst 3/sec --hashlimit-mode srcip --hashlimit-name query -j DROP
iptables -I INPUT -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|081e77da|' -m recent --name test ! --rcheck  -m recent --name test --set   -j  DROP
iptables -I INPUT -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|081e77da|'  -m recent --name test --rcheck --seconds 2  --hitcount 1     -j DROP 
iptables -I INPUT  -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e63|'  -m recent --name limitC7777 ! --rcheck  -m recent --name limitC7777 --set -j DROP
iptables -I INPUT  -p udp --dport 7777   -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e63|' -m recent --name limitC7777 --rcheck  --seconds 2 --hitcount 1   -j DROP
iptables -I INPUT  -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e69|'  -m recent --name limitI7777 ! --rcheck  -m recent --name limitI7777 --set 
iptables -I INPUT  -p udp --dport 7777   -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e69|' -m recent --name limitI7777 --rcheck  --seconds 2 --hitcount 1   -j DROP
iptables -I INPUT  -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e72|'  -m recent --name limitR7777 ! --rcheck  -m recent --name limitR7777 --set -j DROP
iptables -I INPUT -p udp --dport 7777 -m string --algo kmp --hex-string '|53414d50|' -m string --algo kmp --hex-string '|611e72|' -m recent --name limitR7777 --rcheck --seconds 2 --hitcount 1 -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|f8f9fafbfcfdfeff|" -j DROP  
iptables -A INPUT -p udp -m string --algo bm --hex-string "|f1f2f3f4f5f6f7|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|eaebecedeeeff0|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|e3e4e5e6e7e8e9|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|dcdddedfe0e1e2|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|d5d6d7d8d9dadb|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|cecfd0d1d2d3d4|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|65666768696a6b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|a4a5a6a7a8a9aa|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|abacadaeafb0b1|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|c0c1c2c3c4c5c6|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|b9babbbcbdbebf|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|b2b3b4b5b6b7b8|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|9d9e9fa0a1a2a3|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|969798999a9b9c|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|8f909192939495|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|88898a8b8c8d8e|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|81828384858687|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|7a7b7c7d7e7f80|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|73747576777879|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|5e5f6061626364|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|5758595a5b5c5d|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|50515253545556|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|494a4b4c4d4e4f|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|42434445464748|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|3b3c3d3e3f4041|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|3435363738393a|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|2d2e2f30313233|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|262728292a2b2c|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|1f202122232425|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|11121314151617|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|0a0b0c0d0e0f10|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|03040506070809|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|58992158992158992158992158992158992158992158992158992158992158992158992158992158992158992158992158|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|18191a1b1c1d1e|" -j DROP
echo "Block spoofed"
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP
iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP
iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
echo "Block invalid packet"
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -t raw -I PREROUTING -p udp ! --sport 1:65535 -j DROP
iptables -t raw -I PREROUTING -p tcp ! --sport 1:65535 -j DROP
iptables -t raw -I PREROUTING -p udp -m limit --limit 4/s -j ACCEPT
iptables -t raw -A PREROUTING -p udp -j DROP
echo "Block udp packet"
iptables -t raw -A PREROUTING -p udp --sport 123 -m limit --limit 2/s --limit-burst 1 -j ACCEPT
iptables -t raw -A PREROUTING -p udp --sport 53 -m limit --limit 4/s --limit-burst 10 -j ACCEPT
iptables -t raw -A PREROUTING -p udp -m multiport --sports 53,123,17185,7001,9000 -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6" -j DROP
iptables -t raw -I PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED -j DROP
iptables -t raw -I PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED -j DROP
iptables -t raw -I PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED -j DROP
iptables -t raw -I PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED -j DROP
iptables -t raw -A PREROUTING -p udp -m u32 --u32 "2&0xFFFF=0x2:0x0100" -j DROP
iptables -t raw -A PREROUTING -p udp -m u32 --u32 "12&0xFFFFFF00=0xC0A80F00" -j DROP
iptables -t raw -A PREROUTING -p tcp -syn -m length --length 52 u32 --u32 "12&0xFFFFFF00=0xc838" -j DROP
iptables -t raw -A PREROUTING -p udp -m length --length 28 -m string --algo bm --string "0x0010" -j DROP
iptables -t raw -A PREROUTING -p udp -m length --length 28 -m string --algo bm --string "0x0000" -j DROP
iptables -t raw -A PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0x0020" -j DROP
iptables -t raw -A PREROUTING -p tcp -m length --length 40 -m string --algo bm --string "0x0c54" -j DROP
iptables -t raw -A PREROUTING -p tcp --tcp-flags ACK ACK -m length --length 52 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED -j DROP
iptables -t mangle -A PREROUTING -p tcp -syn -m length --length 52 -m string --algo bm --string "0xc838" -m state --state ESTABLISHED -j DROP
iptables -t raw -I PREROUTING -m pkttype --pkt-type broadcast -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "CRI" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "ddos" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "flood" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "HACKED" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "0x00000" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --string "0x000000000001" -j DROP
iptables -t raw -A PREROUTING -m ipv4options --ssrr -j DROP 
echo "Block all payload"
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|424f4f5445524e4554|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|41545441434b|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|504r574552|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|6c6e6f6172656162756e6386f6673b694464696573|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|736b6954|" -j DROP
iptables -t raw -A PREROUTING -p udp -m string --algo bm --hex-string "|736b69646e6574|" -j DROP
iptables -t raw -A PREROUTING -p udp -m multiport --dports 16000:29000,"$SSH" -m string --to 75 --algo bm --string 'HTTP/1.1 200 OK' -j DROP
iptables -t raw -A PREROUTING -p udp --dport 16000:29000 -m string --to 75 --algo bm --string 'HTTP/1.1 200 OK' -j DROP
iptables -t raw -A PREROUTING -p udp -m udp -m string --hex-string "|7374640000000000|" --algo kmp --from 28 --to 29 -j DROP
iptables -t raw -A PREROUTING -p udp -m u32 --u32 "6&0xFF=0,2:5,7:16,18:255" -j DROP
iptables -t raw -A PREROUTING -m u32 --u32 "12&0xFFFF=0xFFFF" -j DROP
iptables -t raw -A PREROUTING -m u32 --u32 "28&0x00000FF0=0xFEDFFFFF" -j DROP
iptables -t raw -A PREROUTING -m string --algo bm --from 28 --to 29 --string "farewell" -j DROP
iptables -t raw -A PREROUTING -p udp -m udp -m string --hex-string "|53414d50|" --algo kmp --from 28 --to 29 -j DROP
echo "Block tcp packet"
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
echo "Block shodan ip"
ipset create blacklist nethash hashsize 260000
ipset add blacklist 240.0.0.0/5
ipset add blacklist 162.142.125.0/24
ipset add blacklist 167.94.138.0/24
ipset add blacklist 198.20.69.0/24
ipset add blacklist 198.20.70.114
ipset add blacklist 93.120.27.62
ipset add blacklist 66.240.236.119
ipset add blacklist 66.240.205.34
ipset add blacklist 198.20.99.130
ipset add blacklist 71.6.135.131
ipset add blacklist 66.240.192.138
ipset add blacklist 71.6.167.142
ipset add blacklist 82.221.105.0/24
ipset add blacklist 71.6.165.200
ipset add blacklist 188.138.9.50
ipset add blacklist 85.25.103.50
ipset add blacklist 85.25.43.94
ipset add blacklist 71.6.146.185
ipset add blacklist 71.6.158.166
ipset add blacklist 198.20.87.98
ipset add blacklist 185.163.109.66
ipset add blacklist 94.102.49.0/24
ipset add blacklist 104.131.0.69
ipset add blacklist 104.236.198.48
ipset add blacklist 155.94.222.0/24
ipset add blacklist 155.94.254.0/24
ipset add blacklist 162.142.125.0/24
ipset add blacklist 167.94.138.0/24
ipset add blacklist 167.94.145.0/24
ipset add blacklist 167.94.146.0/24
ipset add blacklist 167.248.133.0/24
ipset add blacklist 2602:80d:1000:b0cc:e::/80
ipset add blacklist 2620:96:e000:b0cc:e::/80
iptables-nft -t raw -A PREROUTING -m set --match-set blacklist src -j DROP
echo "Filter All port"
iptables -A INPUT -p tcp -s 114.10.118.228 --dport 53 -j ACCEPT
iptables -A INPUT -p udp -s 114.10.118.228 --dport 53 -j ACCEPT
iptables -A INPUT -p tcp -s 114.10.118.228 --dport 80 -j ACCEPT
iptables -A INPUT -p udp -s 0.0.0.0/0 --dport 53 -j REJECT
iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 53 -j REJECT
iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 80 -j REJECT
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
echo "Anti Ddos Setup Done"
iptables-save