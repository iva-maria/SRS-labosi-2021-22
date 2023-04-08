#! /bin/sh

IPT=/sbin/iptables

$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

$IPT -F INPUT
$IPT -F OUTPUT
$IPT -F FORWARD

$IPT -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# 
# za potrebe testiranja dozvoljen je ICMP (ping i sve ostalo)
#
$IPT -A INPUT   -p icmp -j ACCEPT
$IPT -A FORWARD -p icmp -j ACCEPT
$IPT -A OUTPUT  -p icmp -j ACCEPT


# ================ Dodajte ili modificirajte pravila na oznacenim mjestima #
# "anti spoofing" (eth0)
#
$IPT -A INPUT   -i eth0 -s 127.0.0.0/8  -j DROP
$IPT -A FORWARD -i eth0 -s 127.0.0.0/8  -j DROP
#
# <--- Dodajte ili modificirajte pravila
$IPT -A INPUT	-i eth0 -s 203.0.113.1/24	-m state --state NEW -j DROP
$IPT -A INPUT	-i eth0 -s 10.0.0.1/24		-m state --state NEW -j DROP

#
# racunala iz lokalne mreze (LAN) imaju neograniceni pristup posluziteljima u DMZ i Internetu
#
# <--- Dodajte pravila
$IPT -A FORWARD -i eth1	-s 10.0.0.0/24	-d 192.0.2.0/24		-o eth0	-j ACCEPT
$IPT -A FORWARD -i eth1	-s 10.0.0.0/24	-d 203.0.113.0/24	-o eth2	-j ACCEPT

#
# iz vanjske mreze (Interneta) dozvoljen je pristup posluzitelju server u DMZ korištenjem 
# protokola SSH (tcp port 22) i DNS (udp i tcp port 53)
#
# <--- Dodajte pravila
$IPT -A FORWARD	-p tcp	-i eth0	-s 192.0.2.0/24	-d 203.0.113.10	-o eth2	--dport ssh	-j ACCEPT
$IPT -A FORWARD -p udp	-i eth0	-s 192.0.2.0/24 -d 203.0.113.10	-o eth2	--dport 53	-j ACCEPT
$IPT -A FORWARD	-p tcp	-i eth0	-s 192.0.2.0/24 -d 203.0.113.10 -o eth2	--dport 53	-j ACCEPT

#
# pristup iz vanjske mreze i DMZ u lokalnu LAN mrezu je zabranjen, dozvoljen je samo 
# pristup posluzitelju host (u LAN-u) s posluzitelja server (u DMZ) korištenjem protokola SSH
#
# <--- Dodajte pravila
$IPT -A FORWARD	-i eth0	-o eth1	-s 192.0.2.0/24		-d 10.0.0.0/24	-j DROP
$IPT -A FORWARD	-i eth2	-o eth1	-s 203.0.113.0/24	-d 10.0.0.0/24	-j DROP
$IPT -A FORWARD	-p tcp	-i eth2	-o eth1	-s 203.0.113.10/24	-d 10.0.0.11/24 --dport ssh	-j ACCEPT

#
# s posluzitelja server je dozvoljen pristup DNS posluziteljima u Internetu (UDP i TCP port 53)
#
# <--- Dodajte pravila
$IPT -A FORWARD	-p udp	-i eth2	-s 203.0.113.10	-d 192.0.2.0/24	-o eth0	--dport 53	-j ACCEPT
$IPT -A FORWARD -p tcp	-i eth2	-s 203.0.113.10	-d 192.0.2.0/24	-o eth0	--dport 53	-j ACCEPT

#
# SSH pristup vatrozidu firewall je dozvoljen samo s računala admin (LAN)
#
# <--- Dodajte pravila
$IPT -A INPUT	-i eth1	-p tcp	-s 10.0.0.10	--dport 22	-m state --state NEW,ESTABLISHED	-j ACCEPT
$IPT -A OUTPUT	-o eth1	-p tcp	--sport 22	-m state --state ESTABLISHED	-j ACCEPT


