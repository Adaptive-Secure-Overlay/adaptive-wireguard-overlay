# Debian 13 / strongSwan 6.0.1 запуск real-IKE overlay

Проверенный целевой профиль для лаборатории:

```text
Debian 13.x trixie, amd64
strongSwan 6.0.1 из Debian 13
Python 3.11+
Linux kernel 6.x
nftables
```

## 1. Пакеты

На User1 и User2, где будет strongSwan:

```bash
sudo apt update
sudo apt install -y python3 python3-cryptography nftables tcpdump iproute2 charon-systemd strongswan-swanctl strongswan-pki
```

На User3 и User4, которые только overlay-релеи:

```bash
sudo apt update
sudo apt install -y python3 python3-cryptography tcpdump iproute2
```

Важно: для swanctl-схемы используй `charon-systemd` + `strongswan-swanctl`, а не одновременно legacy starter.

## 2. IP-адреса в этой сборке

`config.py` уже выставлен под текущую LAN-схему:

```text
User1 = 192.168.100.11
User2 = 192.168.100.12
User3 = 192.168.100.13
User4 = 192.168.100.14
Overlay UDP port = 9000
```

Если DHCP выдал другие адреса, поправь `USERS` в `config.py` одинаково на всех четырех ВМ.

## 3. strongSwan

Сначала добей прямой IPsec без overlay. Это обязательный контрольный тест:

```bash
sudo swanctl --load-all
sudo swanctl --initiate --child <child-name>
sudo swanctl --list-sas
sudo ip xfrm state
sudo ip xfrm policy
```

Только после этого включай IKE-overlay.

## 4. Firewall-перехват IKE

На Debian 13 предпочтительно использовать nftables-скрипт:

```bash
sudo bash scripts/ike_proxy_nft_apply.sh
```

Он перенаправляет:

```text
UDP/500 -> 15000
UDP/4500 только если первые 4 байта UDP payload = 00 00 00 00, то есть IKE Non-ESP Marker
ESP-in-UDP с ненулевым SPI не перенаправляется
```

Откат:

```bash
sudo bash scripts/ike_proxy_nft_clear.sh
```

Fallback через iptables есть, но для Debian 13 лучше nft:

```bash
sudo bash scripts/ike_proxy_iptables_apply.sh
sudo bash scripts/ike_proxy_iptables_clear.sh
```

## 5. Запуск overlay

На User1:

```bash
sudo python3 node_daemon.py --name User1 --ike-proxy --ike-default-dst User2
```

На User2:

```bash
sudo python3 node_daemon.py --name User2 --ike-proxy --ike-default-dst User1
```

На User3:

```bash
python3 node_daemon.py --name User3
```

На User4:

```bash
python3 node_daemon.py --name User4
```

После этого инициируй соединение на User1:

```bash
sudo swanctl --initiate --child <child-name>
```

## 6. Что считать успехом

В логах overlay должны появиться строки вида:

```text
[IKE-PROXY] CAPTURE ...
[IKE-ROUTE] READY User1->User3->User4->User2 ...
[IKE-OVERLAY] ARRIVE DST=User2 ...
[IKE-PROXY] INJECT ... -> charon 127.0.0.1:500
```

В strongSwan:

```bash
sudo swanctl --list-sas
```

должны появиться `IKE_SA` и `CHILD_SA`.

В ядре:

```bash
sudo ip xfrm state
sudo ip xfrm policy
```

должны появиться SA и политики.

ESP проверяй так:

```bash
sudo tcpdump -ni <iface> 'esp or udp port 4500 or udp port 500'
```

## 7. Ограничение текущей реализации

Эта сборка не является плагином strongSwan. Это внешний transparent-adapter. Поэтому первый запуск на Debian 13/strongSwan 6.0.1 надо считать интеграционным тестом. Если `IKE_SA` появляется, а `CHILD_SA` нет, смотри логи `charon` и `[IKE-PROXY] INJECT`.
