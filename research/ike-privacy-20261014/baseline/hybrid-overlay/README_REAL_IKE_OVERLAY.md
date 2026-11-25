# Реальный IKE через overlay + штатный ESP strongSwan

Этот вариант прототипа переносит через overlay **настоящие UDP-датаграммы IKEv2** от strongSwan/charon. ESP не проксируется Python-кодом: после успешного IKE_AUTH strongSwan сам устанавливает CHILD_SA/XFRM, и пользовательский трафик идет прямым ESP-туннелем между конечными узлами.

## Что добавлено

- `ike_proxy.py` — Linux-адаптер перехвата и инжекта IKE.
- `node_daemon.py --ike-proxy` — режим, в котором daemon:
  - принимает настоящие IKE-пакеты от локального strongSwan;
  - строит маршрут `A -> X1 -> X2 -> B`;
  - передает raw UDP payload через существующий `T_PROXY_BLOB`;
  - на конечном узле инжектит payload в локальный strongSwan/charon;
  - ответы strongSwan захватывает и отправляет обратно по reverse route.
- `config.py` — параметры локального IKE-перехвата: capture-порты, charon-порты, socket mark.
- `scripts/ike_proxy_iptables_apply.sh` и `scripts/ike_proxy_iptables_clear.sh` — базовые iptables-правила для лаборатории.

## Требования

- Linux на конечных узлах, где работает strongSwan.
- Запуск от root или с `CAP_NET_ADMIN`/`CAP_NET_RAW`.
- Python 3.9+ и `cryptography`.
- strongSwan/charon продолжает слушать UDP/500 и UDP/4500.
- Overlay daemon использует свой UDP-порт из `USERS[*]["port"]`, по умолчанию 9000.

## Настройка config.py

Проверь `USERS` на всех узлах:

```python
USERS = {
    "User1": {"ip": "192.168.100.11", "port": 9000, "password": "1111"},
    "User2": {"ip": "192.168.100.12", "port": 9000, "password": "2222"},
    "User3": {"ip": "192.168.100.13", "port": 9000, "password": "3333"},
    "User4": {"ip": "192.168.100.14", "port": 9000, "password": "4444"},
}
```

Для нормального режима original-destination должен определяться ядром Linux. Если в простой двухузловой лаборатории original-dst не приходит, временно задай fallback:

```python
# На User1:
CLI: python3 node_daemon.py --name User1 --ike-proxy --ike-default-dst User2
# На User2:
CLI: python3 node_daemon.py --name User2 --ike-proxy --ike-default-dst User1
```

В четырехузловом сценарии лучше оставить пустым и добиться корректного original-dst через правила redirect/tproxy.

## Запуск

На каждом узле установи зависимости:

```bash
sudo apt install -y python3-cryptography
```

На каждом конечном узле strongSwan включи правила перехвата:

```bash
sudo bash scripts/ike_proxy_nft_apply.sh
```

Запусти daemon на всех overlay-узлах. На конечных узлах strongSwan — с `--ike-proxy`:

```bash
sudo python3 node_daemon.py --name User1 --ike-proxy
sudo python3 node_daemon.py --name User2 --ike-proxy
python3 node_daemon.py --name User3
python3 node_daemon.py --name User4
```

После этого инициируй IPsec штатно через strongSwan:

```bash
sudo swanctl --initiate --child <child-name>
```

или отправь трафик под trap-policy, если в strongSwan используется `start_action = trap`.

## Проверка

На инициаторе и получателе:

```bash
sudo swanctl --list-sas
sudo ip xfrm state
sudo ip xfrm policy
```

В логах daemon должны появиться строки:

```text
[IKE-PROXY] CAPTURE ...
[IKE-ROUTE] READY User1->User3->User4->User2 ...
[IKE-OVERLAY] SEND fwd ...
[IKE-OVERLAY] ARRIVE DST=User2 ...
[IKE-PROXY] INJECT ... -> charon 127.0.0.1:500
```

Для ESP:

```bash
sudo tcpdump -ni <iface> 'esp or udp port 4500 or udp port 500'
```

Если UDP/4500 используется для NAT-T, IKE имеет 4-байтовый Non-ESP Marker `00 00 00 00`, а ESP-in-UDP имеет ненулевой SPI. Python-прокси должен получать только IKE. ESP-in-UDP должен обходить overlay.

## Очистка firewall-правил

```bash
sudo bash scripts/ike_proxy_nft_clear.sh
```

## Важные ограничения текущей версии

1. Это Linux-режим. Windows-узлы могут оставаться overlay-релеями, но реальный strongSwan IKE-proxy рассчитан на Linux.
2. Для корректного инжекта charon должен видеть удаленный peer IP/port. Поэтому используется `IP_TRANSPARENT` и socket mark.
3. ESP не идет через Python. Если ты видишь ESP в overlay-логах — это ошибка firewall-правил. ESP должен идти напрямую после установки CHILD_SA.
4. Если `swanctl --list-sas` не показывает CHILD_SA, смотри сначала логи charon и строки `[IKE-PROXY] INJECT`.

## Fix 2026-05-06: NO_SESSION_NEXT при PROXY
Если промежуточный узел получает PROXY_BLOB и у него еще нет management-сессии со следующим hop, сессия теперь создается в отдельном worker-потоке. Это важно: основной UDP dispatcher не должен блокироваться в ensure_session(), иначе он сам не сможет принять INIT_RESP от следующего узла и появится ложная ошибка NO_SESSION_NEXT.
