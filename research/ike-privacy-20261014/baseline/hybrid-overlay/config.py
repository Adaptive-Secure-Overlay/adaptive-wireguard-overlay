# -*- coding: utf-8 -*-

import os
from typing import Dict

USER13_OVERLAY_IP = os.environ.get("USER13_OVERLAY_IP", "192.168.95.129").strip()

# ЕДИНЫЙ справочник пользователей (это же узлы сети)
# >>> СЮДА ВБИВАЕШЬ IP <<<
USERS: Dict[str, dict] = {
    "User1": {"ip": "192.168.101.10", "port": 9000, "password": "1111"},
    "User2": {"ip": "192.168.102.10", "port": 9000, "password": "2222"},
    "User3": {"ip": "192.168.103.10", "port": 9000, "password": "3333"},
    "User4": {"ip": "192.168.104.10", "port": 9000, "password": "4444"},
    "User5": {"ip": "192.168.105.10", "port": 9000, "password": "5555"},
    "User6": {"ip": "192.168.106.10", "port": 9000, "password": "6666"},
    "User7": {"ip": "192.168.107.10", "port": 9000, "password": "7777"},
    "User8": {"ip": "192.168.108.10", "port": 9000, "password": "8888"},
    "User9": {"ip": "192.168.109.10", "port": 9000, "password": "9999"},
    "User10": {"ip": "192.168.110.10", "port": 9000, "password": "1010"},
    "User11": {"ip": "10.255.11.2", "port": 9000, "password": "11111"},
    "User12": {"ip": "10.255.12.2", "port": 9000, "password": "121212"},
    "User13": {
        "ip": "192.168.113.199",
        "overlay_ip": USER13_OVERLAY_IP or "192.168.113.199",
        "port": 9000,
        "password": "131313",
        "sidecar_inject": True,
    },
}

_active_users_env = os.environ.get("OVERLAY_ACTIVE_USERS", "").strip()
if _active_users_env:
    ACTIVE_USERS = [
        name.strip()
        for name in _active_users_env.split(",")
        if name.strip() in USERS
    ]
    if not ACTIVE_USERS:
        ACTIVE_USERS = list(USERS.keys())
else:
    ACTIVE_USERS = list(USERS.keys())

# Сетевые параметры
UDP_TIMEOUT_S = 2.0
RETRIES = 3
PRECONNECT_ENABLED = os.environ.get("PRECONNECT_ENABLED", "1").lower() not in ("0", "false", "no", "off")

# Полезная нагрузка
I3_LEN = 24

# Предварительные mgmt-сессии включены для full-mesh лаборатории:
# промежуточные узлы уже имеют crypto-session до прихода первого IKE-response.

# =========================
# Реальный IKE -> overlay -> strongSwan adapter
# =========================
# По умолчанию выключено: включается флагом node_daemon.py --ike-proxy.
IKE_PROXY_ENABLED = False

# UDP/500 и UDP/4500 должны быть перенаправлены firewall-правилами на локальные порты.
# Сам strongSwan/charon продолжает слушать штатные 500/4500.
IKE_CAPTURE_BIND = "0.0.0.0"

# Старые общие capture-порты оставлены для совместимости с двухузловой схемой.
IKE_CAPTURE_PORTS = {500: 15000, 4500: 15001}

# Full-mesh режим: nft перенаправляет IKE к разным получателям на разные
# локальные порты. Так адаптер понимает dst_user даже если REDIRECT прячет
# original destination как 127.0.0.1.
IKE_CAPTURE_USER_PORTS = {
    500: {
        "User1": 15101,
        "User2": 15102,
        "User3": 15103,
        "User4": 15104,
        "User5": 15105,
        "User6": 15106,
        "User7": 15107,
        "User8": 15108,
        "User9": 15109,
        "User10": 15110,
        "User11": 15111,
        "User12": 15112,
        "User13": 15113,
    },
    4500: {
        "User1": 15201,
        "User2": 15202,
        "User3": 15203,
        "User4": 15204,
        "User5": 15205,
        "User6": 15206,
        "User7": 15207,
        "User8": 15208,
        "User9": 15209,
        "User10": 15210,
        "User11": 15211,
        "User12": 15212,
        "User13": 15213,
    },
}

# Куда инжектить восстановленные IKE-пакеты внутри локальной машины.
IKE_CHARON_HOST = "127.0.0.1"
IKE_CHARON_PORTS = {500: 500, 4500: 4500}

# Метка сокетов адаптера. Ее надо исключать в firewall-правилах, чтобы не получить петлю.
IKE_SOCKET_MARK = 0x53

# Для корректной подстановки удаленного src_ip:src_port strongSwan требуется IP_TRANSPARENT.
IKE_TRANSPARENT_INJECT_REQUIRED = True

# Fallback для простой двухузловой лаборатории, если firewall не отдает original-dst.
# Например: "User2" на User1 и "User1" на User2. В нормальной схеме оставь пустым.
IKE_PROXY_DEFAULT_DST_USER = os.environ.get("IKE_PROXY_DEFAULT_DST_USER", "").strip()

# Сколько ждать построения overlay-маршрута для первой IKE-датаграммы.
IKE_ROUTE_TIMEOUT_S = 10.0

# Маршрут кешируется только на время одного IKE-обмена, чтобы IKE_SA_INIT и
# IKE_AUTH шли одинаковым путем. Новая установка после TTL снова выбирает X1/X2.
IKE_ROUTE_CACHE_TTL_S = float(os.environ.get("IKE_ROUTE_CACHE_TTL_S", "120"))

# Inline/on-the-fly route must fail fast.  If A sent the first IKE packet to X1
# and no reverse response/READY arrived before this timeout, the partial route
# is invalidated and the next IKE retransmit picks a fresh X1.
IKE_INLINE_ROUTE_TIMEOUT_S = float(os.environ.get("IKE_INLINE_ROUTE_TIMEOUT_S", "5"))

# Temporary circuit breaker for a peer that failed route construction.
IKE_ROUTE_COOLDOWN_S = float(os.environ.get("IKE_ROUTE_COOLDOWN_S", "30"))

# Experimental privacy/on-demand overlay mode:
# - A does not disclose final dst=B to X1 while selecting X2.
# - X1 forwards opaque A->X2 bundles and only knows A/X2.
# - X2 learns B and IKE payload, but the initiator locator is sealed by X1
#   for B over a per-connection X25519 X1-B exchange proxied through X2.
IKE_PRIVACY_OVERLAY = os.environ.get("IKE_PRIVACY_OVERLAY", "0").lower() in ("1", "true", "yes", "on")

# Inline/on-the-fly privacy mode:
# - the first captured IKE packet is sent immediately to X1;
# - X1 selects/connects X2 and forwards the selected sealed capsule;
# - A receives the real IKE response from B, not a separate "route ready" ack.
IKE_PRIVACY_INLINE = os.environ.get("IKE_PRIVACY_INLINE", "0").lower() in ("1", "true", "yes", "on")

# Experimental MCC (multiple start connections) mode from dissertation section 2.1.
# It is intentionally opt-in: ordinary overlay operation remains unchanged.
IKE_MCC_ENABLED = os.environ.get("IKE_MCC_ENABLED", "0").lower() in ("1", "true", "yes", "on")

try:
    IKE_MCC_FANOUT = max(1, int(os.environ.get("IKE_MCC_FANOUT", "2")))
except ValueError:
    IKE_MCC_FANOUT = 2

try:
    IKE_MCC_X1_FANOUT = max(1, int(os.environ.get("IKE_MCC_X1_FANOUT", str(IKE_MCC_FANOUT))))
except ValueError:
    IKE_MCC_X1_FANOUT = IKE_MCC_FANOUT

try:
    IKE_MCC_X2_FANOUT = max(1, int(os.environ.get("IKE_MCC_X2_FANOUT", str(IKE_MCC_FANOUT))))
except ValueError:
    IKE_MCC_X2_FANOUT = IKE_MCC_FANOUT

try:
    IKE_MCC_IKE_FANOUT = max(1, int(os.environ.get("IKE_MCC_IKE_FANOUT", str(IKE_MCC_X2_FANOUT))))
except ValueError:
    IKE_MCC_IKE_FANOUT = IKE_MCC_X2_FANOUT

try:
    IKE_MCC_ROUTE_TIMEOUT_S = float(os.environ.get("IKE_MCC_ROUTE_TIMEOUT_S", str(IKE_ROUTE_TIMEOUT_S)))
except ValueError:
    IKE_MCC_ROUTE_TIMEOUT_S = IKE_ROUTE_TIMEOUT_S

try:
    IKE_MCC_ACCEPT_WINDOW_S = max(0.0, float(os.environ.get("IKE_MCC_ACCEPT_WINDOW_S", "0")))
except ValueError:
    IKE_MCC_ACCEPT_WINDOW_S = 0.0
