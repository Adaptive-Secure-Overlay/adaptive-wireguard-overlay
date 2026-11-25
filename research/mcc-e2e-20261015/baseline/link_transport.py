"""Existing LegacyWorkspace LINK_FRAG port; bounded, no acknowledgement added.
Wire chunks are base64 frames <=1200 bytes, below the existing 1500-byte MTU.
Reassembly precedes the unchanged hop AEAD verification. Shared lab config is unchanged.
"""
import base64
import secrets
import time
from typing import Optional
from protocol import jdump, jload
T_LINK_FRAG = 'LINK_FRAG'
LINK_FRAG_MAX_WIRE = 1200
LINK_FRAG_CHUNK_BYTES = 700
LINK_FRAG_TTL_S = 15

class LinkTransportMixin:
    def _init_link_transport(self):
        self.link_frag_buf = {}

    def send_peer(self, peer: str, payload: bytes):
        if peer == self.name:
            self.logger.error(f"[BUG] attempt to send to self peer={peer} DROP")
            return
        if len(payload) <= LINK_FRAG_MAX_WIRE:
            self._send_peer_raw(peer, payload)
            return
        frag_id = secrets.token_hex(8)
        if len(payload) > 65507:
            raise ValueError('Overlay message exceeds bounded transport size')
        chunks = [payload[i:i + LINK_FRAG_CHUNK_BYTES] for i in range(0, len(payload), LINK_FRAG_CHUNK_BYTES)]
        total = len(chunks)
        self.logger.debug(
            f"[LINK/FRAG] send peer={peer} bytes={len(payload)} fragments={total} "
            f"chunk={LINK_FRAG_CHUNK_BYTES} frag={frag_id}"
        )
        for seq, chunk in enumerate(chunks):
            frag = {
                "t": T_LINK_FRAG,
                "from": self.name,
                "to": peer,
                "frag_id": frag_id,
                "seq": seq,
                "total": total,
                "data": base64.b64encode(chunk).decode("ascii"),
            }
            self._send_peer_raw(peer, jdump(frag))

    def _handle_link_frag(self, p: dict, peer: str) -> Optional[bytes]:
        if not peer or p.get("from") != peer or p.get("to") != self.name:
            self.logger.warning(f"[LINK/FRAG] drop invalid endpoint peer={peer} from={p.get('from')} to={p.get('to')}")
            return None
        try:
            frag_id = str(p.get("frag_id", ""))
            seq = int(p.get("seq", -1))
            total = int(p.get("total", 0))
            data = base64.b64decode(str(p.get("data", "")).encode("ascii"), validate=True)
        except Exception as e:
            self.logger.warning(f"[LINK/FRAG] bad fragment from={peer}: {e}")
            return None
        if not frag_id or total <= 0 or seq < 0 or seq >= total or total > 94 or len(data) > 700 or len(frag_id) != 16:
            self.logger.warning(f"[LINK/FRAG] invalid fragment header from={peer} frag={frag_id} seq={seq}/{total}")
            return None
        now = time.time()
        key = f"{peer}:{frag_id}"
        with self.lock:
            for old_key, entry in list(self.link_frag_buf.items()):
                if now - float(entry.get("created_at", now)) > LINK_FRAG_TTL_S:
                    self.link_frag_buf.pop(old_key, None)
            if key not in self.link_frag_buf and len(self.link_frag_buf) >= 32:
                return None
            entry = self.link_frag_buf.setdefault(key, {"created_at": now, "total": total, "parts": {}})
            if int(entry.get("total", total)) != total:
                self.link_frag_buf.pop(key, None)
                self.logger.warning(f"[LINK/FRAG] total mismatch from={peer} frag={frag_id}")
                return None
            previous = entry['parts'].get(seq)
            if previous is not None and previous != data:
                self.link_frag_buf.pop(key, None)
                return None
            entry["parts"][seq] = data
            if len(entry["parts"]) < total:
                return None
            parts = entry["parts"]
            self.link_frag_buf.pop(key, None)
        try:
            assembled = b"".join(parts[i] for i in range(total))
        except KeyError:
            return None
        self.logger.debug(f"[LINK/FRAG] reassembled from={peer} bytes={len(assembled)} fragments={total} frag={frag_id}")
        if len(assembled) > 65507:
            return None
        try:
            if jload(assembled).get('t') == T_LINK_FRAG:
                return None
        except (ValueError, AttributeError):
            return None
        return assembled
