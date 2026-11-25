from __future__ import annotations

import csv
import io
import json

from .engine import HandshakeOverlayEngine
from .models import Endpoint, Event, OverlayEnvelope
from .routing import RouteCache


_DISJOINT_PAIRS = ((1, 2), (3, 4), (5, 6), (7, 8), (9, 10))
SCENARIO_PAIRS: dict[str, tuple[tuple[int, int], ...]] = {
    "bidir12": ((1, 2), (2, 1)),
    "disjoint5": _DISJOINT_PAIRS,
    "ring10": tuple((node, node % 10 + 1) for node in range(1, 11)),
    "reverse5": tuple(pair for a, b in _DISJOINT_PAIRS for pair in ((a, b), (b, a))),
}

RESULT_FIELDS = (
    "scenario",
    "src",
    "dst",
    "conn_id",
    "model_ok",
    "overlay_control_packets",
    "direct_wg_control_packets",
    "direct_transport_packets",
    "injected_control_packets",
    "route",
    "x1",
    "x2",
    "error",
)


def _packet(kind: int, index: int) -> bytes:
    size = {1: 148, 2: 92, 3: 64, 4: 32}[kind]
    packet = bytearray(size)
    packet[0] = kind
    packet[4:8] = index.to_bytes(4, "little")
    if kind == 2:
        packet[8:12] = (index + 1).to_bytes(4, "little")
    return bytes(packet)


def _walk_control(
    engine: HandshakeOverlayEngine,
    cache: RouteCache,
    source: Endpoint,
    destination: Endpoint,
    packet: bytes,
    now: float,
) -> tuple[list[Event], tuple[Endpoint, ...]]:
    events = list(engine.capture(source, destination, packet, now))
    route = cache.get(source, destination, now)
    if route is None or events[0].kind != "OVERLAY_FRAME":
        return events, ()
    message_id = engine.fingerprint(packet, source, destination)
    for hop_index in range(len(route.nodes) - 1):
        envelope = OverlayEnvelope(message_id, route, hop_index, packet)
        events.extend(engine.advance(envelope, now))
    return events, route.nodes


def run_scenarios() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    sequence = 1
    for scenario, pairs in SCENARIO_PAIRS.items():
        cache = RouteCache(60.0)
        relay_a = Endpoint("X1", 51820)
        relay_b = Endpoint("X2", 51820)
        engine = HandshakeOverlayEngine(cache, (relay_a, relay_b), privacy_mode=True)
        for ordinal, (src_number, dst_number) in enumerate(pairs, start=1):
            source = Endpoint(f"User{src_number}", 51820)
            destination = Endpoint(f"User{dst_number}", 51820)
            initiation = _packet(1, sequence)
            response = _packet(2, sequence + 1000)
            transport = _packet(4, sequence + 2000)
            sequence += 1

            forward_events, route = _walk_control(engine, cache, source, destination, initiation, 0.0)
            reverse_events, reverse_route = _walk_control(engine, cache, destination, source, response, 0.0)
            transport_event = engine.capture(source, destination, transport, 0.0)[0]
            relay_frames = [
                event
                for event in (*forward_events, *reverse_events)
                if event.kind == "OVERLAY_FRAME"
            ]
            injections = [
                event
                for event in (*forward_events, *reverse_events)
                if event.kind == "INJECT"
            ]
            route_shape_ok = (
                len(route) == 4
                and route[0] == source
                and route[-1] == destination
                and set(route[1:-1]) == {relay_a, relay_b}
            )
            model_ok = (
                route_shape_ok
                and reverse_route == tuple(reversed(route))
                and len(injections) == 2
                and injections[0].node == destination.label()
                and injections[1].node == source.label()
                and transport_event.kind == "DIRECT_BYPASS"
                and all(event.route == () for event in relay_frames)
            )
            rows.append(
                {
                    "scenario": scenario,
                    "src": source.host,
                    "dst": destination.host,
                    "conn_id": f"{scenario}-{ordinal:02d}",
                    "model_ok": model_ok,
                    "overlay_control_packets": 2,
                    "direct_wg_control_packets": 0,
                    "direct_transport_packets": int(transport_event.kind == "DIRECT_BYPASS"),
                    "injected_control_packets": len(injections),
                    "route": ">".join(item.host for item in route),
                    "x1": route[1].host if route_shape_ok else "",
                    "x2": route[2].host if route_shape_ok else "",
                    "error": "" if model_ok else "model invariant failed",
                }
            )
    return rows


def format_results(kind: str) -> str:
    rows = run_scenarios()
    if kind == "json":
        return json.dumps(rows, indent=2, sort_keys=True)
    if kind != "csv":
        raise ValueError("format must be json or csv")
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=RESULT_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()
