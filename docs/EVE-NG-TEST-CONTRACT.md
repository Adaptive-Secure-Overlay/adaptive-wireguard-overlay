# Контракт отдельного EVE-NG-прогона

Документ предназначен владельцу отдельного тестового контура. Он не является
командой на запуск и не затрагивает существующий большой прогон.

## Предусловия

- `scripts/validate-local.ps1` или `scripts/validate-local.sh` завершился с 0.
- Создан отдельный checkpoint; действующий прогон не останавливается,
  не перезапускается и не редактируется.
- WG-конфиги уже установлены на endpoint и не включаются в результаты.
- На каждом участнике закреплён один и тот же out-of-band trust root; подписанный
  registry загружен через `TrustedRegistryStore`, а его version/digest записаны.
- Capture/inject/firewall разрешены владельцем только для изолированного lab.

Перед сетевым прогоном отдельно выполнить
`EVE-NG-TRUST-REGISTRY-TEST-CONTRACT.md`. Непройденный trust gate запрещает
переход к route construction и handshake.

## Каноническая матрица

| Серия | Кейсов | Состав |
| --- | ---: | --- |
| `bidir12` | 2 | `1→2`, `2→1` |
| `disjoint5` | 5 | пять независимых направленных пар |
| `ring10` | 10 | `1→2→…→10→1` |
| `reverse5` | 10 | пять пар в обоих направлениях |

Итого: `27` соединений. Серии, направления и агрегация сохраняются от legacy.

## Один кейс

1. В отдельном чистом состоянии подтвердить прямой WG baseline.
2. Инициировать трафик, вызывающий handshake.
3. Для type 1/2/3 подтвердить `CAPTURE → ROUTE_READY → SEND → ARRIVE → INJECT`
   и обратный маршрут `B → X2 → X1 → A`.
4. Подтвердить свежий handshake, рост RX/TX и полезный трафик через `wg0`.
5. В прямом A↔B capture получить `direct_wg_control_packets == 0` и
   WG type 4 data packets `> 0`.
6. В overlay подтвердить type 1/2/3 и отсутствие type 4.
7. Записать `route_setup_ms`, `wg_up_seconds`, `first_data_ms`; отдельно
   проверить rekey и concurrent-start timeout budget.
8. Сформировать JSON по `schemas/eve-result.schema.json` без секретов.
9. Приложить `registry_id`, version, signed-content SHA-256 и результат trust
   gate; signature и public keys допустимы, signing private key запрещён.

Кейс проходит только при одновременном выполнении: activation code `0`, ping
успешен, WG data packets `>= 2`, direct WG control packets `0`, route начинается
с запрошенного source и заканчивается запрошенным destination, reverse route
верен, redaction подтверждён.

## Отдельно документируемые, но не локально запускаемые действия

EVE-NG/SSH/VM lifecycle, `wg`, `ip`, `tcpdump`, nftables, TPROXY, raw sockets,
netns, firewall, daemon start/stop, внешний endpoint и Keenetic. Для них нужно
новое точное разрешение и проверенный rollback владельца стенда.
