# Контракт отдельной проверки trust registry в EVE-NG

Документ предназначен только владельцу изолированного тестового контура. Он не
является командой на запуск, не меняет существующий checkpoint и не разрешает
сетевые или привилегированные действия.

## Версии и предусловия

- Development package: `wg-handshake-overlay 0.2.0`.
- Python: `>=3.11`.
- OpenSSH `ssh-keygen` поддерживает `-Y sign` и `-Y verify`.
- `scripts/validate-local.ps1` либо `.sh` завершён с exit code `0`.
- Для lab создан новый отдельный checkpoint; legacy run не затрагивается.
- Lab signing root генерируется только во временном защищённом каталоге.
  В evidence попадает только public root/fingerprint; private key удаляется.

## Воспроизводимая локальная матрица до EVE-NG

Запустить из корня пакета:

```powershell
pwsh -File scripts/Test-TrustRegistry.ps1
```

Обязательные случаи:

| Case | Expected |
| --- | --- |
| `valid_signed_higher_version` | accept |
| `missing_signature` | reject |
| `bad_signature` | reject |
| `unknown_signer` | reject |
| `key_modified_after_signature` | reject |
| `equal_version_replay` | reject |
| `older_version_rollback` | reject |
| `malformed_or_corrupted_update` | reject |
| `failure_before_atomic_replace` | reject; active unchanged |
| `corrupted_active_with_valid_recovery` | recover highest valid |
| `unknown_route_member` | reject before route |
| `remote_public_key_substitution_without_signed_registry` | reject before route and daemon send |

Каждый rejected update обязан оставить SHA-256 active/last-valid и текущую
version неизменными. После recovery обе копии должны иметь один signed digest.

## Изолированный стендовый шаг

Только после локального pass владелец стенда:

1. Закрепляет один lab root public key вне registry на A/B/X1/X2.
2. Подписывает version 1 с реальными lab WG public keys; private signing key не
   копирует на relay и не включает в evidence.
3. Загружает registry через штатный `TrustedRegistryStore` и фиксирует
   `registry_id`, version, root fingerprint и signed-content SHA-256.
4. Подтверждает успешное построение одного маршрута с неизменённым registry.
5. В отдельном восстановимом состоянии меняет remote WG public key после
   подписи и подтверждает: update rejected, route отсутствует, daemon send и
   WG handshake не начались.
6. Повторяет missing/bad signature, unknown signer, equal/old version и corrupt
   update. Между cases возвращается к checkpoint; старый большой run не трогает.
7. Выполняет valid signed version 2 и подтверждает atomic apply/reload.
8. Повреждает только active copy, перезапускает registry loader и подтверждает
   восстановление version 2 из last-valid; затем возвращает checkpoint.

## Evidence contract

Сформировать отдельный JSON без private keys и packet payload:

```json
{
  "schema_version": 1,
  "package_version": "0.2.0",
  "registry_id": "candidate-wireguard-nodes",
  "registry_version": 2,
  "root_fingerprint": "SHA256:<public-root-fingerprint>",
  "signed_digest": "<sha256>",
  "cases_total": 12,
  "cases_passed": 12,
  "remote_substitution_observed": "reject_before_route",
  "daemon_send_count_for_rejected_cases": 0,
  "network_or_privileged_scope": "isolated-owner-approved-lab"
}
```

Pass разрешён только при `12/12`, отсутствии route/daemon/WG activation для
всех negative cases, успешном valid update, совпадении recovered digest и
подтверждённом отсутствии signing private key в evidence.
