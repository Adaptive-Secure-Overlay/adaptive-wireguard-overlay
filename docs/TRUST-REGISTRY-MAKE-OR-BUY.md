# Выбор реализации аутентифицированного реестра

## Решение

Выбран вариант `combine`: существующий OpenSSH проверяет Ed25519 SSHSIG, а
проект реализует только узкую domain logic — строгий каталог node keys,
canonical JSON, monotonic version, atomic commit/recovery и route gate.
Собственная реализация Ed25519 запрещена.

## Рассмотренные варианты

| Вариант | Решение | Причина |
| --- | --- | --- |
| The Update Framework (`python-tuf`) | не внедрять сейчас | Имеет root/roles/version/rollback/expiry, но полный repository metadata workflow избыточен для одного локального каталога. |
| `securesystemslib` | резерв для расширения | Даёт signing/verification, но registry semantics и persistence всё равно остаются проектными; пакет не установлен. |
| `cryptography` Ed25519 | резерв для library-only backend | Качественный primitive, но compiled dependency не установлен и не решает version/atomic storage. |
| PyNaCl/libsodium | не выбран | Native dependency и только primitive без registry semantics. |
| OpenSSL CLI | не выбран | В текущем окружении отсутствует; формат и deployment сложнее. |
| OpenSSH `ssh-keygen -Y verify` | использовать | Уже установлен, проверяет Ed25519 SSHSIG, поддерживает pinned allowed signer и namespace; не требует download/install. |

## Первичные источники

- OpenSSH SSHSIG protocol и domain namespace:
  https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
- OpenSSH portable repository и manual links:
  https://github.com/openssh/openssh-portable
- TUF metadata model:
  https://theupdateframework.io/docs/metadata/
- Python-TUF:
  https://github.com/theupdateframework/python-tuf
- Secure Systems Library:
  https://github.com/secure-systems-lab/securesystemslib
- PyCA cryptography asymmetric primitives:
  https://cryptography.io/en/latest/hazmat/primitives/asymmetric/
- Python `os.replace` contract:
  https://docs.python.org/3/library/os.html#os.replace

## Acceptance

Подмена remote key, bad/missing signature, unknown signer, tampering after
signature, malformed document, equal/old version, unknown node и failure before
atomic replace должны завершаться до `RouteCache.establish` и daemon send.
Valid signed higher version должна применяться и восстанавливаться из
last-valid copy. Полный локальный suite и secret scan обязательны.
