# Локальная проверка

Запуск из корня пакета:

```powershell
pwsh -File scripts/validate-local.ps1
```

или:

```bash
bash scripts/validate-local.sh
```

Скрипты проверяют наличие установленного OpenSSH `ssh-keygen`, добавляют только
локальный `src` в путь импорта, затем запускают `unittest`,
`python -m wg_handshake_overlay validate` и
`python -m wg_handshake_overlay simulate`. Trust-registry tests создают
Ed25519 signing root только во временном каталоге, подписывают локальные bytes,
проверяют SSHSIG и удаляют private key при завершении.

Сокеты, сеть, EVE-NG, `wg`, `nft`, `sudo`, SSH-соединение и изменение сетевой
конфигурации хоста не используются. Отдельный фокусированный запуск:

```powershell
pwsh -File scripts/Test-TrustRegistry.ps1
```
