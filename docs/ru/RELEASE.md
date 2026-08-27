# Церемония релиза

[← Вся документация](../../README.ru.md#документация) · [🇬🇧 English](../en/RELEASE.md)

Релизы разделяют сетевые нативные builders и офлайн-подписание. Production-ключи
никогда не передаются GitHub.

1. Выполняйте merge только после всех обязательных CI, security и reproducibility checks.
2. Создайте подписанный аннотированный тег из `package.json`, например `v2.2.0`.
3. `Build release candidate` независимо собирает части darwin/arm64 и linux/x64.
4. Combine job требует одинаковые bundle, архив исходников, SBOM и рецепт, затем
   создаёт один manifest для обоих бинарников и provenance records.
5. Скачайте семидневный unsigned candidate и воспроизведите каждую нативную часть
   на её платформе с Node v26.7.0 и npm 11.19.0.
6. Подпишите `SHA256SUMS` каждой офлайн-идентичностью:

```sh
npm run sign-release -- --scheme=ed25519 --key=/absolute/external/ed25519.pem
npm run sign-release -- --scheme=ml-dsa-87 --key=/absolute/external/ml-dsa.pem
npm run sign-release -- --scheme=slh-dsa-sha2-128s --key=/absolute/external/slh-dsa.pem
```

7. Создайте draft GitHub Release ровно с allow-listed assets.
8. Пока релиз остаётся draft, запустите `Verify release assets` вручную и укажите
   его тег. Read-only jobs на обеих платформах проверяют подписи, хеши, SBOM и
   provenance, пересобирают свою нативную часть, сравнивают байты, запускают
   self-test и capability probes и проверяют GitHub attestation.
9. Публикуйте только после успеха обеих jobs. Immutable Releases должны быть включены заранее.

Никогда не загружайте приватные ключи, не подписывайте в Actions, не публикуйте до
проверки и не используйте release tag повторно.

---

<sub>Часть **HEATDEATH**. Copyright © 2026 ILIA MAKSIMENKA. Распространяется под
[AGPL-3.0-or-later](../../LICENSE). English version: [English](../en/RELEASE.md).</sub>
