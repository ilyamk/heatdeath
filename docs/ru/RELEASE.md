# Церемония релиза

Релиз намеренно разделяет недоверенную онлайн-сборку и офлайн-подпись. GitHub
никогда не получает production-ключи подписи.

1. Merge разрешён только после успешных CI, dependency, security и
   reproducibility checks.
2. Создайте подписанный аннотированный тег, совпадающий с `package.json`, например
   `v2.1.0`.
3. Workflow `Build release candidate` собирает точные darwin/arm64 bundle, SEA,
   `heatdeath-v2.1.0-source.tar.gz`, `heatdeath-v2.1.0.spdx.json`, provenance,
   рецепт и манифест. Он создаёт GitHub attestations и на семь дней загружает
   **неподписанный** кандидат.
4. Скачайте кандидат на контролируемую релизную машину и независимо воспроизведите
   его с Node v26.7.0 и входящим в него npm 11.19.0.
5. Подпишите `SHA256SUMS` по одному разу каждым внешним ключом:

```sh
npm run sign-release -- --scheme=ed25519 --key=/absolute/external/ed25519.pem
npm run sign-release -- --scheme=ml-dsa-87 --key=/absolute/external/ml-dsa.pem
npm run sign-release -- --scheme=slh-dsa-sha2-128s --key=/absolute/external/slh-dsa.pem
```

6. Создайте draft GitHub Release и приложите ровно файлы из allow-list. Пока не
   публикуйте его.
7. Вручную запустите `Verify release assets` для draft-тега. Workflow заново
   скачивает assets, проверяет все подписи и хеши, независимо пересобирает релиз
   на чистом macOS arm64 runner, сравнивает каждый байт, проверяет `codesign`,
   запускает self-test и доказывает capability guard.
8. Публикуйте только после зелёного workflow. Immutable Releases должны быть
   включены: публикация блокирует тег и assets. Событие published повторяет
   проверку.

Никогда не загружайте приватные ключи, не подписывайте в Actions, не публикуйте
до проверки и не используйте релизный тег повторно.
