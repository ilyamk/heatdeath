# Сборка и выпуск

Обычная и релизная сборки намеренно разделены.

`npm run build` запускает `node:test`, все внутренние known-answer-векторы,
локальный esbuild строго версии **0.28.2** и self-test автономного bundle. Эта
команда не создаёт SEA и не меняет provenance или подписи.

`npm run build:release` закрывается при любой неоднозначности. Нужны чистое
рабочее дерево, аннотированный тег `v2.1.0` на `HEAD`, Node **v26.7.0** и
**darwin/arm64**. Результат включает bundle, SEA, детерминированный архив исходников
`heatdeath-v2.1.0-source.tar.gz` (`git archive | gzip -n`),
`SOURCE-PROVENANCE.json`, рецепт, `heatdeath-v2.1.0.spdx.json` в формате SPDX SBOM
и `SHA256SUMS`. Provenance фиксирует тег, commit, хеши lockfile, исходного архива
и SBOM, версию и хеш бинарника Node, npm 11.19.0 из Node v26.7.0, esbuild, платформу и архитектуру.

Релизная сборка ничего не подписывает автоматически. Каждая схема вызывается
отдельно:

```sh
npm run sign-release -- --scheme=ed25519 --key=/absolute/external/ed25519.pem
npm run sign-release -- --scheme=ml-dsa-87 --key=/absolute/external/ml-dsa.pem
npm run sign-release -- --scheme=slh-dsa-sha2-128s --key=/absolute/external/slh-dsa.pem
```

Приватный ключ обязан находиться вне репозитория, не быть symlink и иметь права
0600 или строже. Производный публичный fingerprint должен совпасть с уже
зафиксированной релизной идентичностью. Отсутствующий ключ — ошибка: подпись больше
никогда не создаёт и не ротирует ключи как побочный эффект. Новая идентичность
создаётся только явно названной командой `init-signing-key` и публикуется через
независимый канал.

SEA использует `execArgvExtension: "none"` и разрешает чтение только
`/dev/urandom`. Шесть проб проверяют least privilege для доверенного кода. Node
Permission Model — capability guard, а не песочница от вредоносного кода. Доверие
к коду дают аудит, воспроизводимость, provenance и независимо закреплённые ключи.

Тег и публикация остаются отдельным ручным шагом после независимого review.
Полная последовательность candidate, offline signing, draft verification и
immutable release описана в [RELEASE.md](RELEASE.md).
