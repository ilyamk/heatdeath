# Дисциплина сборки и релиза

[← Вся документация](../../README.ru.md#документация) · [🇬🇧 English](../en/BUILD.md)

`npm run build` — developer-сборка. Она запускает тесты и эталонные векторы,
собирает bundle закреплённым esbuild и проверяет `dist/heatdeath.mjs`. Нативные
бинарники, provenance и подписи не создаются.

`npm run build:release` создаёт одну нативную часть релиза `v2.3.0`. Требуются:

- чистое рабочее дерево и аннотированный тег `v2.3.0`, указывающий на `HEAD`;
- Node v26.7.0, npm 11.19.0 и esbuild 0.28.2;
- либо darwin/arm64, либо linux/x64.

Каждая платформа создаёт одинаковые bundle, детерминированный
`heatdeath-v2.3.0-source.tar.gz`, SPDX `heatdeath-v2.3.0.spdx.json` и рецепт,
а также собственные SEA и provenance:

- `heatdeath-darwin-arm64` и `SOURCE-PROVENANCE-darwin-arm64.json`;
- `heatdeath-linux-x64` и `SOURCE-PROVENANCE-linux-x64.json`.

CI сравнивает общие байты, объединяет обе нативные части и создаёт финальный manifest:

```sh
node build/finalize-release.mjs candidate
```

Из общего SPDX удаляются только опциональные нативные helper-пакеты, выбранные
хостом (например, `@esbuild/darwin-arm64` вместо `@esbuild/linux-x64`), и их
relationships. Логический пакет `esbuild` остаётся. Хеш полного lockfile и
provenance каждой платформы сохраняют данные о builder, а product SBOM остаётся
побайтово одинаковым на обеих платформах.

Только этот полный manifest подписывается офлайн. Каждый provenance закрепляет
тег, commit, хеши исходников и SBOM, lockfile, бинарник Node, npm, esbuild, хеш
нативного артефакта, платформу и архитектуру.

SEA содержит точный рантайм Node, использует `execArgvExtension: "none"` и получает
только чтение `/dev/urandom`. Это артефакт для удобства; основной объект аудита —
читаемый кроссплатформенный bundle `.mjs`.

---

<sub>Часть **HEATDEATH**. Copyright © 2026 ILIA MAKSIMENKA. Распространяется под
[AGPL-3.0-or-later](../../LICENSE). English version: [English](../en/BUILD.md).</sub>
