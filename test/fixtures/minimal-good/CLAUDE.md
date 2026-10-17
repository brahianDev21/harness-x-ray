# Minimal project

This is a small module with no runtime dependencies. The entry point is `src/index.mjs`.

## Commands

- Run the tests with `npm test`.
- Lint with `npm run lint`, and check types with `npm run typecheck`.
- Format with `npm run format`.

```sh
npm test
npm run lint
```

## Layout

- Line references work: `src/index.mjs:1` and `src/index.mjs:1:14`.
- Guides are in `docs/`. See [the guide](docs/guide.md), [its usage section](docs/guide.md#usage), or [the top](#commands).
- The diagram is ![diagram](docs/diagram.svg).
- Globs and examples: `src/*.mjs` and `docs/...`. Placeholders: `<path>`, `path/to/file.md`, and `$HOME/cache`.
- URLs and names: [site](https://example.com/guide.md), `https://example.com/docs/page.md`, `www.example.com/docs`, `mailto:team@example.com`, `node:test`, `@scope/package`.
- The folder `docs/` exists.
