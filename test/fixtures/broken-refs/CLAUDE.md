# Broken references fixture

The entry point is `src/index.mjs`, and the parser is in `src/parser/parse.mjs`.
Read the [guide](docs/guide.md) and the [design notes](docs/design.md).
Run `npm test` and `npm run lint`, then `npm run deploy` for a release build.
Use `pnpm release` on the release branch.
Settings live in `/opt/shared/settings.json` on the build machine.
Drafts are in `docs/drafts/*.md` and examples in `examples/<name>.json`.

```sh
cat docs/only-in-fence.md
npm run lint && npm run ghost
```

See `docs/guide.md:3` for the first section, and `docs/guide.md` again.
Old script: `npm run build:legacy`.
Diagram: ![diagram](assets/diagram.png)
