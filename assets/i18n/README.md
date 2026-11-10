# Translation packs

One folder per language, one JSON file per module:

```
assets/i18n/
  ar/  app.json  nav.json  engine.json  dashboard.json  common.json
       audit.json  scanner.json  network.json  ids.json  vulns.json
       guard.json  canaries.json  hardening.json  incidents.json
       reports.json  settings.json  helper.json  intel.json  sync.json
  en/  (same files, same keys)
```

Keys are flat and namespaced by module (`scanner.scan`, `settings.dnd`, …), so a
screen only ever reads its own module and two screens can never collide.

## Add a language (no code change beyond one line)

1. Copy `en/` to e.g. `fr/`.
2. Translate the **values** only — never the keys.
3. Add `'fr': 'Français'` to `bundledLangs` in `lib/core/i18n/app_i18n.dart`.

The loader (`i18nModules` in the same file) already reads every module folder;
a missing module degrades to English instead of crashing.

## Rules enforced by tests

- `test/i18n_parity_test.dart` — every language must have exactly the same
  module files and the same keys, no empty values, and the same `{placeholders}`
  in every language.
- `test/i18n_lint_test.dart` — user-facing copy must come from `context.tr(...)`.
  A literal inside `Text('…')` fails the build unless it is pure interpolation
  or an explicitly allowed brand/legal/path string.

## Add a key

1. Put it in the module that owns the screen.
2. Use `{name}` for placeholders and substitute with
   `context.tr('key').replaceAll('{name}', value)`.
3. Add it to **every** language folder in the same commit — the parity test
   fails otherwise.
