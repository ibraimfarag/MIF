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
3. Add `assets/i18n/fr/` to the `assets:` list in `pubspec.yaml`. **This is the
   step that is easy to forget, and it was silent until D-050**: a folder the
   build does not carry is not an error at run time, because the loader tolerates
   a failed asset read — the pack simply loads empty and every key of it renders
   as English or as its own name. `test/lang_registry_test.dart` fails on the
   repository, and since D-050 the loader also logs one line naming the folder and
   Settings prints one line naming the language, so a *built* app says so too.
4. Add `'fr': 'Français'` to `bundledLangs` in `lib/core/i18n/app_i18n.dart`.

The loader (`i18nModules` in the same file) reads every module folder; a missing
module degrades to English instead of crashing, and a module the list names but
no folder ships is caught by `test/lang_registry_test.dart` both ways (D-050 —
`about` was such an entry, one failed read per language on every start, with no
file on disk anywhere).

Step 4 is the only code line, and it is what makes the picker offer the new
language. A tag the app is *told* to use but has no pack for - a hand-edited
`settings.json`, or an RPC caller writing `lang` straight, which the engine
accepts on purpose - renders in English too (`AppLang.resolve`), the same
language a missing key falls back to, and Settings prints one line naming the
tag so the user is not left guessing (D-049). A *bundled* language whose pack
loaded nothing is the other way round: the stored tag is fine and the build is
not, so Settings names the language instead of the tag (D-050). A missing
*module* inside a pack that exists still degrades key by key, as above — that
one is logged, not shown.

## Rules enforced by tests

- `test/i18n_parity_test.dart` — every language must have exactly the same
  module files and the same keys, no empty values, and the same `{placeholders}`
  in every language.
- `test/lang_registry_test.dart` — every bundled language is declared under
  `assets:` in `pubspec.yaml`, and the module list and the shipped files agree in
  **both** directions (a folder nobody declares, and a module nobody ships).
- `test/i18n_pack_load_test.dart` — the real bundle loads a pack for every
  bundled language and the loader logs nothing (a correct build must be quiet);
  a folder the asset list does not carry loads empty, is named once in the log,
  and leaves the app answering instead of throwing (D-050).
- `test/i18n_lint_test.dart` — user-facing copy must come from `context.tr(...)`.
  A literal inside `Text('...')` fails the build unless it is pure interpolation
  or an explicitly allowed brand/legal/path string.

## Add a key

1. Put it in the module that owns the screen.
2. Use `{name}` for placeholders and substitute with
   `context.tr('key').replaceAll('{name}', value)`.
3. Add it to **every** language folder in the same commit — the parity test
   fails otherwise.
