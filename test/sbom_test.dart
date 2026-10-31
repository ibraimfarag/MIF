// Tests for the third-party inventory generator (tool/sbom.dart).
//
// What these are for: `sbom.cdx.json` and `THIRD-PARTY-NOTICES` are generated
// files that are committed, so the failure mode to defend against is not a crash
// - it is a stale or quietly shrinking inventory. These tests re-derive the
// component set from the two lockfiles (which need neither cargo nor a network)
// and fail when the committed files no longer describe them, and they pin the
// parts a legal reader cares about: which license we rely on, and that its text
// is in the file.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

import '../tool/sbom.dart';

/// A license fixture needs the phrases `detectLicenseId` keys on, which is what
/// real license files look like: nothing here is a full license text.
const _mitFixture = '''
MIT License

Copyright (c) 2024 Example Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.
''';

const _bsd3Fixture = '''
Copyright 2024 Example Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software.
''';

const _bsd2Fixture = '''
Copyright 2024 Example Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
''';

const _apacheShortFixture = '''
Copyright 2024 Example Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
''';

const _iscFixture = '''
Copyright (c) 2024 Example Authors

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.
''';

const _zeroBsdFixture = '''
Copyright (C) 2024 Example Authors

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES.
''';

/// A small `cargo metadata` document: one workspace member, three registry
/// crates, one of them reachable only through a dev edge.
const _cargoFixture = '''
{
  "packages": [
    {"id": "path+file:///engine#mics-engine@0.1.0", "name": "mics-engine",
     "version": "0.1.0", "source": null, "license": "GPL-3.0-or-later"},
    {"id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
     "name": "serde", "version": "1.0.0", "license": "MIT OR Apache-2.0",
     "checksum": "aa", "source": "registry+https://github.com/rust-lang/crates.io-index"},
    {"id": "registry+https://github.com/rust-lang/crates.io-index#libc@0.2.0",
     "name": "libc", "version": "0.2.0", "license": "MIT",
     "checksum": "bb", "source": "registry+https://github.com/rust-lang/crates.io-index"},
    {"id": "registry+https://github.com/rust-lang/crates.io-index#criterion@0.5.0",
     "name": "criterion", "version": "0.5.0", "license": "Apache-2.0",
     "checksum": "cc", "source": "registry+https://github.com/rust-lang/crates.io-index"}
  ],
  "workspace_members": ["path+file:///engine#mics-engine@0.1.0"],
  "resolve": {
    "nodes": [
      {"id": "path+file:///engine#mics-engine@0.1.0",
       "deps": [
         {"name": "serde", "pkg": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
          "dep_kinds": [{"kind": null, "target": null}]},
         {"name": "libc", "pkg": "registry+https://github.com/rust-lang/crates.io-index#libc@0.2.0",
          "dep_kinds": [{"kind": null, "target": "cfg(windows)"}]},
         {"name": "criterion", "pkg": "registry+https://github.com/rust-lang/crates.io-index#criterion@0.5.0",
          "dep_kinds": [{"kind": "dev", "target": null}]}
       ]},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0", "deps": []},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#libc@0.2.0", "deps": []},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#criterion@0.5.0", "deps": []}
    ]
  }
}
''';

const _pubDepsFixture = '''
{
  "root": "demo",
  "packages": [
    {"name": "demo", "kind": "root", "source": "root",
     "directDependencies": ["shelf", "flutter"], "devDependencies": ["test"]},
    {"name": "flutter", "kind": "direct", "source": "sdk",
     "dependencies": []},
    {"name": "shelf", "kind": "direct", "source": "hosted",
     "dependencies": ["http_parser"]},
    {"name": "http_parser", "kind": "transitive", "source": "hosted",
     "dependencies": []},
    {"name": "test", "kind": "dev", "source": "hosted",
     "dependencies": ["matcher"]},
    {"name": "matcher", "kind": "transitive", "source": "hosted",
     "dependencies": []}
  ]
}
''';

const _pubLockFixture = '''
# Generated by pub
packages:
  shelf:
    dependency: "direct main"
    description:
      name: shelf
      sha256: "1111111111111111111111111111111111111111111111111111111111111111"
      url: "https://pub.dev"
    source: hosted
    version: "1.4.2"
  matcher:
    dependency: transitive
    description:
      name: matcher
      sha256: "2222222222222222222222222222222222222222222222222222222222222222"
      url: "https://pub.dev"
    source: hosted
    version: "0.12.17"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
sdks:
  dart: ">=3.9.0 <4.0.0"
''';

String _read(String relative) {
  final file = File(relative);
  expect(file.existsSync(), isTrue, reason: '$relative is missing');
  return file.readAsStringSync();
}

void main() {
  group('SPDX expressions', () {
    test('a choice is usable when either side is', () {
      expect(evaluateExpression('MIT OR Apache-2.0'), LicenseVerdict.permissive);
      expect(evaluateExpression('MIT/Apache-2.0'), LicenseVerdict.permissive);
      expect(
        evaluateExpression('MIT OR Apache-2.0 OR LGPL-2.1-or-later'),
        LicenseVerdict.permissive,
        reason: 'we take the MIT option, and the notices say so',
      );
      expect(
        evaluateExpression('Zlib OR Apache-2.0 OR MIT'),
        LicenseVerdict.permissive,
      );
    });

    test('a conjunction needs every side', () {
      expect(
        evaluateExpression('(Apache-2.0 OR MIT) AND BSD-3-Clause'),
        LicenseVerdict.permissive,
      );
      expect(
        evaluateExpression('MIT AND GPL-3.0-only'),
        LicenseVerdict.copyleft,
      );
      expect(evaluateExpression('Apache-2.0 AND ISC'), LicenseVerdict.permissive);
    });

    test('copyleft and unknown ids are reported, never assumed away', () {
      expect(evaluateExpression('GPL-3.0-only'), LicenseVerdict.copyleft);
      expect(evaluateExpression('MPL-2.0'), LicenseVerdict.copyleft);
      expect(evaluateExpression('MIT OR MPL-2.0'), LicenseVerdict.permissive);
      expect(evaluateExpression('Some-New-License-1.0'), LicenseVerdict.unknown);
      expect(
        evaluateExpression('MIT AND Some-New-License-1.0'),
        LicenseVerdict.unknown,
      );
    });

    test('an exception narrows the id it sits on', () {
      expect(
        evaluateExpression('Apache-2.0 WITH LLVM-exception'),
        LicenseVerdict.permissive,
      );
      expect(
        evaluateExpression(
          'Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT',
        ),
        LicenseVerdict.permissive,
      );
    });

    test('the option we rely on does not depend on the order', () {
      expect(concludedId('MIT OR Apache-2.0'), 'MIT');
      expect(concludedId('Apache-2.0 OR MIT'), 'MIT');
      expect(
        concludedId('Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT'),
        'MIT',
      );
      expect(concludedId('MIT OR Apache-2.0 OR LGPL-2.1-or-later'), 'MIT');
      expect(concludedId('GPL-3.0-only'), isNull);
      expect(concludedId('MIT AND Some-New-License-1.0'), isNull);
    });

    test('every id in the expression is listed, once', () {
      expect(expressionIds('MIT OR (Apache-2.0 AND BSD-3-Clause)'), [
        'MIT',
        'Apache-2.0',
        'BSD-3-Clause',
      ]);
      expect(expressionIds('MIT OR MIT'), ['MIT']);
    });

    test('a malformed expression throws instead of passing', () {
      expect(() => evaluateExpression('MIT OR'), throwsFormatException);
      expect(() => evaluateExpression('MIT)'), throwsFormatException);
      expect(() => evaluateExpression('(MIT'), throwsFormatException);
      expect(() => evaluateExpression('   '), throwsFormatException);
      expect(() => evaluateExpression('MIT Apache-2.0'), throwsFormatException);
    });
  });

  group('license text recognition', () {
    test('the common ids are recognised from their own wording', () {
      expect(detectLicenseId(_mitFixture), 'MIT');
      expect(detectLicenseId(_bsd3Fixture), 'BSD-3-Clause');
      expect(detectLicenseId(_bsd2Fixture), 'BSD-2-Clause');
      expect(detectLicenseId(_apacheShortFixture), 'Apache-2.0');
      expect(
        detectLicenseId('                     Apache License\n'
            '                Version 2.0, January 2004\n'),
        'Apache-2.0',
      );
      expect(detectLicenseId(_iscFixture), 'ISC');
      expect(detectLicenseId(_zeroBsdFixture), '0BSD');
      expect(
        detectLicenseId('This is free and unencumbered software released into '
            'the public domain.'),
        'Unlicense',
      );
      expect(detectLicenseId("This software is provided 'as-is', without any "
          'express or implied warranty.'), 'Zlib');
      expect(
        detectLicenseId('SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007'),
        'OFL-1.1',
      );
      expect(
        detectLicenseId('UNICODE LICENSE V3\n\nCOPYRIGHT AND PERMISSION NOTICE'),
        'Unicode-3.0',
      );
      expect(
        detectLicenseId('Mozilla Public License Version 2.0\n1. Definitions'),
        'MPL-2.0',
      );
      expect(
        detectLicenseId('GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007'),
        'GPL-3.0-only',
      );
    });

    test('a pointer file or an unknown text is not guessed at', () {
      expect(
        detectLicenseId('This project is dual-licensed under the Unlicense and '
            'MIT licenses.\n\nYou may use this code under the terms of either '
            'license.'),
        isNull,
      );
      expect(detectLicenseId('(c) 2024 Example. All rights reserved.'), isNull);
      expect(detectLicenseId(''), isNull);
    });

    test('the copyright line is taken from the file, not invented', () {
      expect(
        copyrightLineOf(_mitFixture),
        'Copyright (c) 2024 Example Authors',
      );
      expect(
        copyrightLineOf('Copyright (c) 2020 The Authors\nCopyright (c) 2021 '
            'The Authors\n\nPermission is hereby granted'),
        'Copyright (c) 2020 The Authors Copyright (c) 2021 The Authors',
      );
      expect(
        copyrightLineOf('Apache License\nVersion 2.0, January 2004'),
        isNull,
      );
    });
  });

  group('pubspec.lock', () {
    test('the fixture pins every field we depend on', () {
      final components = parsePubLock(_pubLockFixture, sdkVersion: '3.47.8');
      expect(components, hasLength(3));
      final shelf = components.firstWhere((c) => c.name == 'shelf');
      expect(shelf.version, '1.4.2');
      expect(shelf.ecosystem, ecosystemPub);
      expect(shelf.purl, 'pkg:pub/shelf@1.4.2');
      expect(shelf.sha256, hasLength(64));
      expect(shelf.scope, 'required');
      final flutter = components.firstWhere((c) => c.name == 'flutter');
      expect(flutter.ecosystem, ecosystemFlutter);
      expect(flutter.version, '3.47.8', reason: 'pub records 0.0.0 for the SDK');
      expect(flutter.declaredLicense, 'BSD-3-Clause');
    });

    test('the runtime closure decides the scope, not the lockfile order', () {
      final components = parsePubLock(
        _pubLockFixture,
        shippedNames: pubShippedNames(_pubDepsFixture),
        sdkVersion: '3.47.8',
      );
      String scopeOf(String name) =>
          components.firstWhere((c) => c.name == name).scope;
      expect(pubShippedNames(_pubDepsFixture), contains('http_parser'));
      expect(scopeOf('shelf'), 'required');
      expect(scopeOf('matcher'), 'excluded', reason: 'only test depends on it');
      expect(scopeOf('flutter'), 'required');
    });

    test('an unexpected shape throws instead of shrinking the inventory', () {
      expect(
        () => parsePubLock('packages:\n  shelf:\n    version: "1.0.0"\n'
            '      nested: too deep\n'),
        throwsFormatException,
      );
    });

    test('the real lockfile parses to one component per package', () {
      final lock = _read('pubspec.lock');
      final pinned = RegExp(r'^  ([a-z0-9_]+):$', multiLine: true)
          .allMatches(lock)
          .length;
      final components = parsePubLock(lock, sdkVersion: '3.47.8');
      expect(components, hasLength(pinned));
      for (final c in components) {
        expect(c.name, isNotEmpty);
        expect(c.version, isNotEmpty);
        if (c.ecosystem == ecosystemPub) {
          expect(
            c.sha256,
            matches(RegExp(r'^[0-9a-f]{64}$')),
            reason: '${c.name} has no sha256 in pubspec.lock',
          );
          expect(c.purl, startsWith('pkg:pub/${c.name}@'));
        }
      }
    });
  });

  group('cargo metadata', () {
    test('our own workspace member is the product, not a component', () {
      final components = parseCargoMetadata(
        _cargoFixture,
        shippedCoordinates: cargoShippedCoordinates(_cargoFixture),
      );
      expect(components.map((c) => c.name), isNot(contains('mics-engine')));
      expect(components, hasLength(3));
      final serde = components.firstWhere((c) => c.name == 'serde');
      expect(serde.purl, 'pkg:cargo/serde@1.0.0');
      expect(serde.sha256, 'aa');
      expect(serde.declaredLicense, 'MIT OR Apache-2.0');
      expect(serde.scope, 'required');
      expect(serde.assessment?.concluded, 'MIT');
    });

    test('dev-only and build-only crates are excluded, not hidden', () {
      final shipped = cargoShippedCoordinates(_cargoFixture);
      expect(shipped, contains('serde@1.0.0'));
      expect(shipped, contains('libc@0.2.0'));
      expect(shipped, isNot(contains('criterion@0.5.0')));
      final components = parseCargoMetadata(
        _cargoFixture,
        shippedCoordinates: shipped,
      );
      expect(
        components.firstWhere((c) => c.name == 'criterion').scope,
        'excluded',
      );
    });

    test('the real lockfile pins the crates the SBOM must describe', () {
      final coordinates = cargoLockCoordinates(_read('engine/Cargo.lock'));
      expect(coordinates.length, greaterThan(400));
      for (final coordinate in coordinates) {
        expect(coordinate, matches(RegExp(r'^[A-Za-z0-9_.\-]+@[0-9][^@]*$')));
      }
      expect(coordinates.toSet(), hasLength(coordinates.length));
    });
  });

  group('the committed inventory', () {
    late Map<String, dynamic> bom;
    late List<Map<String, dynamic>> components;
    late String notices;

    setUpAll(() {
      bom = jsonDecode(_read('sbom.cdx.json')) as Map<String, dynamic>;
      components = (bom['components'] as List).cast<Map<String, dynamic>>();
      notices = _read('THIRD-PARTY-NOTICES');
    });

    test('it is a CycloneDX 1.6 document about this product', () {
      expect(bom['bomFormat'], 'CycloneDX');
      expect(bom['specVersion'], '1.6');
      expect(
        bom['serialNumber'],
        matches(
          RegExp(r'^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-'
              r'[0-9a-f]{4}-[0-9a-f]{12}$'),
        ),
      );
      final metadata = bom['metadata'] as Map<String, dynamic>;
      final app = metadata['component'] as Map<String, dynamic>;
      expect(app['name'], 'MI CS');
      expect(app['type'], 'application');
      expect(
        ((app['licenses'] as List).first as Map)['license'],
        {'id': 'GPL-3.0-or-later'},
      );
      expect(
        (metadata['tools'] as Map)['components'],
        isNotEmpty,
        reason: 'an SBOM should say what produced it',
      );
    });

    test('the component set is exactly what the lockfiles pin', () {
      // The SDK packages are pinned as 0.0.0 in the lockfile; the generator
      // records the Flutter version instead, and so does the expected set here.
      final flutterVersion =
          flutterVersionOf(flutterRoot(repoRoot: Directory.current.path)) ??
              'unknown';
      final expected = <String>{
        ...cargoLockCoordinates(_read('engine/Cargo.lock')),
        for (final c in parsePubLock(
          _read('pubspec.lock'),
          sdkVersion: flutterVersion,
        ))
          '${c.name}@${c.version}',
        'Cairo@3.130',
        'JetBrains Mono@2.211',
        'Flutter engine@$flutterVersion',
        'Microsoft Visual C++ runtime@14.x',
      };
      final actual = <String>{
        for (final c in components) '${c['name']}@${c['version']}',
      };
      expect(
        actual.difference(expected),
        isEmpty,
        reason: 'the SBOM lists something the lockfiles do not pin anymore',
      );
      expect(
        expected.difference(actual),
        isEmpty,
        reason: 'a dependency changed and the SBOM was not regenerated - run '
            'dart run tool/sbom.dart',
      );
      final properties = ((bom['metadata'] as Map)['component']
          as Map)['properties'] as List;
      expect(
        properties.any(
          (p) =>
              p is Map &&
              p['name'] == 'mics:sbom:componentCount' &&
              p['value'] == '${components.length}',
        ),
        isTrue,
        reason: 'the SBOM should state how many components it describes',
      );
    });

    test('every component carries a license and a purl', () {
      for (final c in components) {
        expect(c['purl'], startsWith('pkg:'), reason: '${c['name']}');
        expect(c['licenses'], isNotNull, reason: '${c['name']} has no license');
        expect(
          const ['required', 'optional', 'excluded'],
          contains(c['scope']),
        );
      }
      final cargo = components.where((c) => c['purl'].toString().startsWith(
        'pkg:cargo/',
      ));
      expect(
        cargo.every(
          (c) => (c['licenses'] as List).every(
            (l) => ((l as Map)['license'] as Map)['acknowledgement'] ==
                'declared',
          ),
        ),
        isTrue,
        reason: 'a crate states its own license; we do not conclude for it',
      );
    });

    test('the notices carry the audit and a text for every license we rely on',
        () {
      expect(notices, contains('# Third-party notices for MI CS'));
      expect(notices, contains('- Copyleft: 0'));
      expect(notices, contains('- Unclassified: 0'));
      expect(notices, contains('- License texts missing: 0'));

      final ids = <String>{};
      for (final c in components) {
        for (final raw in (c['licenses'] as List)) {
          final license = (raw as Map)['license'] as Map;
          if (license['acknowledgement'] == 'concluded') {
            ids.add(license['id'] as String);
          }
        }
      }
      expect(ids, isNotEmpty);
      for (final id in ids) {
        expect(
          notices,
          contains('\n### $id\n'),
          reason: 'the concluded license $id has no text in the notices',
        );
      }
      expect(notices, contains('### OFL-1.1'));
      expect(notices, contains('Copyright 2009 The Cairo Project Authors'));
      expect(notices, contains('Copyright 2020 The JetBrains Mono Project'));
    });
  });

  group('rendering', () {
    test('the same inventory renders byte for byte the same document', () {
      final components = parseCargoMetadata(
        _cargoFixture,
        shippedCoordinates: cargoShippedCoordinates(_cargoFixture),
      );
      attachLicenses(
        components,
        cargoRegistryRoots: const [],
        pubCache: 'no-such-cache',
        flutterRootPath: null,
        oflTextPath: 'no-such-file',
        warnings: <String>[],
      );
      final inventory = Inventory(components, <String>[]);
      String render() => renderCycloneDx(
        appName: 'MI CS',
        appVersion: '9.9.9',
        appLicense: 'GPL-3.0-or-later',
        inventory: inventory,
      );
      expect(render(), render());
      expect(render(), contains('urn:uuid:'));
      final notices = renderNotices(
        appName: 'MI CS',
        appVersion: '9.9.9',
        appLicense: 'GPL-3.0-or-later',
        inventory: inventory,
      );
      expect(notices, contains('| 3 |'), reason: 'the summary counts');
      expect(notices, contains('criterion'));
    });
  });
}
