import re, json
s = open('lib/core/i18n/app_i18n.dart', encoding='utf-8').read()

def extract(name):
    m = re.search(r"const Map<String, String> " + name + r" = \{(.*?)\n\};", s, re.S)
    body = m.group(1)
    # keys may contain uppercase (camelCase) — capture generously
    pat = re.compile(r"'([A-Za-z0-9._]+)':\s*'((?:[^'\\]|\\.)*)'", re.S)
    pairs = pat.findall(body)
    return {k: v.replace("\\'", "'") for k, v in pairs}

en = extract('_en')
ar = extract('_ar')
json.dump(en, open('assets/i18n/en.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
json.dump(ar, open('assets/i18n/ar.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=2)

# completeness check: every key used in code via tr('...') / labelKey exists
used = set(re.findall(r"tr\('([A-Za-z0-9._]+)'\)", s))
used |= set(re.findall(r"'((?:nav|common|engine|audit|dashboard|score|settings|soon|app|status|lang|state)\.[A-Za-z0-9_]+)'", s))
missing_en = sorted(k for k in used if k not in en)
missing_ar = sorted(k for k in used if k not in ar)
print('en keys:', len(en), 'ar keys:', len(ar))
print('missing in en:', missing_en)
print('missing in ar:', missing_ar)
