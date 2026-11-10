import json, pathlib, sys

BS = chr(92)

def strip_jsonc(s):
    out = []
    i, n = 0, len(s)
    in_str = False
    esc = False
    while i < n:
        c = s[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == BS:
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == '/' and i + 1 < n and s[i + 1] == '/':
            while i < n and s[i] not in '\r\n':
                i += 1
            continue
        if c == '/' and i + 1 < n and s[i + 1] == '*':
            i += 2
            while i + 1 < n and not (s[i] == '*' and s[i + 1] == '/'):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    t = ''.join(out)
    res = []
    i, n = 0, len(t)
    in_str = False
    esc = False
    while i < n:
        c = t[i]
        if in_str:
            res.append(c)
            if esc:
                esc = False
            elif c == BS:
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            res.append(c)
            i += 1
            continue
        if c == ',':
            j = i + 1
            while j < n and t[j] in ' \t\r\n':
                j += 1
            if j < n and t[j] in '}]':
                i += 1
                continue
        res.append(c)
        i += 1
    return ''.join(res)

ok = True
for p in sorted(pathlib.Path('profiles').glob('*.jsonc')):
    try:
        d = json.loads(strip_jsonc(p.read_text(encoding='utf-8')))
    except Exception as e:
        ok = False
        print(f'{p.name}: FAIL {e}')
        continue
    entries = d.get('entries', [])
    print(f"{p.name}: schema={d.get('schema_version')} entries={len(entries)} roots={list(d.get('roots', {}).keys())}")
sys.exit(0 if ok else 1)
