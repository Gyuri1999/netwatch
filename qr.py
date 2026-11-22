"""QR code (ISO/IEC 18004) σε καθαρή Python — byte mode, διόρθωση λαθών M, εκδόσεις 1–15 (έως 412 bytes).

Για τη σύζευξη συσκευών (🧩 Οι συσκευές μου): χωρίς εξωτερική βιβλιοθήκη και χωρίς internet.
Βασισμένο στον αλγόριθμο του προτύπου (Reed–Solomon σε GF(256), μάσκες, format/version bits).
"""

# διόρθωση M: codewords διόρθωσης ανά block και πλήθος blocks, ανά έκδοση (δείκτης = έκδοση)
EC_PER_BLOCK = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24]
BLOCKS = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10]
ALIGN = [[], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
         [6, 30, 54], [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70]]
MAX_VER = 15
FORMAT_M = 0  # τα 2 bits του επιπέδου M


def _raw_modules(ver):
    r = (16 * ver + 128) * ver + 64
    if ver >= 2:
        n = ver // 7 + 2
        r -= (25 * n - 10) * n - 55
        if ver >= 7:
            r -= 36
    return r


def _data_codewords(ver):
    return _raw_modules(ver) // 8 - EC_PER_BLOCK[ver] * BLOCKS[ver]


# ── Reed–Solomon σε GF(2^8), πολυώνυμο 0x11D ──
_EXP, _LOG = [0] * 512, [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _rs_generator(deg):
    g = [1]
    for i in range(deg):
        ng = [0] * (len(g) + 1)
        for j, c in enumerate(g):
            ng[j] ^= c
            ng[j + 1] ^= _mul(c, _EXP[i])
        g = ng
    return g  # μεγαλύτερος βαθμός πρώτος, g[0] = 1


def _rs_remainder(data, deg):
    gen = _rs_generator(deg)
    rem = [0] * deg
    for b in data:
        f = b ^ rem[0]
        rem = rem[1:] + [0]
        for i in range(deg):
            rem[i] ^= _mul(gen[i + 1], f)
    return rem


def _codewords(data, ver):
    """Δεδομένα (bytes) → τελική σειρά codewords με διόρθωση και interleaving."""
    n = len(data)
    bits = [0, 1, 0, 0]  # byte mode
    cc = 8 if ver < 10 else 16
    bits += [(n >> i) & 1 for i in range(cc - 1, -1, -1)]
    for b in data:
        bits += [(b >> i) & 1 for i in range(7, -1, -1)]
    cap = _data_codewords(ver) * 8
    bits += [0] * min(4, cap - len(bits))
    bits += [0] * (-len(bits) % 8)
    cw = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(cw) < cap // 8:
        cw.append(pad)
        pad ^= 0xEC ^ 0x11
    nb, ecl = BLOCKS[ver], EC_PER_BLOCK[ver]
    raw = _raw_modules(ver) // 8
    short = nb - raw % nb
    short_len = raw // nb - ecl  # μήκος δεδομένων των «κοντών» blocks
    blocks, ecs, k = [], [], 0
    for i in range(nb):
        ln = short_len + (0 if i < short else 1)
        blk = cw[k:k + ln]
        k += ln
        blocks.append(blk)
        ecs.append(_rs_remainder(blk, ecl))
    out = []
    for i in range(short_len + 1):
        for blk in blocks:
            if i < len(blk):
                out.append(blk[i])
    for i in range(ecl):
        for e in ecs:
            out.append(e[i])
    return out


class _Matrix:
    def __init__(self, ver):
        self.ver, self.size = ver, ver * 4 + 17
        self.m = [[False] * self.size for _ in range(self.size)]
        self.fn = [[False] * self.size for _ in range(self.size)]

    def set(self, x, y, v):
        self.m[y][x], self.fn[y][x] = bool(v), True

    def function_patterns(self):
        s = self.size
        for i in range(s):
            self.set(6, i, i % 2 == 0)
            self.set(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (s - 4, 3), (3, s - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < s and 0 <= y < s:
                        self.set(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        al = ALIGN[self.ver]
        last = len(al) - 1
        for i, ax in enumerate(al):
            for j, ay in enumerate(al):
                if (i == 0 and j == 0) or (i == 0 and j == last) or (i == last and j == 0):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.set(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)
        self.format_bits(0)
        if self.ver >= 7:
            rem = self.ver
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            bits = self.ver << 12 | rem
            for i in range(18):
                b = (bits >> i) & 1
                a, c = s - 11 + i % 3, i // 3
                self.set(a, c, b)
                self.set(c, a, b)

    def format_bits(self, mask):
        data = FORMAT_M << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        g = lambda i: (bits >> i) & 1  # noqa: E731
        s = self.size
        for i in range(6):
            self.set(8, i, g(i))
        self.set(8, 7, g(6))
        self.set(8, 8, g(7))
        self.set(7, 8, g(8))
        for i in range(9, 15):
            self.set(14 - i, 8, g(i))
        for i in range(8):
            self.set(s - 1 - i, 8, g(i))
        for i in range(8, 15):
            self.set(8, s - 15 + i, g(i))
        self.set(8, s - 8, 1)

    def place(self, cw):
        s, i, n = self.size, 0, len(cw) * 8
        right = s - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(s):
                for j in range(2):
                    x = right - j
                    up = ((right + 1) & 2) == 0
                    y = s - 1 - vert if up else vert
                    if not self.fn[y][x] and i < n:
                        self.m[y][x] = bool((cw[i >> 3] >> (7 - (i & 7))) & 1)
                        i += 1
            right -= 2

    def apply_mask(self, k):
        for y in range(self.size):
            for x in range(self.size):
                if self.fn[y][x]:
                    continue
                if k == 0:
                    inv = (x + y) % 2 == 0
                elif k == 1:
                    inv = y % 2 == 0
                elif k == 2:
                    inv = x % 3 == 0
                elif k == 3:
                    inv = (x + y) % 3 == 0
                elif k == 4:
                    inv = (x // 3 + y // 2) % 2 == 0
                elif k == 5:
                    inv = x * y % 2 + x * y % 3 == 0
                elif k == 6:
                    inv = (x * y % 2 + x * y % 3) % 2 == 0
                else:
                    inv = ((x + y) % 2 + x * y % 3) % 2 == 0
                if inv:
                    self.m[y][x] = not self.m[y][x]

    def penalty(self):
        m, s, p = self.m, self.size, 0
        for line in list(m) + [[m[y][x] for y in range(s)] for x in range(s)]:  # N1: σειρές ίδιου χρώματος
            run, prev = 0, None
            for v in line:
                if v == prev:
                    run += 1
                else:
                    if run >= 5:
                        p += run - 2
                    run, prev = 1, v
            if run >= 5:
                p += run - 2
        for y in range(s - 1):  # N2: τετράγωνα 2x2
            for x in range(s - 1):
                if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    p += 3
        dark = sum(sum(r) for r in m)  # N4: ισορροπία μαύρου/άσπρου
        p += abs(dark * 20 - s * s * 10) // (s * s) * 10
        return p


def encode(text):
    """Κείμενο → πίνακας (λίστα γραμμών με True = μαύρο). ValueError αν δεν χωράει."""
    data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    for ver in range(1, MAX_VER + 1):
        cc = 8 if ver < 10 else 16
        if 4 + cc + len(data) * 8 <= _data_codewords(ver) * 8:
            break
    else:
        raise ValueError("πολύ μεγάλο για QR")
    cw = _codewords(data, ver)
    best = None
    for k in range(8):
        mx = _Matrix(ver)
        mx.function_patterns()
        mx.place(cw)
        mx.apply_mask(k)
        mx.format_bits(k)
        sc = mx.penalty()
        if best is None or sc < best[0]:
            best = (sc, mx)
    return best[1].m


def svg(text, scale=6, border=4, dark="#000", light="#fff"):
    m = encode(text)
    n = len(m) + 2 * border
    path = "".join(f"M{x + border},{y + border}h1v1h-1z" for y, row in enumerate(m) for x, v in enumerate(row) if v)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" width="{n * scale}" height="{n * scale}" '
            f'shape-rendering="crispEdges"><rect width="{n}" height="{n}" fill="{light}"/><path d="{path}" fill="{dark}"/></svg>')
