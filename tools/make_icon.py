"""Generate the small 32x32 Sysbin icon without external dependencies."""
import struct
import os

W = H = 32
# 5x7 bitmap font for 'S'
GLYPH = [
    "01111",
    "10000",
    "10000",
    "01110",
    "00001",
    "00001",
    "11110",
]

pixels = [[(0, 0, 0, 0) for _ in range(W)] for _ in range(H)]

# Rounded-ish navy tile with subtle vertical gradient
for y in range(H):
    for x in range(W):
        corner = (x in (0, 1, 30, 31) and y in (0, 1, 30, 31))
        if corner:
            continue
        t = y / (H - 1)
        r = int(18 + 20 * (1 - t))
        g = int(34 + 40 * (1 - t))
        b = int(62 + 60 * (1 - t))
        pixels[y][x] = (b, g, r, 255)  # BGRA

# white S, 3px scale -> 15x21, centered
sx, sy = 3, 3
ox = (W - 5 * sx) // 2
oy = (H - 7 * sy) // 2
for gy, row in enumerate(GLYPH):
    for gx, bit in enumerate(row):
        if bit == '1':
            for dy in range(sy):
                for dx in range(sx):
                    x, y = ox + gx * sx + dx, oy + gy * sy + dy
                    if 0 <= x < W and 0 <= y < H:
                        pixels[y][x] = (255, 255, 255, 255)

# accent bar at bottom
for x in range(6, 26):
    for y in range(28, 30):
        pixels[y][x] = (90, 200, 240, 255)  # BGRA

xor = bytearray()
for y in range(H - 1, -1, -1):  # bottom-up
    for x in range(W):
        b, g, r, a = pixels[y][x]
        xor += bytes((b, g, r, a))

and_mask = bytearray()
for y in range(H - 1, -1, -1):
    row = bytearray(4)  # 32 px / 8 = 4 bytes
    for x in range(W):
        if pixels[y][x][3] == 0:
            row[x // 8] |= 0x80 >> (x % 8)
    and_mask += row

bih = struct.pack('<IiiHHIIiiII',
                  40, W, H * 2, 1, 32, 0, len(xor) + len(and_mask),
                  0, 0, 0, 0)
image = bih + bytes(xor) + bytes(and_mask)

icondir = struct.pack('<HHH', 0, 1, 1)
entry = struct.pack('<BBBBHHII', W, H, 0, 0, 1, 32, len(image), 6 + 16)
icon = icondir + entry + image

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'sysbin.ico')
with open(out, 'wb') as f:
    f.write(icon)
print('wrote', os.path.abspath(out), len(icon), 'bytes')
