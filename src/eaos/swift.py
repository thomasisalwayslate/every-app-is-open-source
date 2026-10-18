"""Decode the documented Swift small String bit layout; do not guess pointers."""


def decode_small_string(words):
    if len(words) != 2:
        raise ValueError("Supply two 64-bit words in memory order")
    values = [int(w, 0) if isinstance(w, str) else int(w) for w in words]
    if any(w < 0 or w >= 1 << 64 for w in values):
        raise ValueError("Words must be unsigned 64-bit values")
    raw = b''.join(w.to_bytes(8, 'little') for w in values)
    tag = raw[15]
    if tag & 0xA0 != 0xA0:
        raise ValueError("Not a supported small Swift String discriminator; pointer-backed strings require memory inspection")
    size = tag & 0x0F
    payload = raw[:size]
    text = payload.decode('utf-8', errors='strict')
    if tag & 0x40 and not payload.isascii():
        raise ValueError("ASCII discriminator conflicts with payload")
    return {"text": text, "utf8_bytes": size, "discriminator": hex(tag),
            "raw_hex": raw.hex(), "layout": "Swift small String, 64-bit little endian"}
