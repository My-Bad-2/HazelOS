import sys
import os
import math
from PIL import Image, ImageFont, ImageDraw

# Standard VGA dimensions used by the kernel console
FIRST_CHAR: int = 0
LAST_CHAR: int = 255
NUM_CHARS: int = LAST_CHAR - FIRST_CHAR + 1

# Manual offsets for characters that don't center correctly with automatic calculation
TWEAKS: dict[int, tuple[int, int]] = {
    # char: (width, height)
}

# Maps specific VGA byte indices to Unicode for rendering non-manual chars.
# Modern TTF fonts use Unicode, but we need to generate a legacy CP437
# charset for the VGA console. This map bridges the gap.
CP437_MAP: dict[int, int] = {
    # Box Drawing
    179: 0x2502,
    180: 0x2524,
    181: 0x2561,
    182: 0x2562,
    183: 0x2556,
    184: 0x2555,
    185: 0x2563,
    186: 0x2551,
    187: 0x2557,
    188: 0x255D,
    189: 0x255C,
    190: 0x255B,
    191: 0x2510,
    192: 0x2514,
    193: 0x2534,
    194: 0x252C,
    195: 0x251C,
    196: 0x2500,
    197: 0x253C,
    198: 0x255E,
    199: 0x255F,
    200: 0x255A,
    201: 0x2554,
    202: 0x2569,
    203: 0x2566,
    204: 0x2560,
    205: 0x2550,
    206: 0x256C,
    207: 0x2567,
    208: 0x2568,
    209: 0x2564,
    210: 0x2565,
    211: 0x2559,
    212: 0x2558,
    213: 0x2552,
    214: 0x2553,
    215: 0x256B,
    216: 0x256A,
    217: 0x2518,
    218: 0x250C,
    # Symbols
    224: 0x03B1,
    227: 0x03C0,
    248: 0x00B0,
    251: 0x221A,
    253: 0x00B2,
}


# Render block characters manually to ensure they fill the entire cell without anti-aliasing artifacts
def draw_manual_block(draw: ImageDraw.ImageDraw, code: int, w: int, h: int) -> bool:
    # Light shade
    if code == 176:
        for y in range(h):
            for x in range(w):
                if (x + y) % 2 == 0 and (x % 2 == 0):
                    draw.point((x, y), fill=1)
        return True

    # Medium shade
    if code == 177:
        for y in range(h):
            for x in range(w):
                if (x + y) % 2 == 0:
                    draw.point((x, y), fill=1)
        return True

    # Dark Shade
    if code == 178:
        for y in range(h):
            for x in range(w):
                if (x + y) % 2 != 0 or (x % 2 == 0):
                    draw.point((x, y), fill=1)
        return True

    # Full Block (Solid)
    if code == 219:
        draw.rectangle((0, 0, w, h), fill=1)
        return True

    # Lower Half Block
    if code == 220:
        draw.rectangle((0, h // 2, w, h), fill=1)
        return True

    # Left Half Block
    if code == 221:
        draw.rectangle((0, 0, w // 2 - 1, h), fill=1)
        return True

    # Right Half Block
    if code == 222:
        draw.rectangle((w // 2, 0, w, h), fill=1)
        return True

    # Upper Half Block
    if code == 223:
        draw.rectangle((0, 0, w, h // 2 - 1), fill=1)
        return True

    return False


def generate_font(
    ttf_path: str, output_path: str, char_w: int, char_h: int, font_size: int
) -> None:
    try:
        # Load the image
        font = ImageFont.truetype(ttf_path, font_size)
    except IOError:
        print(f"Error: Could not open font file `{ttf_path}`")
        sys.exit(1)

    bytes_per_row = math.ceil(char_w / 8)
    total_bytes = NUM_CHARS * char_h * bytes_per_row

    print(f"Processing: {ttf_path}")
    print(f"Dimensions: {char_w}x{char_h}")
    print(f"Output    : {output_path}")
    print(f"Font Size : {font_size}px")

    # ascent: distance from baseline to top of highest glyph
    # descent: distance from baseline to bottom of lowest descender
    ascent, descent = font.getmetrics()
    font_height = ascent + descent
    base_y_offset = (char_h - font_height) // 2

    arr = []
    arr.append(f"// Generated from {os.path.basename(ttf_path)}")
    arr.append(f"// Font Size: {char_w}x{char_h} ({bytes_per_row} bytes stride)")
    arr.append(f'#include "drivers/term.h"')
    arr.append("")
    arr.append(f"static const uint8_t font_data[{total_bytes}] = {{")

    for i in range(FIRST_CHAR, LAST_CHAR + 1):
        image = Image.new("1", (char_w, char_h), 0)
        draw = ImageDraw.Draw(image)

        is_manual = draw_manual_block(draw, i, char_w, char_h)

        if not is_manual:
            char_code = i

            if i in CP437_MAP:
                char_code = CP437_MAP[i]

            char = chr(char_code)
            bbox = font.getbbox(char)

            if bbox:
                text_width = bbox[2] - bbox[0]
                x_pos = (char_w - text_width) // 2 - bbox[0]
            else:
                x_pos = 0

            y_pos = base_y_offset

            if i in TWEAKS:
                adj_x, adj_y = TWEAKS[i]
                x_pos += adj_x
                y_pos += adj_y

            draw.text((x_pos, y_pos), char, font=font, fill=1)

        pixels = image.load()
        byte_list = []

        # Pack 1-bit pixels into bytes for C array storage (row-major)
        for y in range(char_h):
            for b in range(bytes_per_row):
                val = 0
                for bit in range(8):
                    px_x = (b * 8) + bit
                    if px_x < char_w:
                        if pixels[px_x, y]:
                            val |= 1 << (7 - bit)

                byte_list.append(f"0x{val:02x}")

        arr.append(f"   {', '.join(byte_list)}, // character {i}")

    arr.append("};")
    arr.append("")

    arr.append(f"static term_font_t term_font = {{")
    arr.append(f"   .data = font_data,")
    arr.append(f"   .width = {char_w},")
    arr.append(f"   .height = {char_h},")
    arr.append(f"   .stride = {bytes_per_row}")
    arr.append(f"}};")

    with open(output_path, "w") as f:
        f.write("\n".join(arr))

    print(f"Done! Saved to {output_path}.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            "Usage: python ttf_to_array.py <input.ttf> <output.c> <width> <height> <font_size>"
        )
        print("Example: python ttf_to_array.py arial.ttf font16x32.c 16 32 28")
    else:
        generate_font(
            sys.argv[1],
            sys.argv[2],
            int(sys.argv[3]),
            int(sys.argv[4]),
            int(sys.argv[5]),
        )
