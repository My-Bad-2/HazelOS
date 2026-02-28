#include "drivers/term.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "boot/boot.h"
#include "boot/limine.h"
#include "libs/math.h"
#include "libs/mmio.h"
#include "memory/memory.h"
#include "memory/pagemap.h"
#include "memory/vma.h"

static uint8_t* shadow_buffer = nullptr;
static uint8_t* fb_address    = nullptr;
static term_font_t* curr_font = nullptr;

static uint64_t fb_width  = 0;
static uint64_t fb_height = 0;
static uint64_t fb_pitch  = 0;
static uint64_t fb_size   = 0;
static uint8_t fb_bpp     = 0;

static uint8_t r_size  = 8;
static uint8_t r_shift = 16;

static uint8_t g_size  = 8;
static uint8_t g_shift = 8;

static uint8_t b_size  = 8;
static uint8_t b_shift = 0;

static size_t term_cols = 0;
static size_t term_rows = 0;
static size_t cursor_x  = 0;
static size_t cursor_y  = 0;

static size_t dirty_min_y = 0;
static size_t dirty_max_y = 0;
static bool is_dirty      = false;

static size_t font_w      = 8;
static size_t font_h      = 16;
static size_t font_stride = 1;

typedef struct {
    uint64_t fg;          // Current Active FG
    uint64_t bg;          // Current Active BG
    uint64_t default_fg;  // Default FG (White)
    uint64_t default_bg;  // Default BG (Black)
    bool bold;
    bool underline;
    bool reverse;
} term_style_t;

static term_style_t style;

#define ANSI_MAX_PARAMS 16
typedef struct {
    enum {
        STATE_NORMAL,
        STATE_ESC,
        STATE_CSI,
    } state;

    int params[ANSI_MAX_PARAMS];
    int param_count;
    int current_param;
    bool has_param;

    size_t saved_x;
    size_t saved_y;
} ansi_ctx_t;

static ansi_ctx_t ansi = {0};

static inline uint64_t scale_channel(uint8_t val, uint8_t mask) {
    if (mask == 0) {
        return 0;
    }

    if (mask == 8) {
        return val;
    }

    // Upscale
    if (mask > 8) {
        return ((uint64_t)val << (mask - 8));
    }

    // Downscale
    return val >> (8 - mask);
}

static inline uint64_t rgb_to_native(uint8_t r, uint8_t g, uint8_t b) {
    uint64_t color = 0;

    color |= (scale_channel(r, r_size) << r_shift);
    color |= (scale_channel(g, g_size) << g_shift);
    color |= (scale_channel(b, b_size) << b_shift);

    return color;
}

static uint64_t get_standard_color(int idx, bool bright) {
    static const uint8_t pallete[8][3] = {
        {0, 0, 0},
        {170, 0, 0},
        {0, 170, 0},
        {170, 85, 0},
        {0, 0, 170},
        {170, 0, 170},
        {0, 170, 170},
        {170, 170, 170}
    };

    static const uint8_t bright_pallete[8][3] = {
        {85, 85, 85},
        {255, 85, 85},
        {85, 255, 85},
        {255, 255, 85},
        {85, 85, 255},
        {255, 85, 255},
        {85, 255, 255},
        {255, 255, 255}
    };

    uint8_t r = bright ? bright_pallete[idx][0] : pallete[idx][0];
    uint8_t g = bright ? bright_pallete[idx][1] : pallete[idx][1];
    uint8_t b = bright ? bright_pallete[idx][2] : pallete[idx][2];

    return rgb_to_native(r, g, b);
}

void term_init(term_font_t* font) {
    if (!framebuffer_request.response) {
        return;
    }

    struct limine_framebuffer* fb = framebuffer_request.response->framebuffers[0];

    fb_address = fb->address;
    curr_font  = font;

    font_w      = font->width;
    font_h      = font->height;
    font_stride = font->stride;

    fb_height = fb->height;
    fb_width  = fb->width;
    fb_pitch  = fb->pitch;
    fb_bpp    = (uint8_t)(fb->bpp / 8);
    fb_size   = fb_height * fb_width * fb_bpp;

    term_cols = fb_width / font_w;
    term_rows = fb_height / font_h;

    if (fb->memory_model == LIMINE_FRAMEBUFFER_RGB) {
        r_size  = fb->red_mask_size;
        r_shift = fb->red_mask_shift;

        g_size  = fb->green_mask_size;
        g_shift = fb->green_mask_shift;

        b_size  = fb->blue_mask_size;
        b_shift = fb->blue_mask_shift;
    }

    style.fg = style.default_fg = rgb_to_native(255, 255, 255);
    style.bg = style.default_bg = rgb_to_native(0, 0, 0);

    style.bold      = false;
    style.underline = false;
    style.reverse   = false;

    shadow_buffer = (void*)vmalloc(
        kernel_space,
        nullptr,
        fb_size,
        VMM_FLAG_READ | VMM_FLAG_WRITE | VMM_FLAG_GLOBAL,
        CACHE_WRITE_BACK,
        PAGE_SIZE_SMALL
    );

    memset(shadow_buffer, 0, fb_size);
    memset(fb_address, 0, fb_size);

    cursor_x = cursor_y = 0;
    dirty_max_y         = 0;
    dirty_min_y         = fb_height;
    is_dirty            = false;
}

static inline void mark_dirty(size_t y, size_t height) {
    size_t y_end = y + height;

    if (y_end > fb_height) {
        y_end = fb_height;
    }

    if (!is_dirty) {
        dirty_min_y = y;
        dirty_max_y = y_end;
        is_dirty    = true;
    } else {
        if (y < dirty_min_y) {
            dirty_min_y = y;
        }

        if (y_end > dirty_max_y) {
            dirty_max_y = y_end;
        }
    }
}

void term_refresh(void) {
    if (!is_dirty) {
        return;
    }

    size_t start_offset = dirty_min_y * fb_pitch;
    size_t copy_len     = (dirty_max_y - dirty_min_y) * fb_pitch;

    memcpy(fb_address + start_offset, shadow_buffer + start_offset, copy_len);

    dirty_min_y = fb_height;
    dirty_max_y = 0;
    is_dirty    = false;
}

static void term_fill_rect(size_t x, size_t y, size_t w, size_t h, uint64_t color) {
    for (size_t row = 0; row < h; ++row) {
        size_t cy = y + row;

        if (cy >= fb_height) {
            break;
        }

        size_t row_offset   = cy * fb_pitch;
        size_t pixel_offset = row_offset + (x * fb_bpp);

        for (size_t col = 0; col < w; ++col) {
            if (x + col >= fb_width) {
                break;
            }

            if (fb_bpp == 4) {
                mmio_write32(shadow_buffer + pixel_offset, (uint32_t)color);
            } else if (fb_bpp == 8) {
                mmio_write64(shadow_buffer + pixel_offset, color);
            } else if (fb_bpp == 2) {
                mmio_write16(shadow_buffer + pixel_offset, (uint16_t)color);
            } else {
                uint8_t* p = shadow_buffer + pixel_offset;
                p[0]       = color & 0xff;
                p[1]       = (color >> 8) & 0xff;
                p[2]       = (color >> 16) & 0xff;
            }

            pixel_offset += fb_bpp;
        }
    }
}

static void term_scroll(void) {
    size_t row_bytes    = fb_pitch * font_h;
    size_t screen_bytes = fb_pitch * fb_height;
    size_t move_bytes   = screen_bytes - row_bytes;

    memmove(shadow_buffer, shadow_buffer + row_bytes, move_bytes);

    term_fill_rect(0, fb_height - font_h, fb_width, font_h, style.default_bg);
    mark_dirty(0, fb_height);
}

static void term_draw_char(char ch, size_t cx, size_t cy) {
    const uint8_t* glyph = curr_font->data + ((uint8_t)ch * font_h * font_stride);

    size_t screen_y_start = cy * font_h;
    size_t screen_x_start = cx * font_w;
    size_t base_offset    = (screen_y_start * fb_pitch) + (screen_x_start * fb_bpp);

    uint64_t fg = style.fg;
    uint64_t bg = style.bg;

    if (style.reverse) {
        uint64_t tmp = fg;
        fg           = bg;
        bg           = tmp;
    }

    const size_t underline_row = (font_h > 2) ? font_h - 2 : font_h - 1;

    for (size_t y = 0; y < font_h; ++y) {
        const uint8_t* glyph_row = glyph + (y * font_stride);
        size_t offset            = base_offset + (y * fb_pitch);

        bool is_underline_px = style.underline && (y == underline_row);

        for (size_t x = 0; x < font_w; ++x) {
            size_t byte_idx = x / 8;
            size_t bit_idx  = 7 - (x % 8);

            bool on = (glyph_row[byte_idx] >> bit_idx) & 1;

            if (is_underline_px) {
                on = true;
            }

            uint64_t color = on ? fg : bg;

            if (fb_bpp == 4) {
                mmio_write32(shadow_buffer + offset, (uint32_t)color);
            } else if (fb_bpp == 8) {
                mmio_write64(shadow_buffer + offset, color);
            } else if (fb_bpp == 2) {
                mmio_write16(shadow_buffer + offset, (uint16_t)color);
            } else {
                uint8_t* p = shadow_buffer + offset;
                p[0]       = color & 0xff;
                p[1]       = (color >> 8) & 0xff;
                p[2]       = (color >> 16) & 0xff;
            }

            offset += fb_bpp;
        }
    }

    mark_dirty(cy * font_h, font_h);
}

static void ansi_insert_line(int n) {
    size_t start_y_px = cursor_y * font_h;
    size_t total_h_px = (term_rows - cursor_y) * font_h;
    size_t move_px    = (size_t)n * font_h;

    if (move_px >= total_h_px) {
        term_fill_rect(0, start_y_px, fb_width, total_h_px, style.bg);
    } else {
        uint8_t* src = shadow_buffer + (start_y_px * fb_pitch);
        uint8_t* dst = src + (move_px * fb_pitch);
        size_t size  = (total_h_px - move_px) * fb_pitch;

        memmove(dst, src, size);
        term_fill_rect(0, start_y_px, fb_width, move_px, style.bg);
    }

    mark_dirty(start_y_px, total_h_px);
}

static void ansi_delete_line(int n) {
    size_t start_y_px = cursor_y * font_h;
    size_t total_h_px = (term_rows - cursor_y) * font_h;
    size_t move_px    = (size_t)n * font_h;

    if (move_px >= total_h_px) {
        term_fill_rect(0, start_y_px, fb_width, total_h_px, style.bg);
    } else {
        uint8_t* dst = shadow_buffer + (start_y_px * fb_pitch);
        uint8_t* src = dst + (move_px * fb_pitch);
        size_t size  = (total_h_px - move_px) * fb_pitch;

        memmove(dst, src, size);
        term_fill_rect(0, fb_height - move_px, fb_width, move_px, style.bg);
    }

    mark_dirty(start_y_px, total_h_px);
}

static void ansi_delete_char(int n) {
    size_t row_off    = cursor_y * font_h * fb_pitch;
    size_t start_x_px = cursor_x * font_w;
    size_t move_px    = (size_t)n * font_w;
    size_t total_w_px = (term_cols - cursor_x) * font_w;

    if (move_px >= total_w_px) {
        term_fill_rect(start_x_px, cursor_y * font_h, total_w_px, font_h, style.bg);
    } else {
        for (size_t y = 0; y < font_h; y++) {
            uint8_t* line = shadow_buffer + row_off + (y * fb_pitch);
            uint8_t* dst  = line + (start_x_px * fb_bpp);
            uint8_t* src  = dst + (move_px * fb_bpp);

            memmove(dst, src, (total_w_px - move_px) * fb_bpp);
        }

        size_t clear_x = (term_cols - (size_t)n) * font_w;
        term_fill_rect(clear_x, cursor_y * font_h, (size_t)n * font_w, font_h, style.bg);
    }

    mark_dirty(cursor_y * font_h, font_h);
}

static void ansi_insert_char(int n) {
    size_t row_off    = cursor_y * font_h * fb_pitch;
    size_t start_x_px = cursor_x * font_w;
    size_t move_px    = (size_t)n * font_w;
    size_t total_w_px = (term_cols - cursor_x) * font_w;

    if (move_px >= total_w_px) {
        term_fill_rect(start_x_px, cursor_y * font_h, total_w_px, font_h, style.bg);
    } else {
        for (size_t y = 0; y < font_h; y++) {
            uint8_t* line = shadow_buffer + row_off + (y * fb_pitch);
            uint8_t* src  = line + (start_x_px * fb_bpp);
            uint8_t* dst  = src + (move_px * fb_bpp);

            memmove(dst, src, (total_w_px - move_px) * fb_bpp);
        }

        term_fill_rect(start_x_px, cursor_y * font_h, (size_t)n * font_w, font_h, style.bg);
    }

    mark_dirty(cursor_y * font_h, font_h);
}

static int get_param(int idx, int default_val) {
    return (idx < ansi.param_count) ? ansi.params[idx] : default_val;
}

static void ansi_render_color(void) {
    if (ansi.param_count == 0) {
        style.fg        = style.default_fg;
        style.bg        = style.default_bg;
        style.bold      = false;
        style.underline = false;
        style.reverse   = false;
        return;
    }

    for (int i = 0; i < ansi.param_count; i++) {
        int n = ansi.params[i];

        if (n == 0) {
            style.fg        = style.default_fg;
            style.bg        = style.default_bg;
            style.bold      = false;
            style.underline = false;
            style.reverse   = false;
        } else if (n == 1) {
            style.bold = true;
        } else if (n == 4) {
            style.underline = true;
        } else if (n == 7) {
            style.reverse = true;
        } else if (n == 22) {
            style.bold = false;
        } else if (n == 24) {
            style.underline = false;
        } else if (n == 27) {
            style.reverse = false;
        } else if (n >= 30 && n <= 37) {
            style.fg = get_standard_color(n - 30, style.bold);
        } else if (n >= 40 && n <= 47) {
            style.bg = get_standard_color(n - 40, false);
        } else if (n >= 90 && n <= 97) {
            style.fg = get_standard_color(n - 90, true);
        } else if (n >= 100 && n <= 107) {
            style.bg = get_standard_color(n - 100, true);
        } else if (n == 39) {
            style.fg = style.default_fg;
        } else if (n == 49) {
            style.bg = style.default_bg;
        } else if ((n == 38 || n == 48) && i + 4 < ansi.param_count && ansi.params[i + 1] == 2) {
            uint64_t color = rgb_to_native(
                (uint8_t)ansi.params[i + 2],
                (uint8_t)ansi.params[i + 3],
                (uint8_t)ansi.params[i + 4]
            );

            if (n == 38) {
                style.fg = color;
            } else {
                style.bg = color;
            }

            i += 4;
        }
    }
}

static void term_writec(char c) {
    if (ansi.state == STATE_NORMAL) {
        if (c == '\033') {
            ansi.state = STATE_ESC;
            return;
        }

        if (c == '\n') {
            cursor_x = 0;
            cursor_y++;
        } else if (c == '\r') {
            cursor_x = 0;
        } else if (c == '\b') {
            if (cursor_x > 0) {
                cursor_x--;
            }
        } else if (c == '\t') {
            cursor_x = align_down(cursor_x, 4);
        } else {
            if (cursor_x >= term_cols) {
                cursor_x = 0;
                cursor_y++;
            }

            if (cursor_y >= term_rows) {
                term_scroll();
                cursor_y--;
            }

            term_draw_char(c, cursor_x, cursor_y);
            cursor_x++;
        }
        if (cursor_y >= term_rows) {
            term_scroll();
            cursor_y--;
        }

        return;
    } else if (ansi.state == STATE_ESC) {
        if (c == '[') {
            ansi.state         = STATE_CSI;
            ansi.param_count   = 0;
            ansi.current_param = 0;
            ansi.has_param     = false;
        } else
            ansi.state = STATE_NORMAL;
        return;
    } else if (ansi.state == STATE_CSI) {
        if (c >= '0' && c <= '9') {
            ansi.current_param = ansi.current_param * 10 + (c - '0');
            ansi.has_param     = true;
        } else if (c == ';') {
            if (ansi.param_count < ANSI_MAX_PARAMS) {
                ansi.params[ansi.param_count++] = ansi.current_param;
            }

            ansi.current_param = 0;
            ansi.has_param     = false;
        } else if (c >= 0x40 && c <= 0x7E) {
            if (ansi.has_param && ansi.param_count < ANSI_MAX_PARAMS) {
                ansi.params[ansi.param_count++] = ansi.current_param;
            }

            int p0 = get_param(0, 1);
            int p1 = get_param(1, 1);

            switch (c) {
                case 'A':
                    cursor_y -= (cursor_y >= p0) ? (size_t)p0 : 0;
                    break;
                case 'B':
                    cursor_y += (size_t)p0;

                    if (cursor_y >= term_rows) {
                        cursor_y = term_rows - 1;
                    }

                    break;
                case 'C':
                    cursor_x += (size_t)p0;

                    if (cursor_x >= term_cols) {
                        cursor_x = term_cols - 1;
                    }

                    break;
                case 'D':
                    cursor_x -= (cursor_x >= p0) ? (size_t)p0 : 0;
                    break;
                case 'H':
                case 'f': {
                    cursor_y = (p0 > 0) ? (size_t)p0 - 1 : 0;
                    cursor_x = (p1 > 0) ? (size_t)p1 - 1 : 0;
                    if (cursor_x >= term_cols) {
                        cursor_x = term_cols - 1;
                    }

                    if (cursor_y >= term_rows) {
                        cursor_y = term_rows - 1;
                    }

                    break;
                }
                case 'J':  // Erase Display
                {
                    int m = get_param(0, 0);

                    if (m == 2) {
                        term_fill_rect(0, 0, fb_width, fb_height, style.bg);
                        cursor_x = 0;
                        cursor_y = 0;
                    } else if (m == 0) {  // Cursor Down
                        term_fill_rect(
                            cursor_x * font_w,
                            cursor_y * font_h,
                            fb_width - (cursor_x * font_w),
                            font_h,
                            style.bg
                        );

                        if (cursor_y < term_rows - 1) {
                            term_fill_rect(
                                0,
                                (cursor_y + 1) * font_h,
                                fb_width,
                                (term_rows - cursor_y - 1) * font_h,
                                style.bg
                            );
                        }
                    }

                    mark_dirty(0, fb_height);
                    break;
                }
                case 'K':  // Erase Line
                {
                    int m       = get_param(0, 0);
                    size_t y_px = cursor_y * font_h;

                    if (m == 0) {
                        term_fill_rect(
                            cursor_x * font_w,
                            y_px,
                            fb_width - (cursor_x * font_w),
                            font_h,
                            style.bg
                        );
                    } else if (m == 1) {
                        term_fill_rect(0, y_px, cursor_x * font_w, font_h, style.bg);
                    } else if (m == 2) {
                        term_fill_rect(0, y_px, fb_width, font_h, style.bg);
                    }

                    mark_dirty(y_px, font_h);
                    break;
                }
                case 'L':
                    ansi_insert_line(p0);
                    break;
                case 'M':
                    ansi_delete_line(p0);
                    break;
                case 'P':
                    ansi_delete_char(p0);
                    break;
                case '@':
                    ansi_insert_char(p0);
                    break;
                case 'm':
                    ansi_render_color();
                    break;
                case 's':
                    ansi.saved_x = cursor_x;
                    ansi.saved_y = cursor_y;
                    break;
                case 'u':
                    cursor_x = ansi.saved_x;
                    cursor_y = ansi.saved_y;
                    break;
                default:
                    break;
            }
            ansi.state = STATE_NORMAL;
        }
    }
}

void term_write(const char* str) {
    while (*str != '\0') {
        term_writec(*str++);
    }

    term_refresh();
}

bool term_is_initialized(void) {
    return shadow_buffer != nullptr;
}