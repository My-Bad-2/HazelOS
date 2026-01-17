#ifndef KERNEL_DRIVERS_TERM_H
#define KERNEL_DRIVERS_TERM_H 1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t* data;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
} term_font_t;

void term_init(term_font_t* font);
void term_refresh(void);

void term_write(const char* str);
bool term_is_initialized(void);

#ifdef __cplusplus
}
#endif

#endif