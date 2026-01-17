#ifndef KERNEL_DRIVERS_TERM_H
#define KERNEL_DRIVERS_TERM_H 1

#ifdef __cplusplus
extern "C" {
#endif

void term_init(void);
void term_refresh(void);

void term_write(const char* str);
bool term_is_initialized(void);

#ifdef __cplusplus
}
#endif

#endif