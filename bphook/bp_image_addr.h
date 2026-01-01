#ifndef BP_IMAGE_ADDR_H
#define BP_IMAGE_ADDR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns absolute address (slide + offset). Returns 0 if not found.
uintptr_t getAbsoluteAddress(const char *image_name, uintptr_t offset);

#ifdef __cplusplus
}
#endif

#endif
