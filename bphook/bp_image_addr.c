#include "bp_image_addr.h"
#include <mach-o/dyld.h>
#include <string.h>

uintptr_t getAbsoluteAddress(const char *image_name, uintptr_t offset) {
    if (!image_name) {
        return _dyld_get_image_vmaddr_slide(0) + offset;
    }

    uint32_t count = _dyld_image_count();
    size_t search_len = strlen(image_name);
    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) {
            continue;
        }
        size_t path_len = strlen(path);
        if (strcmp(path, image_name) == 0) {
            return _dyld_get_image_vmaddr_slide(i) + offset;
        }
        if (path_len >= search_len &&
            strcmp(path + path_len - search_len, image_name) == 0) {
            return _dyld_get_image_vmaddr_slide(i) + offset;
        }
    }

    return 0;
}
