#include "atlas_logger.h"

int atlas_get_loglevel(void) {
    return LITE_get_loglevel();
}

void  atlas_set_loglevel(int level) {
    LITE_set_loglevel(level);
}
