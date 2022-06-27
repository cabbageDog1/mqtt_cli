#ifndef CNIOT_ATLAS_ATLAS_SCHEDULER_H
#define CNIOT_ATLAS_ATLAS_SCHEDULER_H

#include <cniot_atlas_code.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define C_SCHEDULER_INTERVAL_TIME     (1000)

CNIOT_STATUS_CODE cniot_atlas_scheduler_initialize(void);

CNIOT_STATUS_CODE cniot_atlas_scheduler_finalize(void);

CNIOT_STATUS_CODE cniot_atlas_scheduler_startup(void);

CNIOT_STATUS_CODE cniot_atlas_scheduler_shutdown(void);

#if defined(__cplusplus)
}
#endif

#endif //CNIOT_ATLAS_ATLAS_SCHEDULER_H
