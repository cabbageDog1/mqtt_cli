#ifndef CNIOT_ATLAS_ATLAS_REPORT_H
#define CNIOT_ATLAS_ATLAS_REPORT_H

#include "cniot_atlas.h"
#include "wrappers_defs.h"

typedef  enum {
    REPORT_ACTION =0,
    REPORT_UPLOAD = 1,
    REPORT_DOWNLOAD = 2
}CNIOT_REPORT_LOGLINE;

CNIOT_STATUS_CODE cniot_atlas_report_initialize(void);

CNIOT_STATUS_CODE cniot_atlas_report_finalize(void);

CNIOT_STATUS_CODE cniot_atlas_report_startup(void);

CNIOT_STATUS_CODE cniot_atlas_report_shutdown(void);

CNIOT_STATUS_CODE cniot_atlas_report_proc();

CNIOT_STATUS_CODE cniot_atlas_report(CNIOT_REPORT_LOGLINE logLine, const char *action, char *traceId,
                                     uint64_t beginTime, uint32_t cost,
                                     const char *content, CNIOT_STATUS_CODE code);

CNIOT_STATUS_CODE cniot_atlas_dns_resolver(const char *addr, int code, uint32_t ip);

CNIOT_STATUS_CODE cniot_atlas_scheduler_count();

CNIOT_STATUS_CODE cniot_atlas_heartbeat_count();

CNIOT_STATUS_CODE cniot_atlas_build_core_message(char *buff, int *buff_len);

CNIOT_STATUS_CODE cniot_atlas_build_failed_message(char * trace_id, uint32_t cost, const char *service, const char *bizKey);

#endif
