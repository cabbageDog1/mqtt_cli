#ifndef CNIOT_ATLAS_ATLAS_LOGGER_H
#define CNIOT_ATLAS_ATLAS_LOGGER_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "cniot_atlas_code.h"
#include "infra_log.h"

#define LOG_NONE_LEVEL                  (0)     /* no log printed at all */
#define LOG_CRIT_LEVEL                  (1)     /* current application aborting */
#define LOG_ERR_LEVEL                   (2)     /* current app-module error */
#define LOG_WARNING_LEVEL               (3)     /* using default parameters */
#define LOG_INFO_LEVEL                  (4)     /* running messages */
#define LOG_DEBUG_LEVEL                 (5)     /* debugging messages */
#define LOG_FLOW_LEVEL                  (6)     /* code/packet flow messages */

#define logger_emerg(...)             log_emerg(g_module, __VA_ARGS__)
#define logger_crit(...)              log_crit(g_module, __VA_ARGS__)
#define logger_err(...)               log_err(g_module, __VA_ARGS__)
#define logger_warning(...)           log_warning(g_module, __VA_ARGS__)
#define logger_info(...)              log_info(g_module, __VA_ARGS__)
#define logger_debug(...)             log_debug(g_module, __VA_ARGS__)


int     atlas_get_loglevel(void);

void    atlas_set_loglevel(int level);


#if defined(__cplusplus)
}
#endif

#endif //CNIOT_ATLAS_ATLAS_LOGGER_H
