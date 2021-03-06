#ifndef CNIOT_ATLAS_INFRA_BINARYDATA_H
#define CNIOT_ATLAS_INFRA_BINARYDATA_H

#include "infra_types.h"

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif

#define IOT_BYTE_ORDER LITTLE_ENDIAN

#if IOT_BYTE_ORDER == BIG_ENDIAN
#define nghttp2_htonl(x) (x)
#define nghttp2_htons(x) (x)
#define nghttp2_ntohl(x) (x)
#define nghttp2_ntohs(x) (x)
#else
/* Windows requires ws2_32 library for ntonl family functions.  We
   define inline functions for those function so that we don't have
   dependeny on that lib. */

#ifdef _MSC_VER
#define STIN
#else
#define STIN
#endif

STIN uint32_t atlas_htonl(uint32_t hostlong);

STIN uint16_t atlas_htons(uint16_t hostshort);

STIN uint32_t atlas_ntohl(uint32_t netlong);

STIN uint16_t atlas_ntohs(uint16_t netshort);

#endif

#endif
