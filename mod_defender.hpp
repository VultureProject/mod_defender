#ifndef MOD_DEFENDER_HPP
#define MOD_DEFENDER_HPP

/*
 * To install mod_defender:
 * sudo apxs -n defender -i mod_defender.so
 */

#ifdef __cplusplus
#define EXTERN_C_BLOCK_BEGIN    extern "C" {
#define EXTERN_C_BLOCK_END      }
#define EXTERN_C_FUNC           extern "C"
#else
#define EXTERN_C_BLOCK_BEGIN
#define EXTERN_C_BLOCK_END
#define EXTERN_C_FUNC
#endif

#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>

#endif /* MOD_DEFENDER_HPP */

