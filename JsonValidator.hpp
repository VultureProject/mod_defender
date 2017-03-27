/*                       _        _       __                _
 *   _ __ ___   ___   __| |    __| | ___ / _| ___ _ __   __| | ___ _ __
 *  | '_ ` _ \ / _ \ / _` |   / _` |/ _ \ |_ / _ \ '_ \ / _` |/ _ \ '__|
 *  | | | | | | (_) | (_| |  | (_| |  __/  _|  __/ | | | (_| |  __/ |
 *  |_| |_| |_|\___/ \__,_|___\__,_|\___|_|  \___|_| |_|\__,_|\___|_|
 *                       |_____|
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#ifndef MOD_DEFENDER_JSONVALIDATOR_H
#define MOD_DEFENDER_JSONVALIDATOR_H

#include "Util.h"

class RuntimeScanner;

/*
** To avoid getting DoS'ed, define max depth
** for JSON parser, as it is recursive
*/
#define JSON_MAX_DEPTH 10

/*
** this structure is used only for json parsing.
*/
typedef struct {
    str_t json;
    u_char *src;
    unsigned long off, len;
    u_char c;
    int depth;
    str_t ckey;
} json_t;

class JsonValidator {
    friend class RuntimeScanner;
private:
    RuntimeScanner& runtimeScanner;
public:
    JsonValidator(RuntimeScanner &runtimeScanner) : runtimeScanner(runtimeScanner) {}
    bool jsonObj(json_t &js);
    bool jsonVal(json_t &js);
    bool jsonArray(json_t &js);
    bool jsonQuoted(json_t &js, str_t *ve);
    void jsonParse(u_char *src, unsigned long len);
    bool jsonForward(json_t &js);
    bool jsonSeek(json_t &js, unsigned char seek);
};

#endif //MOD_DEFENDER_JSONVALIDATOR_H
