/*                       _        _       __                _
 *   _ __ ___   ___   __| |    __| | ___ / _| ___ _ __   __| | ___ _ __
 *  | '_ ` _ \ / _ \ / _` |   / _` |/ _ \ |_ / _ \ '_ \ / _` |/ _ \ '__|
 *  | | | | | | (_) | (_| |  | (_| |  __/  _|  __/ | | | (_| |  __/ |
 *  |_| |_| |_|\___/ \__,_|___\__,_|\___|_|  \___|_| |_|\__,_|\___|_|
 *                       |_____|
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#include "JsonValidator.hpp"
#include "RuntimeScanner.hpp"
#include "mod_defender.hpp"
#include "RuleParser.h"

bool JsonValidator::jsonForward(json_t &js) {
    while ((*(js.src + js.off) == ' ' ||
            *(js.src + js.off) == '\t' ||
            *(js.src + js.off) == '\n' ||
            *(js.src + js.off) == '\r') && js.off < js.len) {
        js.off++;
    }
    js.c = *(js.src + js.off);
    return true;
}

/*
** used to fast forward in json POSTS,
** we skip whitespaces/tab/CR/LF
*/
bool JsonValidator::jsonSeek(json_t &js, unsigned char seek) {
    jsonForward(js);
    return js.c == seek;
}

/*
** extract a quoted strings,
** JSON spec only supports double-quoted strings,
** so do we.
*/
bool JsonValidator::jsonQuoted(json_t &js, str_t *ve) {
    u_char *vn_start, *vn_end = NULL;

    if (*(js.src + js.off) != '"')
        return false;
    js.off++;
    vn_start = js.src + js.off;
    /* extract varname inbetween "..."*/
    while (js.off < js.len) {
        /* skip next character if backslashed */
        if (*(js.src + js.off) == '\\') {
            js.off += 2;
            if (js.off >= js.len) break;
        }
        if (*(js.src + js.off) == '"') {
            vn_end = js.src + js.off;
            js.off++;
            break;
        }
        js.off++;
    }
    if (!vn_start || !vn_end)
        return false;
    if (!*vn_start || !*vn_end)
        return false;
    ve->data = vn_start;
    ve->len = vn_end - vn_start;
    return true;
}

/*
** an array is values separated by ','
*/
bool JsonValidator::jsonArray(json_t &js) {
    bool rc;

    js.c = *(js.src + js.off);
    if (js.c != '[' || js.depth > JSON_MAX_DEPTH)
        return false;
    js.off++;
    do {
        rc = jsonVal(js);
        /* if we cannot extract the value,
           we may have reached array end. */
        if (!rc)
            break;
        jsonForward(js);
        if (js.c == ',') {
            js.off++;
            jsonForward(js);
        } else break;
    } while (rc);
    return js.c == ']';
}


bool JsonValidator::jsonVal(json_t &js) {
    str_t val;
    bool ret;

    val.data = NULL;
    val.len = 0;

    jsonForward(js);
    if (js.c == '"') {
        ret = jsonQuoted(js, &val);
        if (ret) {
            /* parse extracted values. */
            string jsckey = string((char *) js.ckey.data, js.ckey.len);
            string value = string((char *) val.data, val.len);
            transform(jsckey.begin(), jsckey.end(), jsckey.begin(), tolower);
            transform(value.begin(), value.end(), value.begin(), tolower);
            scanner.basestrRuleset(BODY, jsckey, value, bodyRules);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, scanner.r, "JSON '%s' : '%s'", (char *) js.ckey.data,
                           (char *) val.data);
        }
        return ret;
    }
    if ((js.c >= '0' && js.c <= '9') || js.c == '-') {
        val.data = js.src + js.off;
        while (((*(js.src + js.off) >= '0' && *(js.src + js.off) <= '9') ||
                *(js.src + js.off) == '.' || *(js.src + js.off) == '-') && js.off < js.len) {
            val.len++;
            js.off++;
        }
        /* parse extracted values. */
        string jsckey = string((char *) js.ckey.data, js.ckey.len);
        string value = string((char *) val.data, val.len);
        transform(jsckey.begin(), jsckey.end(), jsckey.begin(), tolower);
        transform(value.begin(), value.end(), value.begin(), tolower);
        scanner.basestrRuleset(BODY, jsckey, value, bodyRules);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, scanner.r, "JSON '%s' : '%s'", (char *) js.ckey.data,
                       (char *) val.data);
        return true;
    }
    if (!strncasecmp((const char *) (js.src + js.off), (const char *) "true", 4) ||
        !strncasecmp((const char *) (js.src + js.off), (const char *) "false", 5) ||
        !strncasecmp((const char *) (js.src + js.off), (const char *) "null", 4)) {
        js.c = *(js.src + js.off);
        /* we don't check static values, do we ?! */
        val.data = js.src + js.off;
        if (js.c == 'F' || js.c == 'f') {
            js.off += 5;
            val.len = 5;
        } else {
            js.off += 4;
            val.len = 4;
        }
        /* parse extracted values. */
        string jsckey = string((char *) js.ckey.data, js.ckey.len);
        string value = string((char *) val.data, val.len);
        transform(jsckey.begin(), jsckey.end(), jsckey.begin(), tolower);
        transform(value.begin(), value.end(), value.begin(), tolower);
        scanner.basestrRuleset(BODY, jsckey, value, bodyRules);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, scanner.r, "JSON '%s' : '%s'", (char *) js.ckey.data,
                       (char *) val.data);
        return true;
    }

    if (js.c == '[') {
        ret = jsonArray(js);
        if (js.c != ']')
            return false;
        js.off++;
        return (ret);
    }
    if (js.c == '{') {
        /*
        ** if sub-struct, parse key without value :
        ** "foobar" : { "bar" : [1,2,3]} => "foobar" parsed alone.
        ** this is to avoid "foobar" left unparsed, as we won't have
        ** key/value here with "foobar" as a key.
        */
        string jsckey = string((char *) js.ckey.data, js.ckey.len);
        transform(jsckey.begin(), jsckey.end(), jsckey.begin(), tolower);
        scanner.basestrRuleset(BODY, jsckey, empty, bodyRules);

        ret = jsonObj(js);
        jsonForward(js);
        if (js.c != '}')
            return false;
        js.off++;
        return (ret);
    }
    return false;
}


bool JsonValidator::jsonObj(json_t &js) {
    js.c = *(js.src + js.off);

    if (js.c != '{' || js.depth > JSON_MAX_DEPTH)
        return false;
    js.off++;

    do {
        jsonForward(js);
        /* check subs (arrays, objects) */
        switch (js.c) {
            case '[': /* array */
                js.depth++;
                jsonArray(js);
                if (!jsonSeek(js, ']'))
                    return false;
                js.off++;
                js.depth--;
                break;
            case '{': /* sub-object */
                js.depth++;
                jsonObj(js);
                if (js.c != '}')
                    return false;
                js.off++;
                js.depth--;
                break;
            case '"': /* key : value, extract and parse. */
                if (!jsonQuoted(js, &(js.ckey)))
                    return false;
                if (!jsonSeek(js, ':'))
                    return false;
                js.off++;
                jsonForward(js);
                if (!jsonVal(js))
                    return false;
            default:
                break;
        }
        jsonForward(js);
        /* another element ? */
        if (js.c == ',') {
            js.off++;
            jsonForward(js);
            continue;

        } else if (js.c == '}') {
            js.depth--;
            /* or maybe we just finished parsing this object */
            return true;
        } else {
            /* nothing we expected, die. */
            return false;
        }
    } while (js.off < js.len);

    return false;
}

/*
** Parse a JSON request
*/
void JsonValidator::jsonParse(u_char *src, unsigned long len) {
    json_t js;
    js.json.data = js.src = src;
    js.json.len = js.len = len;

    if (!jsonSeek(js, '{')) {
        scanner.applyRuleMatch(scanner.parser.invalidJson, 1, BODY, "missing opening brace", empty,
                                      false);
        scanner.block = scanner.drop = true;
        return;
    }
    if (!jsonObj(js)) {
        scanner.applyRuleMatch(scanner.parser.invalidJson, 1, BODY, "malformed json object", empty,
                                      false);
        scanner.block = scanner.drop = true;
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, scanner.r, "jsonObj returned error, apply invalid json.");
        return;
    }
    /* we are now on closing bracket, check for garbage. */
    js.off++;
    jsonForward(js);
    if (js.off != js.len) {
        scanner.applyRuleMatch(scanner.parser.invalidJson, 1, BODY, "garbage after the closing brace",
                                      empty, false);
        scanner.block = scanner.drop = true;
    }
}
