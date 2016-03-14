#ifndef MOD_DEFENDER_NXPARSER_H
#define MOD_DEFENDER_NXPARSER_H

#include <apr_file_io.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include "Util.h"
#include <regex>
#include <unordered_map>

//#define DEBUG_CONFIG_MAINRULE
#ifdef DEBUG_CONFIG_MAINRULE
#define DEBUG_CONF_MR(x) do { std::cerr << x; } while (0)
#else
#define DEBUG_CONF_MR(x)
#endif

//#define DEBUG_CONFIG_CHECKRULE
#ifdef DEBUG_CONFIG_CHECKRULE
#define DEBUG_CONF_CR(x) do { std::cerr << x; } while (0)
#else
#define DEBUG_CONF_CR(x)
#endif

#define DEBUG_CONFIG_BASICRULE
#ifdef DEBUG_CONFIG_BASICRULE
#define DEBUG_CONF_BR(x) do { std::cerr << x; } while (0)
#else
#define DEBUG_CONF_BR(x)
#endif

using std::pair;
using std::vector;
using std::string;
using std::cerr;
using std::stringstream;
using std::endl;
using std::flush;
using std::istream_iterator;
using std::istringstream;
using std::regex;
using std::unordered_map;

typedef struct {
    bool rxMz:1;
    regex matchPaternRx;
    const char *matchPaternStr;
    bool negative = false;
    vector<pair<const char *, int>> scores;
    const char *msg;
    bool headersMz = false;
    bool urlMz = false;
    bool argsMz = false;
    bool bodyMz = false;
    int id;
} main_rule_t;

typedef enum {
    SUP_OR_EQUAL,
    SUP,
    INF_OR_EQUAL,
    INF
} comparator_t;

typedef enum {
    BLOCK,
    DROP,
    ALLOW,
    LOG
} rule_action_t;

typedef struct {
    comparator_t comparator;
    int limit;
    rule_action_t action;
} check_rule_t;

typedef struct {
    bool bodyVar = false; // match in [name] var of body
    bool headersVar = false; // match in [name] var of headers
    bool argsVar = false; // match in [name] var of args
    bool specificUrl = false; // match on URL [name]
    const char *target; // to be used for string match zones
    regex *targetRx; // to be used for regexed match zones
} custom_rule_location_t;

typedef struct {
    bool body = false; // match in full body (POST DATA)
    bool bodyVar = false; // match in [name] var of body
    bool headers = false; // match in all headers
    bool headersVar = false; // match in [name] var of headers
    bool url = false; // match in URI
    bool args = false; // match in args (bla.php?<ARGS>)
    bool argsVar = false; // match in [name] var of args
    bool flags = false; // match on a global flag : weird_request, big_body etc.
    bool fileExt = false; // match on file upload extension
    /* set if defined "custom" match zone (GET_VAR/POST_VAR/...)  */
    vector<int> ids;
    const char *target;
} whitelist_location_t;

typedef struct {
    bool rxMz = false;
    regex matchPaternRx;
    bool negative = false;
    const char *matchPaternStr;
    bool bodyMz = false;
    bool bodyVarMz = false;
    bool headersMz = false;
    bool headersVarMz = false;
    bool urlMz = false;
    bool urlSpecifiedMz = false;
    bool argsMz = false;
    bool argsVarMz = false;
    bool fileExtMz = false;
    bool customZone = false;
    bool targetName = false;
    vector<custom_rule_location_t> customLocations;
} basic_rule_t;

typedef struct {
    vector<int> wlIds;
} http_rule_t;

class NxParser {

public:
    static vector<main_rule_t> parseMainRules(apr_pool_t *pool, apr_array_header_t *rulesArray);

    static unordered_map<string, check_rule_t> parseCheckRules(apr_array_header_t *rulesArray);

    static vector<basic_rule_t> parseBasicRules(apr_pool_t *pool, apr_array_header_t *rulesArray);
};


#endif //MOD_DEFENDER_NXPARSER_H
