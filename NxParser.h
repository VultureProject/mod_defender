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

//#define DEBUG_CONFIG_BASICRULE
#ifdef DEBUG_CONFIG_BASICRULE
#define DEBUG_CONF_BR(x) do { std::cerr << x; } while (0)
#else
#define DEBUG_CONF_BR(x)
#endif

//#define DEBUG_CONFIG_MATCHZONE
#ifdef DEBUG_CONFIG_MATCHZONE
#define DEBUG_CONF_MZ(x) do { std::cerr << x; } while (0)
#else
#define DEBUG_CONF_MZ(x)
#endif

#define DEBUG_CONFIG_HASHTABLES
#ifdef DEBUG_CONFIG_HASHTABLES
#define DEBUG_CONF_HT(x) do { std::cerr << x; } while (0)
#else
#define DEBUG_CONF_HT(x)
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

/*
** struct used to store a specific match zone
** in conf : MATCH_ZONE:[GET_VAR|HEADER|POST_VAR]:VAR_NAME:
*/
typedef struct {
    bool bodyVar = false; // match in [name] var of body
    bool headersVar = false; // match in [name] var of headers
    bool argsVar = false; // match in [name] var of args
    bool specificUrl = false; // match on URL [name]
    const char *target; // to be used for string match zones
    regex *targetRx; // to be used for regexed match zones
} custom_rule_location_t;

/*
** WhiteList Rules Definition :
** A whitelist contains :
** - an URI
**
** - one or several sets containing :
**	- an variable name ('foo') associated with a zone ($GET_VAR:foo)
**	- one or several rules id to whitelist
*/
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
    vector<int> wlIds;
    const char *target;
} whitelist_location_t;

enum DUMMY_MATCH_ZONE {
    HEADERS = 0,
    URL,
    ARGS,
    BODY,
    FILE_EXT,
    UNKNOWN
};

/*
** this struct is used to aggregate all whitelist
** that point to the same URI or the same VARNAME
** all the "subrules" will then be stored in the "whitelist_locations"
*/
typedef struct {
    vector<whitelist_location_t> whitelistLocations;
    enum DUMMY_MATCH_ZONE zone; // zone to wich the WL applies
    bool uriOnly = false; // if the "name" is only an url, specify it
    bool targetName = false; // does the rule targets the name instead of the content
    string name; // hash key [#]URI#VARNAME
//    ngx_int_t hash;
    vector<int> ids;
} whitelist_rule_t;

typedef struct {
    bool rxMz = false;
    regex matchPaternRx;
    bool negative = false;
    const char *matchPaternStr;
    enum DUMMY_MATCH_ZONE zone;
    bool bodyMz = false;
    bool bodyVarMz = false;
    bool headersMz = false;
    bool headersVarMz = false;
    bool urlMz = false;
    bool urlSpecifiedMz = false;
    bool argsMz = false;
    bool argsVarMz = false;
    bool fileExtMz = false;
    bool customLocation = false; // set if defined "custom" match zone (GET_VAR/POST_VAR/...)
    bool targetName = false; // does the rule targets variable name instead ?
    vector<custom_rule_location_t> customLocations;
} basic_rule_t;

enum RULE_TYPE {
    MAIN_RULE = 0,
    BASIC_RULE
};

/* TOP level rule structure */
typedef struct {
    enum RULE_TYPE type; // type of the rule
    bool whitelist = false; // simply put a flag if it's a wlr, wl_id array will be used to store the whitelisted IDs
    vector<int> wlIds;

    /* "common" data for all rules */
    int id;
    const char *logMsg; // a specific log message
//    int score; //also handles DENY and ALLOW

    /* List of scores increased on rule match. */
//    ngx_array_t *sscores;
    vector<pair<const char *, int>> scores;
//    bool sc_block = false; //
//    bool sc_allow = false; //
    // end of specific score tag stuff

    /* CheckRule */
//    bool block = false;
//    bool allow = false;
//    bool drop = false;
//    bool log = false;

    basic_rule_t br; // specific rule stuff
} http_rule_t;

class NxParser {
private:
    apr_pool_t *p;
    vector<http_rule_t> mainRules;
    vector<http_rule_t> whitelistRules; // raw array of whitelist rules

public:
    unordered_map<string, check_rule_t> checkRules;
    vector<http_rule_t> getRules;
    vector<http_rule_t> bodyRules;
    vector<http_rule_t> headerRules;
    vector<http_rule_t> genericRules; // URL

    vector<whitelist_rule_t> tmp_wlr; // raw array of transformed whitelists
    vector<http_rule_t> rxmz_wlr; // raw array of regex-mz whitelists

    unordered_map<string, whitelist_rule_t> wlUrlHash; // hash table of whitelisted URL rules
    unordered_map<string, whitelist_rule_t> wlArgsHash; // hash table of whitelisted ARGS rules
    unordered_map<string, whitelist_rule_t> wlBodyHash; // hash table of whitelisted BODY rules
    unordered_map<string, whitelist_rule_t> wlHeadersHash; // hash table of whitelisted HEADERS rules
    vector<http_rule_t> disabled_rules; // rules that are globally disabled in one location

    NxParser(apr_pool_t *p);

    void parseMainRules(apr_array_header_t *rulesArray);

    void parseCheckRules(apr_array_header_t *rulesArray);

    void parseBasicRules(apr_array_header_t *rulesArray);

    void parseMatchZone(http_rule_t &rule, string &rawMatchZone);

    void createHashTables();

    void wlrIdentify(const http_rule_t &curr, enum DUMMY_MATCH_ZONE &zone, int &uri_idx, int &name_idx);

    void wlrFind(const http_rule_t &curr, whitelist_rule_t &father_wlr, DUMMY_MATCH_ZONE &zone, int &uri_idx, int &name_idx);
};


#endif //MOD_DEFENDER_NXPARSER_H
