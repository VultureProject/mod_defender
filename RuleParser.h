#ifndef MOD_DEFENDER_RULEPARSER_H
#define MOD_DEFENDER_RULEPARSER_H

#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include "Util.h"
#include "mod_defender.hpp"
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

//#define DEBUG_CONFIG_HASHTABLES
#ifdef DEBUG_CONFIG_HASHTABLES
#define DEBUG_CONF_HT(x) do { std::cerr << x; } while (0)
#else
#define DEBUG_CONF_HT(x)
#endif

//#define DEBUG_CONFIG_WLRFIND
#ifdef DEBUG_CONFIG_WLRFIND
#define DEBUG_CONF_WLRF(x) do { std::cerr << x << endl; } while (0)
#else
#define DEBUG_CONF_WLRF(x)
#endif

//#define DEBUG_CONFIG_WL
#ifdef DEBUG_CONFIG_WL
#define DEBUG_CONF_WL(x) do { std::cerr << x << endl; } while (0)
#else
#define DEBUG_CONF_WL(x)
#endif

using namespace Util;
using std::pair;
using std::vector;
using std::string;
using std::cerr;
using std::stringstream;
using std::endl;
using std::istream_iterator;
using std::istringstream;
using std::regex;
using std::sregex_iterator;
using std::regex_match;
using std::distance;
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
    string target; // to be used for string match zones
    regex *targetRx = nullptr; // to be used for regexed match zones
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
    string target;
} whitelist_location_t;

enum MATCH_TYPE {
    URI_ONLY = 0,
    NAME_ONLY,
    MIXED
};

enum MATCH_ZONE {
    HEADERS = 0,
    URL,
    ARGS,
    BODY,
    FILE_EXT,
    UNKNOWN
};

static const char *match_zones[] = {
        "HEADERS",
        "URL",
        "ARGS",
        "BODY",
        "FILE_EXT",
        "UNKNOWN",
        NULL
};

/*
** this struct is used to aggregate all whitelist
** that point to the same URI or the same VARNAME
** all the "subrules" will then be stored in the "whitelist_locations"
*/
typedef struct {
    vector<whitelist_location_t> whitelistLocations;
    enum MATCH_ZONE zone; // zone to wich the WL applies
    bool uriOnly = false; // if the "name" is only an url, specify it
    bool targetName = false; // does the rule targets the name instead of the content
    string name; // hash key [#]URI#VARNAME
    vector<int> ids;
} whitelist_rule_t;

typedef struct {
    regex *rx = nullptr;
    string str;
    bool rxMz = false;
    enum MATCH_ZONE zone;
    bool bodyMz = false;
    bool bodyVarMz = false;
    bool headersMz = false;
    bool headersVarMz = false;
    bool urlMz = false;
    bool specificUrlMz = false;
    bool argsMz = false;
    bool argsVarMz = false;
    bool fileExtMz = false;
    bool customLocation = false; // set if defined "custom" match zone (GET_VAR/POST_VAR/...)
    bool targetName = false; // does the rule targets variable name instead ?
    bool negative = false;
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
    string logMsg; // a specific log message
    /* List of scores increased on rule match. */
    vector<pair<string, int>> scores;
    basic_rule_t *br; // specific rule stuff
} http_rule_t;

class RuleParser {
private:
    vector<http_rule_t> whitelistRules; // raw array of whitelist rules
    bool isRuleWhitelistedRx(const http_rule_t &rule, const string uri, const string &name, enum MATCH_ZONE zone, bool targetName);
    bool isWhitelistAdapted(whitelist_rule_t &wlrule, const string &name, MATCH_ZONE zone, const http_rule_t &rule,
                            MATCH_TYPE type, bool targetName);
    string parseCode(std::regex_constants::error_type etype);

public:
    unordered_map<string, check_rule_t> checkRules;
    vector<http_rule_t*> getRules;
    vector<http_rule_t*> bodyRules;
    vector<http_rule_t*> headerRules;
    vector<http_rule_t*> genericRules; // URL

    vector<whitelist_rule_t> tmpWlr; // raw array of transformed whitelists
    vector<http_rule_t> rxMzWlr; // raw array of regex-mz whitelists

    unordered_map<string, whitelist_rule_t> wlUrlHash; // hash table of whitelisted URL rules
    unordered_map<string, whitelist_rule_t> wlArgsHash; // hash table of whitelisted ARGS rules
    unordered_map<string, whitelist_rule_t> wlBodyHash; // hash table of whitelisted BODY rules
    unordered_map<string, whitelist_rule_t> wlHeadersHash; // hash table of whitelisted HEADERS rules
    vector<http_rule_t> disabled_rules; // rules that are globally disabled in one location
    http_rule_t uncommonHexEncoding;
    http_rule_t uncommonContentType;
    http_rule_t uncommonUrl;
    http_rule_t uncommonPostFormat;
    http_rule_t uncommonPostBoundary;
    http_rule_t libsqliRule;
    http_rule_t libxssRule;

    RuleParser();
    void parseMainRules(vector<string> rulesArray);
    const char* parseCheckRule(apr_pool_t* pool, string equation, string actionArg);
    void parseBasicRules(vector<string> rulesArray);
    void parseMatchZone(http_rule_t &rule, string &rawMatchZone);
    void generateHashTables();
    void wlrIdentify(const http_rule_t &curr, enum MATCH_ZONE &zone, int &uri_idx, int &name_idx);
    void wlrFind(const http_rule_t &curr, whitelist_rule_t &father_wlr, MATCH_ZONE &zone, int &uriIndex, int &name_idx);
    bool checkIds(int matchId, const vector<int> &wlIds);
    bool findWlInHash(whitelist_rule_t &wlRule, const string &key, MATCH_ZONE zone);
    bool isRuleWhitelisted(const http_rule_t &rule, const string& uri, const string &name, MATCH_ZONE zone, bool targetName);
};


#endif //MOD_DEFENDER_RULEPARSER_H
