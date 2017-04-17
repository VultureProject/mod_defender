/*                       _        _       __                _
 *   _ __ ___   ___   __| |    __| | ___ / _| ___ _ __   __| | ___ _ __
 *  | '_ ` _ \ / _ \ / _` |   / _` |/ _ \ |_ / _ \ '_ \ / _` |/ _ \ '__|
 *  | | | | | | (_) | (_| |  | (_| |  __/  _|  __/ | | | (_| |  __/ |
 *  |_| |_| |_|\___/ \__,_|___\__,_|\___|_|  \___|_| |_|\__,_|\___|_|
 *                       |_____|
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#ifndef RUNTIMESCANNER_HPP
#define RUNTIMESCANNER_HPP

#include <map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <chrono>
#include <httpd.h>
#include <unordered_map>
#include <fstream>
#include "RuleParser.h"
#include "mod_defender.hpp"
#include "JsonValidator.hpp"

//#define DEBUG_RUNTIME_PROCESSRULE
#ifdef DEBUG_RUNTIME_PROCESSRULE
#define DEBUG_RUNTIME_PR(x) do { std::cerr << x; } while (0)
#else
#define DEBUG_RUNTIME_PR(x)
#endif

//#define DEBUG_RUNTIME_BASESTR_RULE_SET
#ifdef DEBUG_RUNTIME_BASESTR_RULE_SET
#define DEBUG_RUNTIME_BRS(x) do { std::cerr << x; } while (0)
#else
#define DEBUG_RUNTIME_BRS(x)
#endif

using namespace Util;
using std::chrono::system_clock;
using std::pair;
using std::vector;
using std::string;
using std::cerr;
using std::stringstream;
using std::endl;
using std::regex;
using std::sregex_iterator;
using std::regex_match;
using std::distance;
using std::unordered_map;
using std::transform;

const std::string empty = string();

enum CONTENT_TYPE {
    URL_ENC = 0, // application/x-www-form-urlencoded
    MULTIPART, // multipart/form-data
    APP_JSON, // application/json
    UNSUPPORTED
};

class RuntimeScanner {
    friend class JsonValidator;
private:
    request_rec* r;
    dir_config_t* dcfg;
    RuleParser& parser;
    stringstream matchVars;
    stringstream jsonMatchVars;
    unsigned int rulesMatchedCount = 0;
    string uri;
    unordered_map<string, int> matchScores;
    string rawContentType;
    bool contentTypeFound = false;

    bool block = false;
    bool drop = false;
    bool allow = false;
    bool log = false;

public:
    CONTENT_TYPE contentType = UNSUPPORTED;
    unsigned long contentLength = 0;
    string rawBody;

    RuntimeScanner(dir_config_t *dcfg, RuleParser &parser) : dcfg(dcfg), parser(parser) {}
    void streamToFile(const stringstream &ss, apr_file_t* fd);
    int processHeaders(request_rec *rec);
    void applyRuleAction(const rule_action_t &rule_action);
    void checkLibInjection(MATCH_ZONE zone, const string &name, const string &value);
    void basestrRuleset(MATCH_ZONE zone, const string &name, const string &value,
                        const vector<http_rule_t> &rules);
    bool processRuleBuffer(const string &str, const http_rule_t &rl, unsigned long &nbMatch);
    void applyCheckRule(const http_rule_t &rule, unsigned long nbMatch, const string &name, const string &value,
                        MATCH_ZONE zone, bool targetName);
    void applyRuleMatch(const http_rule_t &rule, unsigned long nbMatch, MATCH_ZONE zone, const string &name,
                        const string &value, bool targetName);
    int processBody();
    void writeLearningLog();
    void writeExtensiveLog(const http_rule_t &rule, MATCH_ZONE zone, const string &name,
                           const string &value, bool targetName);
    void writeJSONLearningLog();
    bool parseFormDataBoundary(unsigned char **boundary, unsigned long *boundary_len);
    void multipartParse(u_char *src, unsigned long len);
    bool contentDispositionParser(unsigned char *str, unsigned char *line_end,
                                  unsigned char **fvarn_start, unsigned char **fvarn_end,
                                  unsigned char **ffilen_start, unsigned char **ffilen_end);
    int processAction();
    bool splitUrlEncodedRuleset(char *str, const vector<http_rule_t> &rules, MATCH_ZONE zone);
};

#endif /* RUNTIMESCANNER_HPP */

