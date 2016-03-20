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
#include "RuleParser.h"
#include "mod_defender.hpp"

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

class RuntimeScanner {
private:
    request_rec* r;
    server_config_t* scfg;
    RuleParser& parser;
    apr_pool_t* pool;
    stringstream matchVars;
    unsigned int rulesMatchedCount = 0;
    vector<pair<const string, const string>> headers;
    vector<pair<const string, const string>> args;
    vector<pair<const string, const string>> body;
    string uri;
    unordered_map<string, int> matchScores;

    bool block = false;
    bool drop = false;
    bool allow = false;
    bool log = false;

public:
    RuntimeScanner(request_rec* rec, server_config_t* scfg, RuleParser& parser);
    static int storeTable(void*, const char*, const char*);
    void readPost();
    int runHandler();
    void applyCheckRuleAction(const rule_action_t &action);
    void checkLibInjection(MATCH_ZONE zone, const string &name, const string &value);
    void basestrRuleset(MATCH_ZONE zone, const string &name, const string &value,
                        const vector<http_rule_t*> &rules);
    bool processRuleBuffer(const string &str, const http_rule_t &rl, int &nbMatch);
    void applyCheckRule(const http_rule_t &rule, int nbMatch, const string &name, const string &value,
                        MATCH_ZONE zone, bool targetName);
    string formatMatch(const http_rule_t &rule, int nbMatch, MATCH_ZONE zone, const string &name, const string &value,
                       bool targetName);
};

#endif /* RUNTIMESCANNER_HPP */

