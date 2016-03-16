#ifndef CAPPLICATION_HPP
#define CAPPLICATION_HPP

#include <map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <chrono>
#include <httpd.h>
#include <unordered_map>
#include "NxParser.h"
#include "mod_defender.hpp"

using std::chrono::system_clock;
using std::pair;
using std::vector;
using std::string;
using std::cerr;
using std::stringstream;
using std::endl;
using std::flush;
using std::regex;
using std::sregex_iterator;
using std::regex_match;
using std::distance;
using std::unordered_map;

class CApplication {
private:
    request_rec* r;
    server_config_t* scfg;
    NxParser& parser;
    apr_pool_t* pool;
    stringstream matchVars;
    unsigned int rulesMatchedCount = 0;
    vector<pair<const string, const string>> headers;
    vector<pair<const string, const string>> args;
    vector<pair<const string, const string>> body;
    string uri;
    unordered_map<string, check_rule_t> checkRules;
    unordered_map<string, int> matchScores;

    bool block = false;
    bool drop = false;
    bool allow = false;
    bool log = false;

public:
    CApplication(request_rec* rec, server_config_t* scfg);
    static int storeTable(void*, const char*, const char*);
    void readPost();
    int runHandler();
    string formatMatch(const http_rule_t &rule, enum DUMMY_MATCH_ZONE zone, const string& varName);
    void applyCheckRule(const http_rule_t &rule, int matchCount);
    void checkRulesOnVars(enum DUMMY_MATCH_ZONE zone, vector<pair<const string, const string>> &v,
                          const http_rule_t &rule);
    void checkVar(enum DUMMY_MATCH_ZONE zone, const string& varName, const string& value, const http_rule_t &rule);
    void applyCheckRuleAction(const rule_action_t &action);
    bool isRuleEligible(DUMMY_MATCH_ZONE zone, const http_rule_t &rule, const string &varName);
    void checkLibInjection(DUMMY_MATCH_ZONE zone, const string &varName, const string &value);
    void checkLibInjectionOnVar(DUMMY_MATCH_ZONE zone, vector<pair<const string, const string>> &v);
};

#endif /* CAPPLICATION_HPP */

