#include <apr_strings.h>
#include "NxParser.h"

vector<main_rule_t> NxParser::parseMainRules(apr_pool_t *pool, apr_array_header_t *rulesArray) {
    vector<main_rule_t> rules;
    for (int i = 0; i < rulesArray->nelts; i+=5) {
        main_rule_t rule;
        if (strcmp(((const char **) rulesArray->elts)[i], "negative") == 0) {
            rule.negative = true;
            DEBUG_CONF("negative ");
            i++;
        }
        pair<string, string> matchPatern = Util::splitAtFirst(((const char **) rulesArray->elts)[i], ":");
        rule.IsMatchPaternRx = (matchPatern.first == "rx");
        DEBUG_CONF(rule.IsMatchPaternRx << " ");
        if (matchPatern.first == "rx") {
            rule.matchPaternRx = regex(matchPatern.second);
            DEBUG_CONF(matchPatern.second << " ");
        }
        if (matchPatern.first == "str") {
            rule.matchPaternStr = apr_pstrdup(pool, matchPatern.second.c_str());
            DEBUG_CONF(rule.matchPaternStr << " ");
        }

        rule.msg = apr_pstrdup(pool, ((const char **) rulesArray->elts)[i+1] + 4);
        DEBUG_CONF(rule.msg << " ");

        string rawMatchZone = ((const char **) rulesArray->elts)[i+2] + 3;
        vector<string> matchZones = Util::split(rawMatchZone, '|');
        for (const string &mz : matchZones) {
            if (mz == "ARGS") {
                rule.argsMz = true;
                DEBUG_CONF("ARGS ");
            }
            else if (mz == "URL") {
                rule.urlMz = true;
                DEBUG_CONF("URL ");
            }
            else if (mz == "BODY") {
                rule.bodyMz = true;
                DEBUG_CONF("BODY ");
            }
            else if (mz.compare(0, strlen("HEADERS"), "HEADERS") == 0) {
                rule.headersMz = true;
                DEBUG_CONF("HEADERS ");
            }
        }

        string score = ((const char **) rulesArray->elts)[i+3] + 2;
        vector<string> scores = Util::split(score, ',');
        for (const string &sc : scores) {
            pair<string, string> scorepair = Util::splitAtFirst(sc, ":");
            rule.scores.emplace_back(apr_pstrdup(pool, scorepair.first.c_str()), std::stoi(scorepair.second));
            DEBUG_CONF(scorepair.first << " " << scorepair.second << " ");
        }

        rule.id = std::stoi(((const char **) rulesArray->elts)[i+4] + 3);
        DEBUG_CONF(rule.id << " ");

        rules.push_back(rule);
        DEBUG_CONF(endl);
    }
    return rules;
}

unordered_map<string, check_rule_t> NxParser::parseCheckRules(apr_array_header_t *rulesArray) {
    unordered_map<string, check_rule_t> rules;
    for (int i = 0; i < rulesArray->nelts; i+=2) {
        check_rule_t chkrule;
        string equation = string(((const char **) rulesArray->elts)[i]);
        vector<string> eqParts = Util::split(equation, ' ');

        string tag = Util::rtrim(eqParts[0]);
        DEBUG_CONF(tag << " ");

        if (eqParts[1] == ">=") {
            chkrule.comparator = SUP_OR_EQUAL;
            DEBUG_CONF(">= ");
        }
        else if (eqParts[1] == ">") {
            chkrule.comparator = SUP;
            DEBUG_CONF("> ");
        }
        else if (eqParts[1] == "<=") {
            chkrule.comparator = INF_OR_EQUAL;
            DEBUG_CONF("<= ");
        }
        else if (eqParts[1] == "<") {
            chkrule.comparator = INF;
            DEBUG_CONF("< ");
        }

        chkrule.limit = std::stoi(eqParts[2]);
        DEBUG_CONF(chkrule.limit << " ");

        string action = string(((const char **) rulesArray->elts)[i+1]);
        action.pop_back(); // remove the trailing semicolon

        if (action == "BLOCK") {
            chkrule.action = BLOCK;
            DEBUG_CONF("BLOCK ");
        }
        else if (action == "DROP") {
            chkrule.action = DROP;
            DEBUG_CONF("DROP ");
        }
        else if (action == "ALLOW") {
            chkrule.action = ALLOW;
            DEBUG_CONF("ALLOW ");
        }
        else if (action == "LOG") {
            chkrule.action = LOG;
            DEBUG_CONF("LOG ");
        }

        rules[tag] = chkrule;
        DEBUG_CONF(endl);
    }
    return rules;
}

vector<basic_rule_t> NxParser::parseBasicRules(apr_pool_t *pool, apr_array_header_t *rulesArray) {
    basic_rule_t rule;
    for (int i = 0; i < rulesArray->nelts; i+=3) {
        string rawWhitelist = ((const char **) rulesArray->elts)[i] + 3;
        rule.wlIds = Util::splitToInt(rawWhitelist, ',');
        for (const int &id : rule.wlIds) {
            cerr << id << " ";
        }

        string rawMatchZone = ((const char **) rulesArray->elts)[i+1] + 3;
        vector<string> matchZones = Util::split(rawMatchZone, '|');
        for (const string &mz : matchZones) {
            cerr << mz << " ";
        }

        cerr << endl;
    }
}