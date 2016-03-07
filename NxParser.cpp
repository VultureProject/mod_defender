#include <apr_strings.h>
#include "NxParser.h"

vector<main_rule_t> NxParser::parseMainRules(apr_pool_t *pool, apr_array_header_t *mainRules) {
    vector<main_rule_t> rules;
    for (int i = 0; i < mainRules->nelts; i+=5) {
        main_rule_t rule;
        pair<string, string> matchpatern = Util::splitAtFirst(((const char **) mainRules->elts)[i], ":");
        rule.IsMatchPaternRx = (matchpatern.first == "rx");
        DEBUG_CONF(rule.IsMatchPaternRx << " ");
        if (matchpatern.first == "rx") {
            rule.matchPaternRx = regex(matchpatern.second);
            DEBUG_CONF(matchpatern.second << " ");
        }
        if (matchpatern.first == "str") {
            rule.matchPaternStr = apr_pstrdup(pool, matchpatern.second.c_str());
            DEBUG_CONF(rule.matchPaternStr << " ");
        }

        rule.msg = apr_pstrdup(pool, Util::stringAfter(((const char **) mainRules->elts)[i+1], ':').c_str());
        DEBUG_CONF(rule.msg << " ");

        string rawMatchZone = Util::stringAfter(((const char **) mainRules->elts)[i+2], ':');
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

        string score = Util::stringAfter(((const char **) mainRules->elts)[i+3], ':');
        vector<string> scores = Util::split(score, ',');
        for (const string &sc : scores) {
            pair<string, string> scorepair = Util::splitAtFirst(sc, ":");
            rule.scores.emplace_back(apr_pstrdup(pool, scorepair.first.c_str()), std::stoi(scorepair.second));
            DEBUG_CONF(scorepair.first << " " << scorepair.second << " ");
        }

        rule.id = Util::intAfter(((const char **) mainRules->elts)[i+4], ':');
        DEBUG_CONF(rule.id << " ");

        rules.push_back(rule);
        DEBUG_CONF(endl);
    }
    return rules;
}

unordered_map<string, check_rule_t> NxParser::parseCheckRules(apr_array_header_t *checkRules) {
    unordered_map<string, check_rule_t> rules;
    for (int i = 0; i < checkRules->nelts; i+=2) {
        check_rule_t chkrule;
        string equation = string(((const char **) checkRules->elts)[i]);
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

        string action = string(((const char **) checkRules->elts)[i+1]);
        action.pop_back(); // remove the trailing semicolon

        if (action == "BLOCK") {
            chkrule.action = BLOCK;
            DEBUG_CONF("BLOCK ");
        }
        else if (action == "DROP") {
            chkrule.action = DROP;
            cerr << "DROP ";
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
