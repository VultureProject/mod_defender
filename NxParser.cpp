#include <apr_strings.h>
#include "NxParser.h"

vector <main_rule_t> NxParser::parseMainRules(apr_pool_t *pool, apr_array_header_t *rulesArray) {
    vector <main_rule_t> rules;
    for (int i = 0; i < rulesArray->nelts; i += 5) {
        main_rule_t rule;
        if (strcmp(((const char **) rulesArray->elts)[i], "negative") == 0) {
            rule.negative = true;
            DEBUG_CONF_MR("negative ");
            i++;
        }
        pair <string, string> matchPatern = Util::splitAtFirst(((const char **) rulesArray->elts)[i], ":");
        rule.rxMz = (matchPatern.first == "rx");
        DEBUG_CONF_MR(rule.rxMz << " ");
        if (matchPatern.first == "rx") {
            rule.matchPaternRx = regex(matchPatern.second);
            DEBUG_CONF_MR(matchPatern.second << " ");
        }
        if (matchPatern.first == "str") {
            rule.matchPaternStr = apr_pstrdup(pool, matchPatern.second.c_str());
            DEBUG_CONF_MR(rule.matchPaternStr << " ");
        }

        rule.msg = apr_pstrdup(pool, ((const char **) rulesArray->elts)[i + 1] + 4);
        DEBUG_CONF_MR(rule.msg << " ");

        string rawMatchZone = ((const char **) rulesArray->elts)[i + 2] + 3;
        vector <string> matchZones = Util::split(rawMatchZone, '|');
        for (const string &mz : matchZones) {
            if (mz == "ARGS") {
                rule.argsMz = true;
                DEBUG_CONF_MR("ARGS ");
            }
            else if (mz == "URL") {
                rule.urlMz = true;
                DEBUG_CONF_MR("URL ");
            }
            else if (mz == "BODY") {
                rule.bodyMz = true;
                DEBUG_CONF_MR("BODY ");
            }
            else if (mz.compare(0, strlen("HEADERS"), "HEADERS") == 0) {
                rule.headersMz = true;
                DEBUG_CONF_MR("HEADERS ");
            }
        }

        string score = ((const char **) rulesArray->elts)[i + 3] + 2;
        vector <string> scores = Util::split(score, ',');
        for (const string &sc : scores) {
            pair<string, string> scorepair = Util::splitAtFirst(sc, ":");
            rule.scores.emplace_back(apr_pstrdup(pool, scorepair.first.c_str()), std::stoi(scorepair.second));
            DEBUG_CONF_MR(scorepair.first << " " << scorepair.second << " ");
        }

        rule.id = std::stoi(((const char **) rulesArray->elts)[i + 4] + 3);
        DEBUG_CONF_MR(rule.id << " ");

        rules.push_back(rule);
        DEBUG_CONF_MR(endl);
    }
    return rules;
}

unordered_map <string, check_rule_t> NxParser::parseCheckRules(apr_array_header_t *rulesArray) {
    unordered_map <string, check_rule_t> rules;
    for (int i = 0; i < rulesArray->nelts; i += 2) {
        check_rule_t chkrule;
        string equation = string(((const char **) rulesArray->elts)[i]);
        vector <string> eqParts = Util::split(equation, ' ');

        string tag = Util::rtrim(eqParts[0]);
        DEBUG_CONF_CR(tag << " ");

        if (eqParts[1] == ">=") {
            chkrule.comparator = SUP_OR_EQUAL;
            DEBUG_CONF_CR(">= ");
        }
        else if (eqParts[1] == ">") {
            chkrule.comparator = SUP;
            DEBUG_CONF_CR("> ");
        }
        else if (eqParts[1] == "<=") {
            chkrule.comparator = INF_OR_EQUAL;
            DEBUG_CONF_CR("<= ");
        }
        else if (eqParts[1] == "<") {
            chkrule.comparator = INF;
            DEBUG_CONF_CR("< ");
        }

        chkrule.limit = std::stoi(eqParts[2]);
        DEBUG_CONF_CR(chkrule.limit << " ");

        string action = string(((const char **) rulesArray->elts)[i + 1]);
        action.pop_back(); // remove the trailing semicolon

        if (action == "BLOCK") {
            chkrule.action = BLOCK;
            DEBUG_CONF_CR("BLOCK ");
        }
        else if (action == "DROP") {
            chkrule.action = DROP;
            DEBUG_CONF_CR("DROP ");
        }
        else if (action == "ALLOW") {
            chkrule.action = ALLOW;
            DEBUG_CONF_CR("ALLOW ");
        }
        else if (action == "LOG") {
            chkrule.action = LOG;
            DEBUG_CONF_CR("LOG ");
        }

        rules[tag] = chkrule;
        DEBUG_CONF_CR(endl);
    }
    return rules;
}

vector <basic_rule_t> NxParser::parseBasicRules(apr_pool_t *pool, apr_array_header_t *rulesArray) {
    vector<basic_rule_t> rules;

    for (int i = 0; i < rulesArray->nelts; i += 3) {
        basic_rule_t rule;
        string rawWhitelist = ((const char **) rulesArray->elts)[i] + 3;

         // TODO Check if id negative (Whitelist all user rules (>= 1000), excepting rule -id
        vector<int> wlIds = Util::splitToInt(rawWhitelist, ',');
        for (const int &id : wlIds) {
            DEBUG_CONF_BR(id << " ");
        }

        // If not matchzone specified
        if (rawWhitelist.back() == ';') {
            i -= 2;
            DEBUG_CONF_BR(endl);
            continue;
        }

        string rawMatchZone = ((const char **) rulesArray->elts)[i + 1] + 3;
        vector<string> matchZones = Util::split(rawMatchZone, '|');
        for (const string &mz : matchZones) {
            if (mz[0] != '$') {
                if (mz == "ARGS") {
                    rule.argsMz = true;
                    DEBUG_CONF_BR("ARGS ");
                }
                else if (mz == "HEADERS") {
                    rule.headersMz = true;
                    DEBUG_CONF_BR("HEADERS ");
                }
                else if (mz == "URL") {
                    rule.urlMz = true;
                    DEBUG_CONF_BR("URL ");
                }
                else if (mz == "BODY") {
                    rule.bodyMz = true;
                    DEBUG_CONF_BR("BODY ");
                }
                else if (mz == "FILE_EXT") {
                    rule.fileExtMz = true;
                    DEBUG_CONF_BR("FILE_EXT ");
                }
                else if (mz == "NAME") {
                    rule.targetName = true;
                    DEBUG_CONF_BR("NAME ");
                }
            }
            else {
                custom_rule_location_t customRule;
                rule.customZone = true;
                pair<string, string> cmz = Util::splitAtFirst(mz, ":");

                if (cmz.first == "$ARGS_VAR") {
                    customRule.argsVar = true;
                    rule.argsVarMz = true;
                    DEBUG_CONF_BR("$ARGS_VAR ");
                }
                else if (cmz.first == "$HEADERS_VAR") {
                    customRule.headersVar = true;
                    rule.headersVarMz = true;
                    DEBUG_CONF_BR("$HEADERS_VAR ");
                }
                else if (cmz.first == "$URL") {
                    customRule.specificUrl = true;
                    rule.urlSpecifiedMz = true;
                    DEBUG_CONF_BR("$URL ");
                }
                else if (cmz.first == "$BODY_VAR") {
                    customRule.bodyVar = true;
                    rule.bodyVarMz = true;
                    DEBUG_CONF_BR("$BODY_VAR ");
                }

                else if (cmz.first == "$ARGS_VAR_X") {
                    customRule.argsVar = true;
                    rule.argsVarMz = true;
                    rule.rxMz = true;
                    DEBUG_CONF_BR("$ARGS_VAR_X ");
                }
                else if (cmz.first == "$HEADERS_VAR_X") {
                    customRule.headersVar = true;
                    rule.headersVarMz = true;
                    rule.rxMz = true;
                    DEBUG_CONF_BR("$HEADERS_VAR_X ");
                }
                else if (cmz.first == "$URL_X") {
                    customRule.specificUrl = true;
                    rule.urlSpecifiedMz = true;
                    rule.rxMz = true;
                    DEBUG_CONF_BR("$URL_X ");
                }
                else if (cmz.first == "$BODY_VAR_X") {
                    customRule.bodyVar = true;
                    rule.bodyVarMz = true;
                    rule.rxMz = true;
                    DEBUG_CONF_BR("$BODY_VAR_X ");
                }

                if (!rule.rxMz) {
                    customRule.target = apr_pstrdup(pool, cmz.second.c_str());
                    rule.matchPaternStr = apr_pstrdup(pool, cmz.second.c_str());
                    DEBUG_CONF_BR("(rx)" << cmz.second << " ");
                }
                else {
                    rule.matchPaternRx = regex(cmz.second);
                    DEBUG_CONF_BR("(str)" << cmz.second << " ");
                }
                rule.customLocations.push_back(customRule);
            }
        }

        rules.push_back(rule);
        DEBUG_CONF_BR(endl);
    }
    return rules;
}