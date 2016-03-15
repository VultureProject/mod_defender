#include <apr_strings.h>
#include "NxParser.h"

NxParser::NxParser(apr_pool_t *pool) {
    p = pool;
}

void NxParser::parseMainRules(apr_array_header_t *rulesArray) {
    for (int i = 0; i < rulesArray->nelts; i += 5) {
        DEBUG_CONF_MR("MainRule ");
        http_rule_t rule;
        rule.type = MAIN_RULE;
        if (strcmp(((const char **) rulesArray->elts)[i], "negative") == 0) {
            rule.br.negative = true;
            DEBUG_CONF_MR("negative ");
            i++;
        }
        pair <string, string> matchPatern = Util::splitAtFirst(((const char **) rulesArray->elts)[i], ":");
        rule.br.rxMz = (matchPatern.first == "rx");
        DEBUG_CONF_MR(rule.br.rxMz << " ");
        if (matchPatern.first == "rx") {
            rule.br.matchPaternRx = regex(matchPatern.second);
            DEBUG_CONF_MR(matchPatern.second << " ");
        }
        if (matchPatern.first == "str") {
            rule.br.matchPaternStr = apr_pstrdup(p, matchPatern.second.c_str());
            DEBUG_CONF_MR(rule.br.matchPaternStr << " ");
        }

        rule.logMsg = apr_pstrdup(p, ((const char **) rulesArray->elts)[i + 1] + 4);
        DEBUG_CONF_MR(rule.logMsg << " ");

        string rawMatchZone = ((const char **) rulesArray->elts)[i + 2] + 3;
        parseMatchZone(rule, rawMatchZone);

        string score = ((const char **) rulesArray->elts)[i + 3] + 2;
        vector <string> scores = Util::split(score, ',');
        for (const string &sc : scores) {
            pair<string, string> scorepair = Util::splitAtFirst(sc, ":");
            rule.scores.emplace_back(apr_pstrdup(p, scorepair.first.c_str()), std::stoi(scorepair.second));
            DEBUG_CONF_MR(scorepair.first << " " << scorepair.second << " ");
        }

        rule.id = std::stoi(((const char **) rulesArray->elts)[i + 4] + 3);
        DEBUG_CONF_MR(rule.id << " ");

        mainRules.push_back(rule);
        DEBUG_CONF_MR(endl);
    }
}

void NxParser::parseCheckRules(apr_array_header_t *rulesArray) {
    for (int i = 0; i < rulesArray->nelts; i += 2) {
        DEBUG_CONF_CR("CheckRule ");
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

        checkRules[tag] = chkrule;
        DEBUG_CONF_CR(endl);
    }
}

void NxParser::parseBasicRules(apr_array_header_t *rulesArray) {
    for (int i = 0; i < rulesArray->nelts; i += 3) {
        DEBUG_CONF_BR("BasicRule ");
        http_rule_t rule;
        rule.type = BASIC_RULE;
        string rawWhitelist = ((const char **) rulesArray->elts)[i] + 3;

        // TODO Check if id negative (Whitelist all user rules (>= 1000), except rule -id
        rule.whitelist = true;
        rule.wlIds = Util::splitToInt(rawWhitelist, ',');
        for (const int &id : rule.wlIds) {
            DEBUG_CONF_BR(id << " ");
        }

        // If not matchzone specified
        if (rawWhitelist.back() == ';') {
            i -= 2;
            whitelistRules.push_back(rule);
            DEBUG_CONF_BR(endl);
            continue;
        }

        string rawMatchZone = ((const char **) rulesArray->elts)[i + 1] + 3;
        parseMatchZone(rule, rawMatchZone);

        whitelistRules.push_back(rule);
        DEBUG_CONF_BR(endl);
    }
}

void NxParser::parseMatchZone(http_rule_t& rule, string& rawMatchZone) {
    vector<string> matchZones = Util::split(rawMatchZone, '|');
    for (const string &mz : matchZones) {
        if (mz[0] != '$') {
            if (mz == "ARGS") {
                rule.br.argsMz = true;
                DEBUG_CONF_MZ("ARGS ");
            }
            else if (mz == "HEADERS") {
                rule.br.headersMz = true;
                DEBUG_CONF_MZ("HEADERS ");
            }
            else if (mz == "URL") {
                rule.br.urlMz = true;
                DEBUG_CONF_MZ("URL ");
            }
            else if (mz == "BODY") {
                rule.br.bodyMz = true;
                DEBUG_CONF_MZ("BODY ");
            }
            else if (mz == "FILE_EXT") {
                rule.br.fileExtMz = true;
                rule.br.bodyMz = true;
                DEBUG_CONF_MZ("FILE_EXT ");
            }
            else if (mz == "NAME") {
                rule.br.targetName = true;
                DEBUG_CONF_MZ("NAME ");
            }
        }
        else {
            custom_rule_location_t customRule;
            rule.br.customLocation = true;
            pair<string, string> cmz = Util::splitAtFirst(mz, ":");

            if (cmz.first == "$ARGS_VAR") {
                customRule.argsVar = true;
                rule.br.argsVarMz = true;
                DEBUG_CONF_MZ("$ARGS_VAR ");
            }
            else if (cmz.first == "$HEADERS_VAR") {
                customRule.headersVar = true;
                rule.br.headersVarMz = true;
                DEBUG_CONF_MZ("$HEADERS_VAR ");
            }
            else if (cmz.first == "$URL") {
                customRule.specificUrl = true;
                rule.br.urlSpecifiedMz = true;
                DEBUG_CONF_MZ("$URL ");
            }
            else if (cmz.first == "$BODY_VAR") {
                customRule.bodyVar = true;
                rule.br.bodyVarMz = true;
                DEBUG_CONF_MZ("$BODY_VAR ");
            }

            else if (cmz.first == "$ARGS_VAR_X") {
                customRule.argsVar = true;
                rule.br.argsVarMz = true;
                rule.br.rxMz = true;
                DEBUG_CONF_MZ("$ARGS_VAR_X ");
            }
            else if (cmz.first == "$HEADERS_VAR_X") {
                customRule.headersVar = true;
                rule.br.headersVarMz = true;
                rule.br.rxMz = true;
                DEBUG_CONF_MZ("$HEADERS_VAR_X ");
            }
            else if (cmz.first == "$URL_X") {
                customRule.specificUrl = true;
                rule.br.urlSpecifiedMz = true;
                rule.br.rxMz = true;
                DEBUG_CONF_MZ("$URL_X ");
            }
            else if (cmz.first == "$BODY_VAR_X") {
                customRule.bodyVar = true;
                rule.br.bodyVarMz = true;
                rule.br.rxMz = true;
                DEBUG_CONF_MZ("$BODY_VAR_X ");
            }

            if (!rule.br.rxMz) {
                customRule.target = apr_pstrdup(p, cmz.second.c_str());
                rule.br.matchPaternStr = apr_pstrdup(p, cmz.second.c_str());
                DEBUG_CONF_MZ("(rx)" << cmz.second << " ");
            }
            else {
                rule.br.matchPaternRx = regex(cmz.second);
                DEBUG_CONF_MZ("(str)" << cmz.second << " ");
            }
            rule.br.customLocations.push_back(customRule);
        }
    }
}

/* check rule, returns associed zone, as well as location index.
  location index refers to $URL:bla or $ARGS_VAR:bla */
void NxParser::wlrIdentify(const http_rule_t& curr, enum DUMMY_MATCH_ZONE &zone, int &uri_idx, int &name_idx) {
    if (curr.br.bodyMz || curr.br.bodyVarMz)
        zone = BODY;
    else if (curr.br.headersMz || curr.br.bodyVarMz)
        zone = HEADERS;
    else if (curr.br.argsMz || curr.br.argsVarMz)
        zone = ARGS;
    else if (curr.br.urlMz) /*don't assume that named $URL means zone is URL.*/
        zone = URL;
    else if (curr.br.fileExtMz)
        zone = FILE_EXT;

    for (int i = 0; i < curr.br.customLocations.size(); i++) {
        const custom_rule_location_t& custLoc = curr.br.customLocations[i];
        if (custLoc.specificUrl) {
            uri_idx = i;
        }
        if (custLoc.bodyVar) {
            name_idx = i;
            zone = BODY;
        }
        if (custLoc.headersVar) {
            name_idx = i;
            zone = HEADERS;
        }
        if (custLoc.argsVar) {
            name_idx = i;
            zone = ARGS;
        }
    }
}

void NxParser::wlrFind(const http_rule_t& curr, whitelist_rule_t& father_wlr, enum DUMMY_MATCH_ZONE &zone, int &uri_idx, int &name_idx) {
    string fullname = "";
    if (curr.br.targetName) // if WL targets variable name instead of content, prefix hash with '#'
        fullname += "#";
    if (uri_idx != -1 && name_idx != -1) {
        fullname += curr.br.customLocations[uri_idx].target;
        fullname += "#";
        fullname += curr.br.customLocations[name_idx].target;
    }
    else if (uri_idx != -1) {
        fullname += curr.br.customLocations[uri_idx].target;
    }
    else if (name_idx != -1) {
        fullname += curr.br.customLocations[name_idx].target;
    }

    for (const whitelist_rule_t& wlr : tmp_wlr) {
        if (wlr.name == fullname) {
            father_wlr = wlr;
            return;
        }
    }

    /*
    * Creates a new whitelist rule in the right place.
    * setup name and zone
    */
    father_wlr.name = fullname;
    father_wlr.zone = zone;
    if (uri_idx != -1 && name_idx == -1)
        father_wlr.uriOnly = true;
    if (curr.br.targetName)
        father_wlr.targetName = curr.br.targetName;
}

/*
** This function will take the whitelist basicrules generated during the configuration
** parsing phase, and aggregate them to build hashtables according to the matchzones.
**
** As whitelist can be in the form :
** "mz:$URL:bla|$ARGS_VAR:foo"
** "mz:$URL:bla|ARGS"
** "mz:$HEADERS_VAR:Cookie"
** ...
**
** So, we will aggregate all the rules that are pointing to the same URL together,
** as well as rules targetting the same argument name / zone.
*/
void NxParser::createHashTables() {
    for (http_rule_t& curr_r : whitelistRules) {
        int uri_idx = -1, name_idx = -1;
        enum DUMMY_MATCH_ZONE zone = UNKNOWN;

        if (curr_r.br.customLocations.size() == 0) {
//            wlrPushDisabled(curr_r);
            continue;
        }
        wlrIdentify(curr_r, zone, uri_idx, name_idx);
        curr_r.br.zone = zone;

        /*
        ** Handle regular-expression-matchzone rules :
        ** Store them in a separate linked list, parsed
        ** at runtime.
        */
        if (curr_r.br.rxMz) {
            rxmz_wlr.push_back(curr_r);
            continue;
        }

        /*
        ** Handle static match-zones for hashtables
        */
        whitelist_rule_t father_wl;
        wlrFind(curr_r, father_wl, zone, uri_idx, name_idx);
        /* merge the two rules into father_wl, meaning ids. Not locations, as we are getting rid of it */
        father_wl.ids.insert(father_wl.ids.end(), curr_r.wlIds.begin(), curr_r.wlIds.end());

        tmp_wlr.push_back(father_wl);
    }

    for (const whitelist_rule_t& wlr : tmp_wlr) {
        switch (wlr.zone) {
            case FILE_EXT:
            case BODY:
                wlBodyHash[wlr.name] = wlr;
                DEBUG_CONF_HT("body hash: " << wlr.name);
                break;
            case HEADERS:
                wlHeadersHash[wlr.name] = wlr;
                DEBUG_CONF_HT("header hash: " << wlr.name);
                break;
            case URL:
                wlUrlHash[wlr.name] = wlr;
                DEBUG_CONF_HT("url hash: " << wlr.name);
                break;
            case ARGS:
                wlArgsHash[wlr.name] = wlr;
                DEBUG_CONF_HT("args hash: " << wlr.name);
                break;
            default:
                DEBUG_CONF_HT("Unknown zone" << endl);
                return;
        }
        DEBUG_CONF_HT(endl);
    }
}