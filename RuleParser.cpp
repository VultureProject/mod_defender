/*                       _        _       __                _
 *   _ __ ___   ___   __| |    __| | ___ / _| ___ _ __   __| | ___ _ __
 *  | '_ ` _ \ / _ \ / _` |   / _` |/ _ \ |_ / _ \ '_ \ / _` |/ _ \ '__|
 *  | | | | | | (_) | (_| |  | (_| |  __/  _|  __/ | | | (_| |  __/ |
 *  |_| |_| |_|\___/ \__,_|___\__,_|\___|_|  \___|_| |_|\__,_|\___|_|
 *                       |_____|
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#define MATCH_ZONE_DEF
#include "RuleParser.h"

vector<string> tmpMainRules;

vector<http_rule_t> getRules;
vector<http_rule_t> bodyRules;
vector<http_rule_t> rawBodyRules;
vector<http_rule_t> headerRules;
vector<http_rule_t> genericRules; // URL

RuleParser::RuleParser() {
    /* Internal rules */
    bigRequest.id = 2;
    bigRequest.logMsg = "Big request";
    bigRequest.action = BLOCK;

    uncommonHexEncoding.id = 10;
    uncommonHexEncoding.logMsg = "Uncommon hex encoding";
    uncommonHexEncoding.action = BLOCK;

    uncommonContentType.id = 11;
    uncommonContentType.logMsg = "Uncommon content type";
    uncommonContentType.action = BLOCK;

    uncommonUrl.id = 12;
    uncommonUrl.logMsg = "Uncommon url";
    uncommonUrl.action = BLOCK;

    uncommonPostFormat.id = 13;
    uncommonPostFormat.logMsg = "Uncommon post format";
    uncommonPostFormat.action = BLOCK;

    uncommonPostBoundary.id = 14;
    uncommonPostBoundary.logMsg = "Uncommon post boundary";
    uncommonPostBoundary.action = BLOCK;

    invalidJson.id = 15;
    invalidJson.logMsg = "Invalid json";
    invalidJson.action = BLOCK;

    emptyPostBody.id = 16;
    emptyPostBody.logMsg = "Empty post body";
    emptyPostBody.action = BLOCK;

    libsqliRule.id = 17;
    libsqliRule.scores.emplace_back("$LIBINJECTION_SQL", 8);
    libsqliRule.action = BLOCK;

    libxssRule.id = 18;
    libxssRule.logMsg = "Libinjection XSS";
    libxssRule.scores.emplace_back("$LIBINJECTION_XSS", 8);
    libxssRule.action = BLOCK;
}

unsigned int RuleParser::parseMainRules(vector<string> &ruleLines, string errorMsg) {
    getRules.clear();
    bodyRules.clear();
    rawBodyRules.clear();
    headerRules.clear();
    genericRules.clear();

    unsigned int ruleCount = 0;
    stringstream err;
    for (string &ruleLine : ruleLines) {
        bool error = false;
        DEBUG_CONF_MR("MainRule ");
        http_rule_t rule;
        rule.br.active = true;
        rule.type = MAIN_RULE;

        vector<string> ruleParts = parseRawDirective(ruleLine);
        for (const string &rulePart : ruleParts) {
            if (rulePart == "negative") {
                rule.br.negative = true;
                DEBUG_CONF_MR("negative=1 ");
            }
            else if (rulePart.substr(0, 4) == "str:") {
                rule.br.str = rulePart.substr(4);
                std::transform(rule.br.str.begin(), rule.br.str.end(), rule.br.str.begin(), tolower);
                rule.br.match_type = STR;
                DEBUG_CONF_MR("str='" << rule.br.str << "' ");
            }
            else if (rulePart.substr(0, 3) == "rx:") {
                string rx = rulePart.substr(3);
                std::transform(rx.begin(), rx.end(), rx.begin(), tolower);
                try {
                    rule.br.rx = regex(rx, std::regex::optimize);
                } catch (std::regex_error &e) {
                    err << "rx:" << rx << " " << parseCode(e.code()) << endl;
                    error = true;
                }
                rule.br.match_type = RX;
                DEBUG_CONF_MR("rx='" << rx << "' ");
            } else if (rulePart == "d:libinj_sql") {
                rule.br.match_type = LIBINJ_SQL;
                DEBUG_CONF_MR("d='libinj_sql' ");
            } else if (rulePart == "d:libinj_xss") {
                rule.br.match_type = LIBINJ_XSS;
                DEBUG_CONF_MR("d='libinj_xss' ");
            } else if (rulePart.substr(0, 4) == "msg:") {
                rule.logMsg = rulePart.substr(4);
                DEBUG_CONF_MR("msg='" << rule.logMsg << "' ");
            } else if (rulePart.substr(0, 3) == "mz:") {
                string rawMatchZone = rulePart.substr(3);
                parseMatchZone(rule, rawMatchZone, err);
            } else if (rulePart.substr(0, 2) == "s:") {
                string score = rulePart.substr(2);
                vector<string> scores = split(score, ',');
                DEBUG_CONF_MR("score=[");
                for (const string &sc : scores) {
                    if (sc.front() == '$') { // $SCORE
                        pair<string, string> scorepair = splitAtFirst(sc, ":");
                        rule.scores.emplace_back(scorepair.first, std::stoul(scorepair.second));
                        DEBUG_CONF_MR("'" << scorepair.first << "'='" << scorepair.second << "'");
                    } else // action
                        parseAction(sc, rule.action);
                }
                DEBUG_CONF_MR("] ");
            } else if (rulePart.substr(0, 3) == "id:") {
                rule.id = std::stoul(rulePart.substr(3));
                DEBUG_CONF_MR("id='" << rule.id << "' ");
            }
        }

        if (!error) {
            /*
             * Naxsi has a bug that adds rules twice if there is multiple custom locations
             * "issue: Multiple *_VAR lead to multiple matching"
             * Handled here (enhancement)
             */
            if (rule.br.headersMz || rule.br.headersVarMz) { // push in headers rules
                headerRules.push_back(rule);
                DEBUG_CONF_MR("[header] ");
            }
            if (rule.br.bodyMz || rule.br.bodyVarMz) { // push in body match rules (POST/PUT)
                bodyRules.push_back(rule);
                DEBUG_CONF_MR("[body] ");
            }
            if (rule.br.rawBodyMz) { // push in raw body match rules (POST/PUT)
                rawBodyRules.push_back(rule);
                DEBUG_CONF_MR("[rawbody] ");
            }
            if (rule.br.urlMz || rule.br.specificUrlMz) { // push in generic rules, as it's matching the URI
                genericRules.push_back(rule);
                DEBUG_CONF_MR("[generic] ");
            }
            if (rule.br.argsMz ||
                rule.br.argsVarMz) { // push in GET arg rules, but we should push in POST rules too
                getRules.push_back(rule);
                DEBUG_CONF_MR("[get] ");
            }
        }

        if (!error)
            ruleCount++;
        else
            err << "MainRule #" << rule.id << " skipped" << endl;
        DEBUG_CONF_MR(endl);
    }
    errorMsg = err.str();
    ruleLines.clear();
    return ruleCount;
}

void RuleParser::parseCheckRule(vector<pair<string, string>> &rulesArray, string errorMsg) {
    stringstream err;
    for (const pair<string, string> &rule : rulesArray) {
        const string &equation = rule.first;
        const string &action = rule.second;

        DEBUG_CONF_CR("CheckRule ");
        check_rule_t chkrule;
        vector<string> eqParts = split(equation, ' ');

        string tag = (std::basic_string<char, std::char_traits<char>, std::allocator<char>> &&) rtrim(eqParts[0]);
        DEBUG_CONF_CR(tag << " ");

        if (eqParts[1] == ">=") {
            chkrule.comparator = SUP_OR_EQUAL;
            DEBUG_CONF_CR(">= ");
        } else if (eqParts[1] == ">") {
            chkrule.comparator = SUP;
            DEBUG_CONF_CR("> ");
        } else if (eqParts[1] == "<=") {
            chkrule.comparator = INF_OR_EQUAL;
            DEBUG_CONF_CR("<= ");
        } else if (eqParts[1] == "<") {
            chkrule.comparator = INF;
            DEBUG_CONF_CR("< ");
        }

        try {
            chkrule.limit = std::stoul(eqParts[2]);
            DEBUG_CONF_CR(chkrule.limit << " ");
        }
        catch (std::exception const &e) {
            err << e.what() << " cannot convert " << eqParts[2] << " to integer" << endl;
            continue;
        }

        parseAction(action, chkrule.action);

        checkRules[tag] = chkrule;

        DEBUG_CONF_CR(endl);
    }
    errorMsg = err.str();
    rulesArray.clear();
}

unsigned int RuleParser::parseBasicRules(vector<string> &ruleLines, string errorMsg) {
    unsigned int ruleCount = 0;
    stringstream err;
    for (string &ruleLine : ruleLines) {
        DEBUG_CONF_BR("BasicRule ");
        http_rule_t rule;
        rule.type = BASIC_RULE;
        rule.whitelist = true;

        vector<string> ruleParts = parseRawDirective(ruleLine);
        for (const string &rulePart : ruleParts) {
            if (rulePart.substr(0, 3) == "wl:") {
                string rawWhitelist = rulePart.substr(3);
                rule.wlIds = splitToInt(rawWhitelist, ',');
#ifdef DEBUG_CONFIG_BASICRULE
                DEBUG_CONF_BR("wl='");
                for (const int &id : rule.wlIds)
                    DEBUG_CONF_BR(id << ".");
                DEBUG_CONF_BR("' ");
#endif // !DEBUG_CONFIG_BASICRULE
            } else if (rulePart.substr(0, 3) == "mz:") {
                string rawMatchZone = rulePart.substr(3);
                parseMatchZone(rule, rawMatchZone, err);
                rule.br.active = true;
            }
        }

        whitelistRules.push_back(rule);
        ruleCount++;
        DEBUG_CONF_BR(endl);
    }
    errorMsg = err.str();
    ruleLines.clear();
    return ruleCount;
}

void RuleParser::parseAction(string action, rule_action_t &rule_action) {
    if (action == "BLOCK") {
        rule_action = BLOCK;
        DEBUG_CONF_ACTN("BLOCK ");
    } else if (action == "DROP") {
        rule_action = DROP;
        DEBUG_CONF_ACTN("DROP ");
    } else if (action == "ALLOW") {
        rule_action = ALLOW;
        DEBUG_CONF_ACTN("ALLOW ");
    } else if (action == "LOG") {
        rule_action = LOG;
        DEBUG_CONF_ACTN("LOG ");
    }
}

void RuleParser::parseMatchZone(http_rule_t &rule, string &rawMatchZone, stringstream &err) {
    vector<string> matchZones = split(rawMatchZone, '|');
    for (const string &mz : matchZones) {
        if (mz[0] != '$') {
            if (mz == "ARGS") {
                rule.br.argsMz = true;
                DEBUG_CONF_MZ("ARGS ");
            } else if (mz == "HEADERS") {
                rule.br.headersMz = true;
                DEBUG_CONF_MZ("HEADERS ");
            } else if (mz == "URL") {
                rule.br.urlMz = true;
                DEBUG_CONF_MZ("URL ");
            } else if (mz == "BODY") {
                rule.br.bodyMz = true;
                DEBUG_CONF_MZ("BODY ");
            } else if (mz == "RAWBODY") {
                rule.br.rawBodyMz = true;
                DEBUG_CONF_MZ("RAWBODY ");
            } else if (mz == "FILE_EXT") {
                rule.br.fileExtMz = true;
                rule.br.bodyMz = true;
                DEBUG_CONF_MZ("FILE_EXT ");
            } else if (mz == "NAME") {
                rule.br.targetName = true;
                DEBUG_CONF_MZ("NAME ");
            }
        } else {
            custom_rule_location_t customRule;
            rule.br.customLocation = true;
            pair<string, string> cmz = splitAtFirst(mz, ":");

            if (cmz.first == "$ARGS_VAR") {
                customRule.argsVar = true;
                rule.br.argsVarMz = true;
                DEBUG_CONF_MZ("$ARGS_VAR ");
            } else if (cmz.first == "$HEADERS_VAR") {
                customRule.headersVar = true;
                rule.br.headersVarMz = true;
                DEBUG_CONF_MZ("$HEADERS_VAR ");
            } else if (cmz.first == "$URL") {
                customRule.specificUrl = true;
                rule.br.specificUrlMz = true;
                DEBUG_CONF_MZ("$URL ");
            } else if (cmz.first == "$BODY_VAR") {
                customRule.bodyVar = true;
                rule.br.bodyVarMz = true;
                DEBUG_CONF_MZ("$BODY_VAR ");
            } else if (cmz.first == "$ARGS_VAR_X") {
                customRule.argsVar = true;
                rule.br.argsVarMz = true;
                rule.br.rxMz = true;
                DEBUG_CONF_MZ("$ARGS_VAR_X ");
            } else if (cmz.first == "$HEADERS_VAR_X") {
                customRule.headersVar = true;
                rule.br.headersVarMz = true;
                rule.br.rxMz = true;
                DEBUG_CONF_MZ("$HEADERS_VAR_X ");
            } else if (cmz.first == "$URL_X") {
                customRule.specificUrl = true;
                rule.br.specificUrlMz = true;
                rule.br.rxMz = true;
                DEBUG_CONF_MZ("$URL_X ");
            } else if (cmz.first == "$BODY_VAR_X") {
                customRule.bodyVar = true;
                rule.br.bodyVarMz = true;
                rule.br.rxMz = true;
                DEBUG_CONF_MZ("$BODY_VAR_X ");
            }

            if (!rule.br.rxMz) { // String MatchZone
                std::transform(cmz.second.begin(), cmz.second.end(), cmz.second.begin(), tolower);
                customRule.target = cmz.second;
                DEBUG_CONF_MZ("(str)" << cmz.second << " ");
            } else { // Regex MatchZone
                try {
                    customRule.targetRx = regex(cmz.second, std::regex::optimize);
                } catch (std::regex_error &e) {
                    err << "regex_error: " << parseCode(e.code()) << endl;
                    continue;
                }
                DEBUG_CONF_MZ("(rx)" << cmz.second << " ");
            }
            rule.br.customLocations.push_back(customRule);
        }
    }
    DEBUG_CONF_MZ((rule.br.rxMz ? "(rxMz) " : " "));
}

/* check rule, returns associed zone, as well as location index.
  location index refers to $URL:bla or $ARGS_VAR:bla */
void RuleParser::wlrIdentify(const http_rule_t &curr, MATCH_ZONE &zone, int &uriIndex, int &nameIndex) {
    if (curr.br.bodyMz || curr.br.bodyVarMz)
        zone = BODY;
    else if (curr.br.headersMz || curr.br.headersVarMz)
        zone = HEADERS;
    else if (curr.br.argsMz || curr.br.argsVarMz)
        zone = ARGS;
    else if (curr.br.urlMz) /*don't assume that named $URL means zone is URL.*/
        zone = URL;
    else if (curr.br.fileExtMz)
        zone = FILE_EXT;

    size_t i = 0;
    for ( i = 0; i < curr.br.customLocations.size(); i++) {
        const custom_rule_location_t &loc = curr.br.customLocations[i];
        if (loc.specificUrl) {
            uriIndex = i;
        }
        if (loc.bodyVar) {
            if (nameIndex != -1) {
                DEBUG_CONF_HT("whitelist can't target more than one BODY item.");
                return;
            }
            nameIndex = i;
            zone = BODY;
        }
        if (loc.headersVar) {
            if (nameIndex != -1) {
                DEBUG_CONF_HT("whitelist can't target more than one HEADERS item.");
                return;
            }
            nameIndex = i;
            zone = HEADERS;
        }
        if (loc.argsVar) {
            if (nameIndex != -1) {
                DEBUG_CONF_HT("whitelist can't target more than one ARGS item.");
                return;
            }
            nameIndex = i;
            zone = ARGS;
        }
    }
}

void RuleParser::wlrFind(const http_rule_t &curr, whitelist_rule_t &father_wlr, MATCH_ZONE &zone, int &uriIndex,
                         int &nameIndex) {
    string fullname = "";
    /* if WL targets variable name instead of content, prefix hash with '#' */
    if (curr.br.targetName) {
        DEBUG_CONF_WLRF("whitelist targets |NAME");
        fullname += "#";
    }
    if (uriIndex != -1 && nameIndex != -1) { // name AND uri
        DEBUG_CONF_WLRF("whitelist has uri + name");
        fullname += curr.br.customLocations[uriIndex].target + "#" + curr.br.customLocations[nameIndex].target;
    } else if (uriIndex != -1) { // only uri
        DEBUG_CONF_WLRF("whitelist has uri");
        fullname += curr.br.customLocations[uriIndex].target;
    } else if (nameIndex != -1) { // only name
        DEBUG_CONF_WLRF("whitelist has name");
        fullname += curr.br.customLocations[nameIndex].target;
    } else {
        DEBUG_CONF_WLRF("wlrFind problem");
        return;
    }

    for (const whitelist_rule_t &wlr : tmpWlr) {
        if (wlr.name == fullname && wlr.zone == zone) {
            DEBUG_CONF_WLRF("found existing 'same' WL : " << wlr.name);
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
    /* If there is URI and no name idx, specify it,
	 so that WL system won't get fooled by an argname like an URL */
    if (uriIndex != -1 && nameIndex == -1)
        father_wlr.uriOnly = true;
    if (curr.br.targetName) // If targetName is present in son, report it
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
void RuleParser::generateHashTables() {
    for (http_rule_t &curr_r : whitelistRules) {
        int uriIndex = -1, nameIndex = -1;
        MATCH_ZONE zone = UNKNOWN;

        /* no custom location at all means that the rule is disabled */
        if (curr_r.br.customLocations.empty()) {
            disabled_rules.push_back(curr_r);
            continue;
        }
        wlrIdentify(curr_r, zone, uriIndex, nameIndex);
        curr_r.br.zone = zone;

        /*
        ** Handle regular-expression-matchzone rules :
        ** Store them in a separate linked list, parsed
        ** at runtime.
        */
        if (curr_r.br.rxMz) {
            /*
             * Naxsi converts custom location string target to regex target here,
             * because it does not handle whitelist that mix _X elements with _VAR or $URL items.
             * Not necessary ! Mod Defender supports it ;) (enhancement)
             */

            rxMzWlr.push_back(curr_r);
            continue;
        }

        /*
        ** Handle static match-zones for hashtables
        */
        whitelist_rule_t father_wl;
        wlrFind(curr_r, father_wl, zone, uriIndex, nameIndex);
        /* merge the two rules into father_wl, meaning ids. Not locations, as we are getting rid of it */
        father_wl.ids.insert(father_wl.ids.end(), curr_r.wlIds.begin(), curr_r.wlIds.end());

        tmpWlr.push_back(father_wl);
    }

    for (const whitelist_rule_t &wlr : tmpWlr) {
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

bool RuleParser::checkIds(unsigned long matchId, const vector<int> &wlIds) {
    bool negative = false;

    for (auto &wlId : wlIds) {
        if (wlId == matchId)
            return true;
        if (wlId == 0) // WHY ??
            return true;
        if (wlId < 0 && matchId >= 1000) { // manage negative whitelists, except for internal rules
            negative = true;
            if (matchId == -wlId) // negative wl excludes this one
                return false;
        }
    }
    return negative;
}

bool RuleParser::isWhitelistAdapted(whitelist_rule_t &wlrule, MATCH_ZONE zone, const http_rule_t &rule, MATCH_TYPE type,
                                    bool targetName) {
    if (zone == FILE_EXT)
        zone = BODY; // FILE_EXT zone is just a hack, as it indeed targets BODY

    if (wlrule.targetName && !targetName) { // if whitelist targets arg name, but the rules hit content
        DEBUG_CONF_WL("whitelist targets name, but rule matched content.");
        return false;
    }
    if (!wlrule.targetName && targetName) { // if if the whitelist target contents, but the rule hit arg name
        DEBUG_CONF_WL("whitelist targets content, but rule matched name.");
        return false;
    }


    if (type == NAME_ONLY) {
        DEBUG_CONF_WL("Name match in zone " <<
                                            (zone == ARGS ? "ARGS" : zone == BODY ? "BODY" : zone == HEADERS ? "HEADERS"
                                                                                                             : "UNKNOWN!!!!!"));
        //False Positive, there was a whitelist that matches the argument name,
        // But is was actually matching an existing URI name.
        if (zone != wlrule.zone || wlrule.uriOnly) {
            DEBUG_CONF_WL("bad whitelist, name match, but WL was only on URL.");
            return false;
        }
        return (checkIds(rule.id, wlrule.ids));
    }
    if (type == URI_ONLY ||
        type == MIXED) {
        /* zone must match */
        if (wlrule.uriOnly && type != URI_ONLY) {
            DEBUG_CONF_WL("bad whitelist, type is URI_ONLY, but not whitelist");
            return false;
        }

        if (zone != wlrule.zone) {
            DEBUG_CONF_WL("bad whitelist, URL match, but not zone");
            return false;
        }

        return (checkIds(rule.id, wlrule.ids));
    }
    DEBUG_CONF_WL("finished wl check, failed.");

    return false;
}

bool RuleParser::isRuleWhitelisted(const http_rule_t &rule, const string &uri, const string &name, MATCH_ZONE zone,
                                   bool targetName) {
    /* Check if the rule is part of disabled rules for this location */
    for (const http_rule_t &disabledRule : disabled_rules) {
        if (checkIds(rule.id, disabledRule.wlIds)) { // Is rule disabled ?
            /* If rule target nothing, it's whitelisted everywhere */
            if (!(disabledRule.br.argsMz || disabledRule.br.headersMz ||
                  disabledRule.br.bodyMz || disabledRule.br.urlMz)) {
                DEBUG_CONF_WL("rule " << rule.id << " not targeting any zone, whitelisted everywhere");
                return true;
            }

            if (!disabledRule.br.active) { // if it doesn't specify zone, skip zone-check
                DEBUG_CONF_WL("rule " << rule.id << " not targeting any zone, skipping zone-check");
                continue;
            }

            /* if exc is in name, but rule is not specificaly disabled for name (and targets a zone)  */
            if (targetName != disabledRule.br.targetName)
                continue;

            switch (zone) {
                case ARGS:
                    if (disabledRule.br.argsMz) {
                        DEBUG_CONF_WL("rule " << rule.id << " is disabled in ARGS");
                        return true;
                    }
                    break;
                case HEADERS:
                    if (disabledRule.br.headersMz) {
                        DEBUG_CONF_WL("rule " << rule.id << " is disabled in HEADERS");
                        return true;
                    }
                    break;
                case BODY:
                    if (disabledRule.br.bodyMz) {
                        DEBUG_CONF_WL("rule " << rule.id << " is disabled in BODY");
                        return true;
                    }
                    break;
                case FILE_EXT:
                    if (disabledRule.br.fileExtMz) {
                        DEBUG_CONF_WL("rule " << rule.id << " is disabled in FILE_EXT");
                        return true;
                    }
                    break;
                case URL:
                    if (disabledRule.br.urlMz) {
                        DEBUG_CONF_WL("rule " << rule.id << " is disabled in URL zone:" << zone);
                        return true;
                    }
                    break;
                default:
                    break;
            }
        }
    }

    whitelist_rule_t wlRule;

    /* check for ARGS_VAR:x(|NAME) whitelists. */
    /* (name) or (#name) */
    if (name.length() > 0) {
        /* try to find in hashtables */
        bool found = findWlInHash(wlRule, name, zone);
        if (found && isWhitelistAdapted(wlRule, zone, rule, NAME_ONLY, targetName))
            return true;

        string hashname = "#" + name;
        DEBUG_CONF_WL("hashing varname [" << name << "] (rule:" << rule.id << ") - 'wl:X_VAR:" << name << "%V|NAME'");
        found = findWlInHash(wlRule, hashname, zone);
        if (found && isWhitelistAdapted(wlRule, zone, rule, NAME_ONLY, targetName))
            return true;
    }

    /* Plain URI whitelists */
    /* check the URL no matter what zone we're in */
    if (!wlUrlHash.empty()) {
        /* mimic find_wl_in_hash, we are looking in a different hashtable */
        string hashname = string(uri);
        std::transform(hashname.begin(), hashname.end(), hashname.begin(), tolower);
        DEBUG_CONF_WL("hashing uri [" << hashname << "] (rule:" << rule.id << ") 'wl:$URI:" << hashname << "|*'");

        unordered_map<string, whitelist_rule_t>::const_iterator it = wlUrlHash.find(hashname);
        bool found = false;
        if (it != wlUrlHash.end()) {
            wlRule = it->second;
            found = true;
        }

        if (found && isWhitelistAdapted(wlRule, zone, rule, URI_ONLY, targetName))
            return true;
    }

    /* Lookup for $URL|URL (uri)*/
    DEBUG_CONF_WL("hashing uri#1 [" << uri << "] (rule:" << rule.id << ") ($URL:X|URI)");
    bool found = findWlInHash(wlRule, uri, zone);
    if (found && isWhitelistAdapted(wlRule, zone, rule, URI_ONLY, targetName))
        return true;

    /* Looking $URL:x|ZONE|NAME */
    string hashname = "#" + uri;
    DEBUG_CONF_WL("hashing uri#3 [" << hashname << "] (rule:" << rule.id << ") ($URL:X|ZONE|NAME)");
    found = findWlInHash(wlRule, hashname, zone);
    if (found && isWhitelistAdapted(wlRule, zone, rule, URI_ONLY, targetName))
        return true;

    /* Maybe it was $URL+$VAR (uri#name) or (#uri#name) */
    hashname.clear();
    if (targetName) {
        hashname += "#";
    }
    hashname += uri + "#" + name;
    DEBUG_CONF_WL("hashing MIX [" << hashname << "] ($URL:x|$X_VAR:y) or ($URL:x|$X_VAR:y|NAME)");
    found = findWlInHash(wlRule, hashname, zone);
    if (found && isWhitelistAdapted(wlRule, zone, rule, MIXED, targetName))
        return true;

    if (isRuleWhitelistedRx(rule, uri, name, zone, targetName)) {
        DEBUG_CONF_WL("Whitelisted by RX !");
        return true;
    }

    return false;
}

bool RuleParser::isRuleWhitelistedRx(const http_rule_t &rule, const string uri, const string &name,
                                     MATCH_ZONE zone, bool targetName) {
    /* Look it up in regexed whitelists for matchzones */
    if (rxMzWlr.empty()) {
        DEBUG_CONF_WL("No rx matchzone rules");
        return false;
    }

    for (const http_rule_t &rxMzRule : rxMzWlr) {
        if (!rxMzRule.br.active || rxMzRule.br.customLocations.empty()) {
            DEBUG_CONF_WL("Rule pushed to RXMZ, but has no custom_location.");
            continue;
        }

        /*
        ** once we have pointer to the rxMzRule :
        ** - go through each custom location (ie. ARGS_VAR_X:foobar*)
        ** - verify that regular expressions match. If not, it means whitelist does not apply.
        */
        if (rxMzRule.br.zone != zone) {
            DEBUG_CONF_WL("Not targeting same zone: custom rule loc zone: " << match_zones[rxMzRule.br.zone] <<
                                                                            " current zone: " << match_zones[zone]);
            continue;
        }

        if (targetName != rxMzRule.br.targetName) {
            DEBUG_CONF_WL("Only one target name");
            continue;
        }

        bool violation = false;
        for (const custom_rule_location_t &loc : rxMzRule.br.customLocations) {
            if (loc.bodyVar) {
                if (!loc.target.empty()) {
                    if (name != loc.target) {
                        violation = true;
                        DEBUG_CONF_WL("[BODY] FAIL (str:" << name << ")");
                        break;
                    }
                    DEBUG_CONF_WL("[BODY] Match (str:" << name << ")");
                } else {
                    if (!regex_search(name, loc.targetRx)) {
                        violation = true;
                        DEBUG_CONF_WL("[BODY] RX FAIL (str:" << name << ")");
                        break;
                    }
                    DEBUG_CONF_WL("[BODY] RX Match (str:" << name << ")");
                }
            }
            if (loc.argsVar) {
                if (!loc.target.empty()) {
                    if (name != loc.target) {
                        violation = true;
                        DEBUG_CONF_WL("[ARGS] FAIL (str:" << name << ")");
                        break;
                    }
                    DEBUG_CONF_WL("[ARGS] Match (str:" << name << ")");
                } else {
                    if (!regex_search(name, loc.targetRx)) {
                        violation = true;
                        DEBUG_CONF_WL("[ARGS] RX FAIL (str:" << name << ")");
                        break;
                    }
                    DEBUG_CONF_WL("[ARGS] RX Match (str:" << name << ")");
                }
            }
            if (loc.specificUrl) {
                if (!loc.target.empty()) {
                    if (uri != loc.target) {
                        violation = true;
                        DEBUG_CONF_WL("[URI] FAIL (str:" << uri << ")");
                        break;
                    }
                    DEBUG_CONF_WL("[URI] Match (str:" << uri << ")");
                } else {
                    if (!regex_search(uri, loc.targetRx)) {
                        violation = true;
                        DEBUG_CONF_WL("[URI] RX FAIL (str:" << uri << ")");
                        break;
                    }
                    DEBUG_CONF_WL("[URI] RX Match (str:" << uri << ")");
                }
            }
        }

        if (!violation) {
            DEBUG_CONF_WL("rxMzRule whitelisted by rx");
            if (checkIds(rule.id, rxMzRule.wlIds))
                return true;
        }
    }
    return false;
}

bool RuleParser::findWlInHash(whitelist_rule_t &wlRule, const string &key, MATCH_ZONE zone) {
    if (zone == BODY || zone == FILE_EXT) {
        unordered_map<string, whitelist_rule_t>::const_iterator it = wlBodyHash.find(key);
        if (it != wlBodyHash.end()) {
            wlRule = it->second;
            return true;
        }
    } else if (zone == HEADERS) {
        unordered_map<string, whitelist_rule_t>::const_iterator it = wlHeadersHash.find(key);
        if (it != wlHeadersHash.end()) {
            wlRule = it->second;
            return true;
        }
    } else if (zone == URL) {
        unordered_map<string, whitelist_rule_t>::const_iterator it = wlUrlHash.find(key);
        if (it != wlUrlHash.end()) {
            wlRule = it->second;
            return true;
        }
    } else if (zone == ARGS) {
        unordered_map<string, whitelist_rule_t>::const_iterator it = wlArgsHash.find(key);
        if (it != wlArgsHash.end()) {
            wlRule = it->second;
            return true;
        }
    }
    return false;
}

string RuleParser::parseCode(std::regex_constants::error_type etype) {
    switch (etype) {
        case std::regex_constants::error_collate:
            return "error_collate: invalid collating element request";
        case std::regex_constants::error_ctype:
            return "error_ctype: invalid character class";
        case std::regex_constants::error_escape:
            return "error_escape: invalid escape character or trailing escape";
        case std::regex_constants::error_backref:
            return "error_backref: invalid back reference";
        case std::regex_constants::error_brack:
            return "error_brack: mismatched bracket([ or ])";
        case std::regex_constants::error_paren:
            return "error_paren: mismatched parentheses(( or ))";
        case std::regex_constants::error_brace:
            return "error_brace: mismatched brace({ or })";
        case std::regex_constants::error_badbrace:
            return "error_badbrace: invalid range inside a { }";
        case std::regex_constants::error_range:
            return "erro_range: invalid character range(e.g., [z-a])";
        case std::regex_constants::error_space:
            return "error_space: insufficient memory to handle this regular expression";
        case std::regex_constants::error_badrepeat:
            return "error_badrepeat: a repetition character (*, ?, +, or {) was not preceded by a valid regular expression";
        case std::regex_constants::error_complexity:
            return "error_complexity: the requested match is too complex";
        case std::regex_constants::error_stack:
            return "error_stack: insufficient memory to evaluate a match";
        default:
            return "";
    }
}