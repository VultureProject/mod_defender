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
        pair<string, string> matchPatern = Util::splitAtFirst(((const char **) rulesArray->elts)[i], ":");
        rule.br.rxMz = (matchPatern.first == "rx");
        DEBUG_CONF_MR((rule.br.rxMz ? "rx " : "str "));
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
        vector<string> scores = Util::split(score, ',');
        for (const string &sc : scores) {
            pair<string, string> scorepair = Util::splitAtFirst(sc, ":");
            rule.scores.emplace_back(apr_pstrdup(p, scorepair.first.c_str()), std::stoi(scorepair.second));
            DEBUG_CONF_MR(scorepair.first << " " << scorepair.second << " ");
        }

        rule.id = std::stoi(((const char **) rulesArray->elts)[i + 4] + 3);
        DEBUG_CONF_MR(rule.id << " ");

        if (rule.br.headersMz) {
            headerRules.push_back(rule);
            DEBUG_CONF_MR("[header] ");
        }
        if (rule.br.bodyMz || rule.br.bodyVarMz) { // push in body match rules (POST/PUT)
            bodyRules.push_back(rule);
            DEBUG_CONF_MR("[body] ");
        }
        if (rule.br.urlMz) { // push in generic rules, as it's matching the URI
            genericRules.push_back(rule);
            DEBUG_CONF_MR("[generic] ");
        }
        if (rule.br.argsMz || rule.br.argsVarMz) { // push in GET arg rules, but we should push in POST rules too
            getRules.push_back(rule);
            DEBUG_CONF_MR("[get] ");
        }
        /* push in custom locations. It's a rule matching a VAR_NAME or an EXACT_URI :
            - GET_VAR, POST_VAR, URI */
        if (rule.br.customLocation) {
            for (const custom_rule_location_t &loc : rule.br.customLocations) {
                if (loc.argsVar) {
                    getRules.push_back(rule);
                    DEBUG_CONF_MR("[get] ");
                }
                if (loc.bodyVar) {
                    bodyRules.push_back(rule);
                    DEBUG_CONF_MR("[body] ");
                }
                if (loc.headersVar) {
                    headerRules.push_back(rule);
                    DEBUG_CONF_MR("[header] ");
                }
            }
        }
        DEBUG_CONF_MR(endl);
    }
}

void NxParser::parseCheckRules(apr_array_header_t *rulesArray) {
    for (int i = 0; i < rulesArray->nelts; i += 2) {
        DEBUG_CONF_CR("CheckRule ");
        check_rule_t chkrule;
        string equation = string(((const char **) rulesArray->elts)[i]);
        vector<string> eqParts = Util::split(equation, ' ');

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

        rule.whitelist = true;
        rule.wlIds = Util::splitToInt(rawWhitelist, ',');
        for (const int &id : rule.wlIds) {
            DEBUG_CONF_BR(id << " ");
        }

        // If not matchzone specified
        if (rawWhitelist.back() == ';') {
            i -= 2;
            whitelistRules.push_back(rule);
            rule.hasBr = false;
            DEBUG_CONF_BR(endl);
            continue;
        }

        string rawMatchZone = ((const char **) rulesArray->elts)[i + 1] + 3;
        parseMatchZone(rule, rawMatchZone);

        whitelistRules.push_back(rule);
        DEBUG_CONF_BR(endl);
    }
}

void NxParser::parseMatchZone(http_rule_t &rule, string &rawMatchZone) {
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
                rule.br.specificUrlMz = true;
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
                rule.br.specificUrlMz = true;
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
                DEBUG_CONF_MZ("(rx)" << cmz.second << " ");
            }
            else {
                customRule.targetRx = regex(cmz.second);
                DEBUG_CONF_MZ("(str)" << cmz.second << " ");
            }
            rule.br.customLocations.push_back(customRule);
        }
    }
}

/* check rule, returns associed zone, as well as location index.
  location index refers to $URL:bla or $ARGS_VAR:bla */
void NxParser::wlrIdentify(const http_rule_t &curr, enum DUMMY_MATCH_ZONE &zone, int &uri_idx, int &name_idx) {
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
        const custom_rule_location_t &custLoc = curr.br.customLocations[i];
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

void NxParser::wlrFind(const http_rule_t &curr, whitelist_rule_t &father_wlr, enum DUMMY_MATCH_ZONE &zone, int &uri_idx,
                       int &name_idx) {
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

    for (const whitelist_rule_t &wlr : tmp_wlr) {
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
    /* If there is URI and no name idx, specify it,
	 so that WL system won't get fooled by an argname like an URL */
    if (uri_idx != -1 && name_idx == -1)
        father_wlr.uriOnly = true;
    if (curr.br.targetName) // If target_name is present in son, report it
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
    for (http_rule_t &curr_r : whitelistRules) {
        int uri_idx = -1, name_idx = -1;
        enum DUMMY_MATCH_ZONE zone = UNKNOWN;

        if (curr_r.br.customLocations.size() == 0) {
            disabled_rules.push_back(curr_r);
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

    for (const whitelist_rule_t &wlr : tmp_wlr) {
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

bool NxParser::checkIds(int matchId, const vector<int> &wlIds) {
    bool negative = false;

    for (const int &wlId : wlIds) {
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

bool NxParser::isWhitelistAdapted(whitelist_rule_t &wlrule, const string &name, enum DUMMY_MATCH_ZONE zone, const http_rule_t &rule,
                                  enum MATCH_TYPE type, bool targetName) {
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
}

// name is hashkey
bool NxParser::isRuleWhitelisted(const string& uri, const http_rule_t &rule, const string &name, enum DUMMY_MATCH_ZONE zone,
                                    bool targetName) {
    /* Check if the rule is part of disabled rules for this location */
    for (const http_rule_t &disabledRule : disabled_rules) {
        if (checkIds(rule.id, disabledRule.wlIds)) { // Is rule disabled ?
            if (!disabledRule.hasBr) { // if it doesn't specify zone, skip zone-check
                continue;
            }

            /* If rule target nothing, it's whitelisted everywhere */
            if (!(disabledRule.br.argsMz || disabledRule.br.headersMz ||
                  disabledRule.br.bodyMz || disabledRule.br.urlMz)) {
                return true;
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
        if (found && isWhitelistAdapted(wlRule, name, zone, rule, NAME_ONLY, targetName))
            return true;

        string hashname = "#";
        hashname += name;
        DEBUG_CONF_WL("hashing varname [" << name << "] (rule:" << rule.id << ") - 'wl:X_VAR:" << name << "%V|NAME'");
        found = findWlInHash(wlRule, hashname, zone);
        if (found && isWhitelistAdapted(wlRule, name, zone, rule, NAME_ONLY, targetName))
            return true;
    }

    /* Plain URI whitelists */
    /* check the URL no matter what zone we're in */
    if (wlUrlHash.size() > 0) {
        /* mimic find_wl_in_hash, we are looking in a different hashtable */
        string hashname = string(uri);
        std::transform(hashname.begin(), hashname.end(), hashname.begin(), ::tolower);
        DEBUG_CONF_WL("hashing uri [" << hashname << "] (rule:" << rule.id << ") 'wl:$URI:" << hashname << "|*'");

        unordered_map<string, whitelist_rule_t>::const_iterator it = wlUrlHash.find(hashname);
        bool found = false;
        if (it != wlUrlHash.end()) {
            wlRule = it->second;
            found = true;
        }

        if (found && isWhitelistAdapted(wlRule, name, zone, rule, URI_ONLY, targetName))
            return true;
    }

    /* Lookup for $URL|URL (uri)*/
    DEBUG_CONF_WL("hashing uri#1 [" << uri << "] (rule:" << rule.id << ") ($URL:X|URI)");
    bool found = findWlInHash(wlRule, uri, zone);
    if (found && isWhitelistAdapted(wlRule, name, zone, rule, URI_ONLY, targetName))
        return true;

    /* Looking $URL:x|ZONE|NAME */
    string hashname = "#";
    /* should make it sound crit isn't it ?*/
    hashname += uri;
    DEBUG_CONF_WL("hashing uri#3 [" << hashname << "] (rule:" << rule.id << ") ($URL:X|ZONE|NAME)");
    found = findWlInHash(wlRule, hashname, zone);
    if (found && isWhitelistAdapted(wlRule, name, zone, rule, URI_ONLY, targetName))
        return true;

    /* Maybe it was $URL+$VAR (uri#name) or (#uri#name) */
    hashname.clear();
    if (targetName) {
        hashname += "#";
    }
    hashname += uri;
    hashname += "#";
    hashname += name;
    DEBUG_CONF_WL("hashing MIX [" << hashname << "] ($URL:x|$X_VAR:y) or ($URL:x|$X_VAR:y|NAME)");
    found = findWlInHash(wlRule, hashname, zone);
    if (found && isWhitelistAdapted(wlRule, name, zone, rule, MIXED, targetName))
        return true;

    if (isRuleWhitelistedRx(rule, name, zone, targetName)) {
        DEBUG_CONF_WL("Whitelisted by RX !");
        return true;
    }

    return false;
}

bool NxParser::isRuleWhitelistedRx(const http_rule_t &rule, const string &name, enum DUMMY_MATCH_ZONE zone, bool targetName) {
    /* Look it up in regexed whitelists for matchzones */
    if (rxmz_wlr.size() > 0)
        return false;

    for (const http_rule_t &rxMwRule : rxmz_wlr) {
        if (!rxMwRule.hasBr || rxMwRule.br.customLocations.size() == 0) {
            DEBUG_CONF_WL("Rule pushed to RXMZ, but has no custom_location.");
            continue;
        }

        /*
        ** once we have pointer to the rxMwRule :
        ** - go through each custom location (ie. ARGS_VAR_X:foobar*)
        ** - verify that regular expressions match. If not, it means whitelist does not apply.
        */
        if (rxMwRule.br.zone != zone) {
            DEBUG_CONF_WL("Not targeting same zone.");
            continue;
        }

        if (targetName != rxMwRule.br.targetName) {
            DEBUG_CONF_WL("only one target_name");
            continue;
        }

        bool violation = false;
        for (const custom_rule_location_t& custloc : rxMwRule.br.customLocations) {
            if (custloc.bodyVar) {
//                long match = distance(sregex_iterator(name.begin(), name.end(), custloc.targetRx), sregex_iterator());
                bool match = regex_match(name, custloc.targetRx);
                if (!match) {
                    violation = true;
                    DEBUG_CONF_WL("[BODY] FAIL (str:" << name << ")");
                    break;
                }
                DEBUG_CONF_WL("[BODY] Match (str:" << name << ")");
            }
            if (custloc.argsVar) {
                bool match = regex_match(name, custloc.targetRx);
                if (!match) {
                    violation = true;
                    DEBUG_CONF_WL("[ARGS] FAIL (str:" << name << ")");
                    break;
                }
                DEBUG_CONF_WL("[ARGS] Match (str:" << name << ")");
            }
            if (custloc.specificUrl) {
                bool match = regex_match(name, custloc.targetRx);
                if (!match) {
                    violation = true;
                    DEBUG_CONF_WL("[URI] FAIL (str:" << name << ")");
                    break;
                }
                DEBUG_CONF_WL("[URI] Match (str:" << name << ")");
            }
        }

        if (!violation) {
            DEBUG_CONF_WL("rxMwRule whitelisted by rx");
            if (checkIds(rule.id, rxMwRule.wlIds))
                return true;
        }
    }
}

bool NxParser::findWlInHash(whitelist_rule_t &wlRule, const string &key, enum DUMMY_MATCH_ZONE zone) {
    string keyLowered = string(key);
    std::transform(keyLowered.begin(), keyLowered.end(), keyLowered.begin(), ::tolower);

    if (zone == BODY || zone == FILE_EXT) {
        unordered_map<string, whitelist_rule_t>::const_iterator it = wlBodyHash.find(key);
        if (it != wlBodyHash.end()) {
            wlRule = it->second;
            return true;
        }
    }
    else if (zone == HEADERS) {
        unordered_map<string, whitelist_rule_t>::const_iterator it = wlHeadersHash.find(key);
        if (it != wlHeadersHash.end()) {
            wlRule = it->second;
            return true;
        }
    }
    else if (zone == URL) {
        unordered_map<string, whitelist_rule_t>::const_iterator it = wlUrlHash.find(key);
        if (it != wlUrlHash.end()) {
            wlRule = it->second;
            return true;
        }
    }
    else if (zone == ARGS) {
        unordered_map<string, whitelist_rule_t>::const_iterator it = wlArgsHash.find(key);
        if (it != wlArgsHash.end()) {
            wlRule = it->second;
            return true;
        }
    }
    return false;
}