#include "RuntimeScanner.hpp"
#include <apr_strings.h>
#include <util_script.h>
#include "libinjection/libinjection_sqli.h"
#include "libinjection/libinjection.h"
#include "mod_defender.hpp"
#include "RuleParser.h"

RuntimeScanner::RuntimeScanner(request_rec* rec, server_config_t* scfg, RuleParser& parser) : parser(parser) {
    r = rec;
    this->scfg = scfg;
    pool = r->pool;

    apr_table_do(storeTable, &headers, r->headers_in, NULL); // Store every HTTP header received

    /* Retrieve GET parameters */
    apr_table_t *GET = NULL;
    ap_args_to_table(r, &GET);
    apr_table_do(storeTable, &args, GET, NULL);

    readPost(); // Store body form data

    uri = string(r->parsed_uri.path);
    std::transform(uri.begin(), uri.end(), uri.begin(), ::tolower);
}

/*
 * Retrieve variables from POST form data
 */
void RuntimeScanner::readPost() {
    apr_array_header_t *POST = NULL;
    int res = ap_parse_form_data(r, NULL, &POST, -1, HUGE_STRING_LEN);
    if (res != OK || !POST) return; /* Return NULL if we failed or if there is no POST data */
    int i = 0;
    while (POST && !apr_is_empty_array(POST)) {
        ap_form_pair_t *formPair = (ap_form_pair_t *) apr_array_pop(POST);
        apr_off_t len;
        apr_brigade_length(formPair->value, 1, &len);
        apr_size_t size = (apr_size_t) len;
        char *buffer = (char *) apr_palloc(pool, size + 1);
        apr_brigade_flatten(formPair->value, buffer, &size);
        buffer[len] = 0;
        string key = string(formPair->name);
        string value = string(buffer);
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        std::transform(value.begin(), value.end(), value.begin(), ::tolower);
        body.emplace_back(key, value);
        i++;
    }
}

/*
 * Callback function to store each key and value of
 * an apr_table_t into a vector
 */
int RuntimeScanner::storeTable(void *pVoid, const char *key, const char *value) {
    vector<pair<const string, const string>>* kvVector = static_cast<vector<pair<const string, const string>>*>(pVoid);
    string keyLower = string(key);
    string valueLower = string(value);
    std::transform(keyLower.begin(), keyLower.end(), keyLower.begin(), ::tolower);
    std::transform(valueLower.begin(), valueLower.end(), valueLower.begin(), ::tolower);
    kvVector->emplace_back(keyLower, valueLower);
    return 1; // Zero would stop iterating; any other return value continues
}

string RuntimeScanner::formatMatch(const http_rule_t &rule, int nbMatch, enum MATCH_ZONE zone, const string& name, const string& value, bool targetName) {
    stringstream ss;
    if (rulesMatchedCount > 0)
        ss << "&";

    ss << "zone" << rulesMatchedCount << "=" << match_zones[zone] << "&";
    ss << "id" << rulesMatchedCount << "=" << rule.id << "&";
    ss << "var_name" << rulesMatchedCount << "=" << name;

    cerr << Util::formatLog(DEFLOG_ERROR, r->useragent_ip);
    cerr << KRED "⚠ Rule #" << rule.id << " ";
    cerr << "(" << rule.logMsg << ") ";
    cerr << "matched " << nbMatch << " times ";
    if (targetName)
        cerr << "in name ";
    cerr << "at " << match_zones[zone] << " " << name << ":" << value << KNRM << endl;

    return ss.str();
}

void RuntimeScanner::applyCheckRuleAction(const rule_action_t& action) {
    if (action == BLOCK)
        block = true;
    else if (action == DROP)
        drop = true;
    else if (action == ALLOW)
        allow = true;
    else if (action == LOG)
        log = true;
}

void RuntimeScanner::applyCheckRule(const http_rule_t &rule, int nbMatch, const string& name, const string& value, enum MATCH_ZONE zone, bool targetName) {
    if (parser.isRuleWhitelisted(rule, uri, name, zone, targetName)) {
        cerr << Util::formatLog(DEFLOG_WARN, r->useragent_ip);
        cerr << KGRN "✓ Rule #" << rule.id << " ";
        cerr << "(" << rule.logMsg << ") ";
        cerr << "whitelisted ";
        if (targetName)
            cerr << "in name ";
        cerr << "at " << match_zones[zone] << " " << name << ":" << value << KNRM << endl;
        return;
    }
    // rule negative case
    if (nbMatch == 0)
        nbMatch = 1;
    for (const pair<string, int> &tagScore : rule.scores) {
        bool matched = false;
        int& score = matchScores[tagScore.first];
        score += tagScore.second * nbMatch;
        check_rule_t& checkRule = parser.checkRules[tagScore.first];
        if (checkRule.comparator == SUP_OR_EQUAL)
            matched = (score >= checkRule.limit);
        else if (checkRule.comparator == SUP)
            matched = (score > checkRule.limit);
        else if (checkRule.comparator <= INF_OR_EQUAL)
            matched = (score <= checkRule.limit);
        else if (checkRule.comparator < INF)
            matched = (score < checkRule.limit);
        if (matched)
            applyCheckRuleAction(checkRule.action);
    }

    if (scfg->learning)
        matchVars << formatMatch(rule, nbMatch, zone, name, value, targetName);
    rulesMatchedCount++;
}

bool RuntimeScanner::processRuleBuffer(const string &str, const http_rule_t &rl, int &nbMatch) {
    if (!rl.br || str.empty())
        return false;
    DEBUG_RUNTIME_PR("[" << str);
    nbMatch = 0;
    if (rl.br->rx) {
        DEBUG_RUNTIME_PR(" ? <regex>] ");
        nbMatch = (int) distance(sregex_iterator(str.begin(), str.end(), *rl.br->rx), sregex_iterator());
        if (nbMatch > 0) {
            DEBUG_RUNTIME_PR("matched " << endl);
            return !rl.br->negative;
        }
        else {
            return rl.br->negative;
        }
    }
    else if (!rl.br->str.empty()) {
        DEBUG_RUNTIME_PR(" ? " << rl.br->str << "] ");
        nbMatch = Util::countSubstring(str, rl.br->str);
        if (nbMatch > 0) {
            DEBUG_RUNTIME_PR("matched " << endl);
            return !rl.br->negative;
        }
        else {
            return rl.br->negative;
        }
    }
    return false;
}

void RuntimeScanner::basestrRuleset(enum MATCH_ZONE zone, const string &name, const string &value,
                                    const vector<http_rule_t*> &rules) {
    if (scfg->libinjection)
        checkLibInjection(zone, name, value);

    int nbMatch = 0;
    for (int i = 0; i < rules.size() && ((!block || scfg->learning) && !drop); i++) {
        const http_rule_t& rule = *rules[i];
        DEBUG_RUNTIME_BRS("Checking in " << match_zones[zone] << " rule #" << rule.id << " ");

        /* does the rule have a custom location ? custom location means checking only on a specific argument */
        if (!name.empty() && rule.br->customLocation) {
            DEBUG_RUNTIME_BRS("loc ");
            /* for each custom location */
            for (const custom_rule_location_t &loc : rule.br->customLocations) {
                /* check if the custom location zone match with the current zone (enhancement) */
                if (!((loc.bodyVar && zone == BODY) || (loc.argsVar && zone == ARGS) ||
                        (loc.headersVar && zone == HEADERS) || (loc.specificUrl && zone == URL))) {
                    DEBUG_RUNTIME_BRS("Custom location zone mismatch ");
                    continue;
                }
                /* if the name are the same, check */
                if (!loc.target.empty() && name == loc.target) {
                    DEBUG_RUNTIME_BRS(loc.target << " ");
                    /* match rule against var content, */
                    if (processRuleBuffer(value, rule, nbMatch)) {
                        applyCheckRule(rule, nbMatch, name, value, zone, false);
                    }

                    if (!rule.br->negative) {
                        /* match rule against var name, */
                        if (processRuleBuffer(name, rule, nbMatch)) {
                            /* if our rule matched, apply effects (score etc.) */
                            applyCheckRule(rule, nbMatch, name, value, zone, true);
                        }
                    }
                }
            }
        }

        /*
        ** check against the rule if the current zone is matching
        ** the zone the rule is meant to be check against
        */
        if ((zone == HEADERS && rule.br->headersMz) || (zone == URL && rule.br->urlMz) ||
             (zone == ARGS && rule.br->argsMz) || (zone == BODY && rule.br->bodyMz) ||
                    (zone == FILE_EXT && rule.br->fileExtMz)) {
            DEBUG_RUNTIME_BRS("zone ");
            /* check the rule against the value*/
            if (processRuleBuffer(value, rule, nbMatch)) {
                /* if our rule matched, apply effects (score etc.) */
                applyCheckRule(rule, nbMatch, name, value, zone, false);
            }

            if (!rule.br->negative) {
                /* check the rule against the name */
                if (processRuleBuffer(name, rule, nbMatch)) {
                    /* if our rule matched, apply effects (score etc.) */
                    applyCheckRule(rule, nbMatch, name, value, zone, true);
                }
            }
        }
        DEBUG_RUNTIME_BRS("done" << endl);
    }
}

void RuntimeScanner::checkLibInjection(enum MATCH_ZONE zone, const string& name, const string& value) {
    if (value.empty() && name.empty())
        return;
    char* valuecstr = NULL;
    size_t valuelen = 0;
    char* namecstr = NULL;
    size_t namelen = 0;
    if (!value.empty()) {
        valuecstr = apr_pstrdup(pool, value.c_str());
        valuelen = strlen(value.c_str());
    }
    if (!name.empty()) {
        namecstr = apr_pstrdup(pool, value.c_str());
        namelen = strlen(value.c_str());
    }


    if (scfg->libinjection_sql) {
        struct libinjection_sqli_state state;

        if (valuecstr) {
            libinjection_sqli_init(&state, valuecstr, valuelen, FLAG_NONE);

            if (libinjection_is_sqli(&state)) {
                http_rule_t& libsqlirule = parser.internalRules[17];
                libsqlirule.logMsg = state.fingerprint;
                applyCheckRule(libsqlirule, 1, name, value, zone, false);
            }
        }

        if (namecstr) {
            libinjection_sqli_init(&state, namecstr, namelen, FLAG_NONE);

            if (libinjection_is_sqli(&state)) {
                http_rule_t& libsqlirule = parser.internalRules[17];
                libsqlirule.logMsg = state.fingerprint;
                applyCheckRule(libsqlirule, 1, name, value, zone, true);
            }
        }
    }

    if (scfg->libinjection_xss) {
        if (valuecstr && libinjection_xss(valuecstr, valuelen)) {
            http_rule_t& libxssrule = parser.internalRules[18];
            applyCheckRule(libxssrule, 1, name, value, zone, false);
        }

        if (namecstr && libinjection_xss(namecstr, namelen)) {
            http_rule_t& libxssrule = parser.internalRules[18];
            applyCheckRule(libxssrule, 1, name, value, zone, true);
        }
    }
}

int RuntimeScanner::runHandler() {
    int returnVal = DECLINED;

    for (const pair<const string, const string>& pair : headers) {
        basestrRuleset(HEADERS, pair.first, pair.second, parser.headerRules);
    }
    for (const pair<const string, const string>& pair : args) {
        basestrRuleset(ARGS, pair.first, pair.second, parser.getRules);
    }
    if (r->method_number == M_POST || r->method_number == M_PUT) {
        for (const pair<const string, const string> &pair : body) {
            basestrRuleset(BODY, pair.first, pair.second, parser.bodyRules);
        }
    }
    basestrRuleset(URL, string(), uri, parser.genericRules);

    if (scfg->learning && rulesMatchedCount > 0) {
        std::time_t tt = system_clock::to_time_t (system_clock::now());
        std::tm * ptm = std::localtime(&tt);
        stringstream errlog;
        errlog << std::put_time(ptm, "%Y/%m/%d %T") << " ";
        errlog << "[error] ";
        errlog << "NAXSI_FMT: ";

        errlog << "ip=" << r->useragent_ip << "&";
        errlog << "server=" << r->hostname << "&";
        errlog << "uri=" << r->parsed_uri.path << "&";

        errlog << "block=" << block << "&";

        int i = 0;
        for (const auto& match : matchScores) {
            errlog << "cscore" << i << "=" << match.first << "&";
            errlog << "score" << i << "=" << match.second << "&";
            i++;
        }

        errlog << matchVars.str();

        errlog << ", ";

        errlog << "client: " << r->useragent_ip << ", ";
        errlog << "server: " << r->server->server_hostname << ", ";
        errlog << "request: \"" << r->method << " " << r->unparsed_uri << " " << r->protocol << "\", ";
        errlog << "host: \"" << r->hostname << "\"";

        errlog << endl;

        const string tmp = errlog.str();
        const char* cstr = tmp.c_str();
        apr_size_t cstrlen = strlen(cstr);
        apr_file_write(scfg->errorlog_fd, cstr, &cstrlen);
    }

    if (block)
        returnVal = HTTP_FORBIDDEN;

    return returnVal;
}