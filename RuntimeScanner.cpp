#include "RuntimeScanner.hpp"
#include <apr_strings.h>
#include <util_script.h>
#include "libinjection/libinjection_sqli.h"
#include "libinjection/libinjection.h"
#include "mod_defender.hpp"

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

string RuntimeScanner::formatMatch(const http_rule_t &rule, enum DUMMY_MATCH_ZONE zone, const string& varName) {
    stringstream ss;
    if (rulesMatchedCount > 0)
        ss << "&";

    ss << "zone" << rulesMatchedCount << "=" << dummy_match_zones[zone] << "&";
    ss << "id" << rulesMatchedCount << "=" << rule.id << "&";
    ss << "var_name" << rulesMatchedCount << "=" << varName;

    cerr << Util::formatLog(DEFLOG_ERROR, r->useragent_ip);
    cerr << KRED "⚠ Rule #" << rule.id << " ";
    if (!rule.br.rxMz)
        cerr << "(" << rule.br.matchPaternStr << ") ";
    else
        cerr << "(<regex>) ";
    cerr << "matched at ";
    cerr << dummy_match_zones[zone] << ":" << varName << KNRM << endl;

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

void RuntimeScanner::applyCheckRule(const http_rule_t &rule, int matchCount) {
    for (const pair<const char*, int> &tagScore : rule.scores) {
        bool matched = false;
        int& score = matchScores[tagScore.first];
        score += tagScore.second * matchCount;
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
}

bool RuntimeScanner::isRuleEligible(enum DUMMY_MATCH_ZONE zone, const http_rule_t &rule, const string& varName) {
    bool eligible = false;
    eligible = ((zone == HEADERS && rule.br.headersMz) || (zone == URL && rule.br.specificUrlMz) ||
                (zone == ARGS && rule.br.argsMz) || (zone == BODY && rule.br.bodyMz));

    if (!eligible) {
        if (rule.br.customLocation) {
            if (zone == HEADERS && rule.br.headersVarMz) {
                for (const custom_rule_location_t &custloc : rule.br.customLocations) {
                    if (rule.br.rxMz)
                        eligible = regex_match(varName, custloc.targetRx);
                    else
                        eligible = (varName == custloc.target);
                }
            }
            else if (zone == URL && rule.br.specificUrlMz) {
                for (const custom_rule_location_t &custloc : rule.br.customLocations) {
                    if (rule.br.rxMz)
                        eligible = regex_match(varName, custloc.targetRx);
                    else
                        eligible = (varName == custloc.target);
                }
            }
            else if (zone == ARGS && rule.br.argsVarMz) {
                for (const custom_rule_location_t &custloc : rule.br.customLocations) {
                    if (rule.br.rxMz)
                        eligible = regex_match(varName, custloc.targetRx);
                    else
                        eligible = (varName == custloc.target);
                }
            }
            else if (zone == BODY && rule.br.bodyVarMz) {
                for (const custom_rule_location_t &custloc : rule.br.customLocations) {
                    if (rule.br.rxMz)
                        eligible = regex_match(varName, custloc.targetRx);
                    else
                        eligible = (varName == custloc.target);
                }
            }
        }
    }

    return eligible;
}

/*
 * MainRules check
 */
void RuntimeScanner::checkVar(enum DUMMY_MATCH_ZONE zone, const string& varName, const string& value, const http_rule_t &rule) {
//    cerr << "→ Checking " << varName << "=" << value << " in " << dummy_match_zones[zone] << " with rule #" << rule.id << " ";
//    if (!rule.br.rxMz)
//        cerr << "pattern: " << rule.br.matchPaternStr << endl;
//    else
//        cerr << "<regex>" << endl;

    if (!isRuleEligible(zone, rule, varName)) {
//        cerr << "Rule #" << rule.id << not eligible" << endl;
        return;
    }

    if (parser.isRuleWhitelisted(uri, rule, varName, zone, rule.br.targetName)) {
        cerr << KGRN "✓ Rule #" << rule.id << " whitelisted" KNRM << endl;
        return;
    }

    int tmpMatchCount = 0;
    if (rule.br.rxMz) {
        tmpMatchCount += distance(sregex_iterator(value.begin(), value.end(), rule.br.matchPaternRx), sregex_iterator());
    }
    else {
        tmpMatchCount += Util::countSubstring(value, rule.br.matchPaternStr);
    }

    /* If rule negative */
    int matchCount = 0;
    if (!rule.br.negative)
        matchCount += tmpMatchCount;
    if (rule.br.negative && tmpMatchCount == 0)
        matchCount++;

    if (matchCount > 0) {
        matchVars << formatMatch(rule, zone, varName);
        applyCheckRule(rule, matchCount);
        rulesMatchedCount++;
    }
}

void RuntimeScanner::checkRulesOnVars(enum DUMMY_MATCH_ZONE zone, vector<pair<const string, const string>> &v,
                                    const http_rule_t &rule) {
    for (const pair<const string, const string>& pair : v) {
        checkVar(zone, pair.first, pair.second, rule);
    }
}

void RuntimeScanner::checkLibInjectionOnVar(enum DUMMY_MATCH_ZONE zone, vector<pair<const string, const string>> &v) {
    for (const pair<const string, const string>& pair : v) {
        checkLibInjection(zone, pair.first, pair.second);
    }
}

void RuntimeScanner::checkLibInjection(enum DUMMY_MATCH_ZONE zone, const string& varName, const string& value) {
    const char* valuecstr = apr_pstrdup(pool, value.c_str());
    size_t slen = strlen(value.c_str());

    if (scfg->libinjection_sql) {
        struct libinjection_sqli_state state;
        libinjection_sqli_init(&state, valuecstr, slen, FLAG_NONE);

        if (libinjection_is_sqli(&state)) {
            http_rule_t& libsqlirule = parser.internalRules[17];
            libsqlirule.br.matchPaternStr = state.fingerprint;
            matchVars << formatMatch(libsqlirule, zone, varName);
            applyCheckRule(libsqlirule, 1);
            rulesMatchedCount++;
        }
    }

    if (scfg->libinjection_xss) {
        if (libinjection_xss(valuecstr, slen)) {
            http_rule_t& libxssrule = parser.internalRules[18];
            matchVars << formatMatch(libxssrule, zone, varName);
            applyCheckRule(libxssrule, 1);
            rulesMatchedCount++;
        }
    }
}

int RuntimeScanner::runHandler() {
    int returnVal = DECLINED;

    for (const http_rule_t &rule : parser.getRules) {
        checkRulesOnVars(ARGS, args, rule);
    }
    if (scfg->libinjection)
        checkLibInjectionOnVar(ARGS, args);
    if ((strcmp(r->method, "POST") == 0 || strcmp(r->method, "PUT") == 0)) {
        for (const http_rule_t &rule : parser.bodyRules) {
            checkRulesOnVars(BODY, body, rule);
        }
        if (scfg->libinjection)
            checkLibInjectionOnVar(BODY, body);
    }
    for (const http_rule_t &rule : parser.headerRules) {
        checkRulesOnVars(HEADERS, headers, rule);
    }
    if (scfg->libinjection)
        checkLibInjectionOnVar(HEADERS, headers);
    string empty = "";
    for (const http_rule_t &rule : parser.genericRules) {
        checkVar(URL, empty, uri, rule);
    }
    if (scfg->libinjection)
        checkLibInjection(URL, empty, uri);

    if (rulesMatchedCount > 0) {
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

        if (block)
            returnVal = HTTP_FORBIDDEN;
    }

    cerr << flush;

    return returnVal;
}