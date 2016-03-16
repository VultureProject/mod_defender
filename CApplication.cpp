#include "CApplication.hpp"
<<<<<<< HEAD
=======
#include <apr_strings.h>
#include <util_script.h>
#include <iomanip>
#include "libinjection/libinjection_sqli.h"
#include "libinjection/libinjection.h"
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> 5eee329... naxsi core rules parser
=======
#include "mod_defender.hpp"
<<<<<<< HEAD
>>>>>>> fd0f819... scoring system
=======
#include "NxParser.h"
>>>>>>> 40a8641... enhanced conf parsing

int CApplication::RunHandler() {
    int nReturnVal = DECLINED;
=======
>>>>>>> 71479aa... added url zone checking

<<<<<<< HEAD
<<<<<<< HEAD
    if (m_pRequestRec->handler != NULL && strcmp(m_pRequestRec->handler, "defender") == 0) {
        ap_rputs("Hello World from DEFENDER", m_pRequestRec);
        nReturnVal = OK;
    }
=======
CApplication::CApplication(request_rec* rec, apr_file_t *errorlog_fd, vector<nxrule_t>& rules) {
=======
=======
#include "NxParser.h"
#include "mod_defender.hpp"

<<<<<<< HEAD
>>>>>>> 10377d6... negative keyword support in MainRule
CApplication::CApplication(request_rec* rec, server_config_t* scfg) {
>>>>>>> fd0f819... scoring system
=======
CApplication::CApplication(request_rec* rec, server_config_t* scfg) : parser(scfg->parser) {
>>>>>>> 05833d4... whitelist check
    r = rec;
    this->scfg = scfg;
    pool = r->pool;
    this->checkRules = scfg->parser.checkRules;

    apr_table_do(storeTable, &headers, r->headers_in, NULL); // Store every HTTP header received

    /* Retrieve GET parameters */
    apr_table_t *GET = NULL;
    ap_args_to_table(r, &GET);
    apr_table_do(storeTable, &args, GET, NULL);

    readPost(); // Store body form data
}

/*
 * Retrieve variables from POST form data
 */
void CApplication::readPost() {
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
        body.emplace_back(apr_pstrdup(pool, formPair->name), buffer);
        i++;
    }
//    std::reverse(body.begin(), body.end());
}

/*
 * Callback function to store each key and value of
 * an apr_table_t into a vector
 */
int CApplication::storeTable(void *pVoid, const char *key, const char *value) {
    vector<pair<const char *, const char *>>* kvVector = static_cast<vector<pair<const char *, const char *>>*>(pVoid);
    kvVector->push_back(pair<const char *, const char *>(key, value));
    return 1; // Zero would stop iterating; any other return value continues
}

string CApplication::formatMatch(const http_rule_t &rule, enum DUMMY_MATCH_ZONE zone, const char* varName) {
    stringstream ss;
    if (rulesMatchedCount > 0)
        ss << "&";

    ss << "zone" << rulesMatchedCount << "=" << dummy_match_zones[zone] << "&";
    ss << "id" << rulesMatchedCount << "=" << rule.id << "&";
    ss << "var_name" << rulesMatchedCount << "=" << varName;

    return ss.str();
}

void CApplication::applyCheckRuleAction(const rule_action_t& action) {
    if (action == BLOCK)
        block = true;
    else if (action == DROP)
        drop = true;
    else if (action == ALLOW)
        allow = true;
    else if (action == LOG)
        log = true;
}

void CApplication::applyCheckRule(const http_rule_t &rule, int matchCount) {
    for (const pair<const char*, int> &tagScore : rule.scores) {
        bool matched = false;
        int& score = matchScores[tagScore.first];
        score += tagScore.second * matchCount;
        check_rule_t& checkRule = checkRules[tagScore.first];
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

// Nx mainRules check
void CApplication::checkVar(enum DUMMY_MATCH_ZONE zone, const char *varName, const char *value, const http_rule_t &rule) {
    cerr << "→ Checking " << varName << "=" << value << " in " << dummy_match_zones[zone] << " with rule #" << rule.id << " ";
    if (!rule.br.rxMz)
        cerr << "pattern: " << rule.br.matchPaternStr << endl;
    else
        cerr << "<regex>" << endl;

    string name = string(varName);
    if (parser.isRuleWhitelisted(r->parsed_uri.path, rule, name, zone, rule.br.targetName)) {
        cerr << "✓ Rule Whitelisted" << endl;
        return;
    }

    string matches;
    int matchCount = 0;
    if (rule.br.rxMz) {
        string valueStr = string(value);
        long rxMatchCount = distance(sregex_iterator(valueStr.begin(), valueStr.end(), rule.br.matchPaternRx), sregex_iterator());
        if (!rule.br.negative)
            matchCount += rxMatchCount;
        if (rule.br.negative && rxMatchCount == 0)
            matchCount++;
    }
    else {
        char* p = apr_pstrdup(pool, value);
        size_t len = strlen(rule.br.matchPaternStr);
        while ((p = strstr(p, rule.br.matchPaternStr)) != NULL && value != p) {
            matchCount++;
            p += len;
        }
    }

    if (matchCount > 0) {
        matches += formatMatch(rule, zone, varName);
        applyCheckRule(rule, matchCount);
        rulesMatchedCount++;
    }

    matchVars << matches;

//    struct libinjection_sqli_state state;
//    size_t slen = strlen(value);
//    libinjection_sqli_init(&state, value, slen, FLAG_NONE);
//
//    if (libinjection_is_sqli(&state)) {
//        http_rule_t rule;
//        rule.id = 17;
//        rule.scores.emplace_back(apr_pstrdup(pool, "$SQL"), 8);
//        formatMatch(rule, zone, varName);
//    }
//
//    if (libinjection_xss(value, slen)) {
//        http_rule_t rule;
//        rule.id = 18;
//        rule.scores.emplace_back(apr_pstrdup(pool, "$XSS"), 8);
//        formatMatch(rule, zone, varName);
//    }
}

void CApplication::checkVector(enum DUMMY_MATCH_ZONE zone, vector<pair<const char *, const char *>> &v, const http_rule_t &rule) {
    for (const pair<const char *, const char *>& pair : v)
        checkVar(zone, pair.first, pair.second, rule);
}

int CApplication::runHandler() {
    int returnVal = DECLINED;

//    for (const http_rule_t &rule : mainRules) {
//        if (rule.br.bodyMz) {
//            checkVector("BODY", body, rule);
//        }
////        if (rule.headersMz) {
////            checkVector("HEADERS", headers, rule);
////        }
//        if (rule.br.urlMz) {
//            checkVar("URL", "", r->parsed_uri.path, rule);
//        }
//        if (rule.br.argsMz) {
//            checkVector("ARGS", args, rule);
//        }
//    }
    for (const http_rule_t &rule : parser.getRules) {
        checkVector(ARGS, args, rule);
    }
    for (const http_rule_t &rule : parser.bodyRules) {
        checkVector(BODY, body, rule);
    }

//    if ((!strcmp(r->method, "POST") ||
//            !strcmp(r->method, "PUT")) &&
//            ) {
//
//    }

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

    cerr << "mod_defender: " << rulesMatchedCount << " match(es)" << endl;
    cerr << flush;
>>>>>>> 5eee329... naxsi core rules parser

    return nReturnVal;
}