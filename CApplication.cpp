#include "CApplication.hpp"
<<<<<<< HEAD
=======
#include <apr_strings.h>
#include <util_script.h>
#include <iomanip>
#include "libinjection/libinjection_sqli.h"
#include "libinjection/libinjection.h"
<<<<<<< HEAD
>>>>>>> 5eee329... naxsi core rules parser
=======
#include "mod_defender.hpp"
>>>>>>> fd0f819... scoring system

int CApplication::RunHandler() {
    int nReturnVal = DECLINED;

<<<<<<< HEAD
<<<<<<< HEAD
    if (m_pRequestRec->handler != NULL && strcmp(m_pRequestRec->handler, "defender") == 0) {
        ap_rputs("Hello World from DEFENDER", m_pRequestRec);
        nReturnVal = OK;
    }
=======
CApplication::CApplication(request_rec* rec, apr_file_t *errorlog_fd, vector<nxrule_t>& rules) {
=======
CApplication::CApplication(request_rec* rec, server_config_t* scfg) {
>>>>>>> fd0f819... scoring system
    r = rec;
    this->scfg = scfg;
    pool = r->pool;
    this->rules = scfg->rules;

    apr_table_do(storeHeaders, &headers, r->headers_in, NULL); // Store every HTTP header received

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

int CApplication::storeHeaders(void *pVoid, const char *key, const char *value) {
    vector<pair<const char *, const char *>>* kvVector = static_cast<vector<pair<const char *, const char *>>*>(pVoid);
    if (strcmp(key, "cookie") == 0)
        kvVector->push_back(pair<const char *, const char *>(key, value));
    return 1; // Zero would stop iterating; any other return value continues
}

string CApplication::formatMatch(const nxrule_t &rule, string zone, string varName) {
    stringstream ss;
    if (matchCount > 0)
        ss << "&";

    ss << "zone" << matchCount << "=" << zone << "&";
    ss << "id" << matchCount << "=" << rule.id << "&";
    ss << "var_name" << matchCount << "=" << varName;

    return ss.str();
}

void CApplication::checkVar(const char *varName, const char *value, const char *zone) {
    // Nx rules check
    string matches;
    for (const nxrule_t &rule : rules) {
        bool matched;
        if (rule.IsMatchPaternRx)
            matched = regex_match(value, rule.matchPaternRx);
        else
            matched = (strstr(value, rule.matchPaternStr) != nullptr);
        if (matched) {
            matches += formatMatch(rule, zone, varName);

            for (int i = 0; i < rule.scores.size(); i++)
                matchScores[rule.scores[i].first] += rule.scores[i].second;

            matchCount++;
        }
    }

    matchVars << matches;

    struct libinjection_sqli_state state;
    size_t slen = strlen(value);
    libinjection_sqli_init(&state, value, slen, FLAG_NONE);

    if (libinjection_is_sqli(&state)) {
        nxrule_t rule;
        rule.id = 17;
        rule.scores.emplace_back(apr_pstrdup(pool, "$SQL"), 8);
        formatMatch(rule, zone, varName);
    }

    if (libinjection_xss(value, slen)) {
        nxrule_t rule;
        rule.id = 18;
        rule.scores.emplace_back(apr_pstrdup(pool, "$XSS"), 8);
        formatMatch(rule, zone, varName);
    }
}

void CApplication::checkVector(const char *zone, vector<pair<const char *, const char *>> &v) {
    for (int i = 0; i < v.size(); i++) {
        checkVar(v[i].first, v[i].second, zone);
    }
}

int CApplication::runHandler() {
    int returnVal = DECLINED;

    // To check if mod_defender is activated
    if (r->handler != NULL && strcmp(r->handler, "defender") == 0) {
        ap_rputs("<!DOCTYPE html>\n<html><head><title>mod_defender config</title></head>"
                         "<body>mod_defender <span style='color:green;'>enabled</span></body></html>", r);
        returnVal = OK;
    }

    checkVector("$HEADERS_VAR:Cookie", headers);
    checkVector("ARGS", args);
    checkVector("BODY", body);
    
    if (matchCount > 0) {
        std::time_t tt = system_clock::to_time_t (system_clock::now());
        std::tm * ptm = std::localtime(&tt);
        errlog << std::put_time(ptm, "%Y/%m/%d %T") << " ";
        errlog << "[error] ";
        errlog << "NAXSI_FMT: ";

        errlog << "ip=" << r->useragent_ip << "&";
        errlog << "server=" << r->hostname << "&";
        errlog << "uri=" << r->parsed_uri.path << "&";

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

    cerr << "mod_defender: " << matchCount << " match(es)" << endl;

    cerr << flush;
>>>>>>> 5eee329... naxsi core rules parser

    return nReturnVal;
}