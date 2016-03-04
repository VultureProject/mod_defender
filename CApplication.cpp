#include "CApplication.hpp"
<<<<<<< HEAD
=======
#include <apr_strings.h>
#include <util_script.h>
#include <iomanip>
#include <http_protocol.h>
#include "libinjection/libinjection_sqli.h"
#include "libinjection/libinjection.h"
>>>>>>> 5eee329... naxsi core rules parser

int CApplication::RunHandler() {
    int nReturnVal = DECLINED;

<<<<<<< HEAD
    if (m_pRequestRec->handler != NULL && strcmp(m_pRequestRec->handler, "defender") == 0) {
        ap_rputs("Hello World from DEFENDER", m_pRequestRec);
        nReturnVal = OK;
    }
=======
CApplication::CApplication(request_rec* rec, apr_file_t *errorlog_fd, vector<nxrule_t>& rules) {
    r = rec;
    this->errorlog_fd = errorlog_fd;
    pool = r->pool;
    this->rules = rules;

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
        body.push_back(pair<const char *, const char *>(apr_pstrdup(pool, formPair->name), buffer));
        i++;
    }
    std::reverse(body.begin(), body.end());
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
    if (strcmp(key, "User-Agent") == 0 || strcmp(key, "cookie") == 0)
        kvVector->push_back(pair<const char *, const char *>(key, value));
    return 1; // Zero would stop iterating; any other return value continues
}

void CApplication::formatAttack(const nxrule_t &rule, string zone, string varname) {
    if (attack > 0)
        attacks << "&";
    for (int i = 0; i < rule.scores.size(); i++) {
        attacks << "cscore" << i << "=" << rule.scores[i].first << "&";
        attacks << "score" << i << "=" << rule.scores[i].second << "&";
    }
    attacks << "zone" << attack << "=" << zone << "&";
    attacks << "id" << attack << "=" << rule.id << "&";
    attacks << "var_name" << attack << "=" << varname;

    attack++;
}

void CApplication::checkAttack(const char *varName, const char *value, const char *zone) {
    // Nx rules check
    for (const nxrule_t &rule : rules) {
        bool matched = false;
        if (rule.IsMatchPaternRx) {
            matched = regex_match(value, rule.matchPaternRx);
        } else {
            matched = (strstr(value, rule.matchPaternStr) != NULL);
        }
        if (matched) {
            formatAttack(rule, zone, varName);
        }
    }

//    struct libinjection_sqli_state state;
//    size_t slen = strlen(value);
//    libinjection_sqli_init(&state, value, slen, FLAG_NONE);
//
//    if (libinjection_is_sqli(&state)) {
//        formatAttack("$SQL", 8, zone, 17, varName);
//    }
//
//    if (libinjection_xss(value, slen)) {
//        formatAttack("$XSS", 8, zone, 18, varName);
//    }
}

void CApplication::checkVector(const char *zone, vector<pair<const char *, const char *>> &v) {
    for (int i = 0; i < v.size(); i++) {
        checkAttack(v[i].first, v[i].second, zone);
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

//    checkVector("HEADERS", headers);
    checkVector("ARGS", args);
    checkVector("BODY", body);
    
    if (attack > 0) {
        std::time_t tt = system_clock::to_time_t (system_clock::now());
        std::tm * ptm = std::localtime(&tt);
        errlog << std::put_time(ptm, "%Y/%m/%d %T") << " ";
        errlog << "[error] ";
        errlog << "NAXSI_FMT: ";

        errlog << "ip=" << r->useragent_ip << "&";
        errlog << "server=" << r->hostname << "&";
        errlog << "uri=" << r->parsed_uri.path << "&";

        errlog << attacks.str();

        errlog << ", ";

        errlog << "client: " << r->useragent_ip << ", ";
        errlog << "server: " << r->server->server_hostname << ", ";
        errlog << "request: \"" << r->method << " " << r->unparsed_uri << " " << r->protocol << "\", ";
        errlog << "host: \"" << r->hostname << "\"";

        errlog << endl;

        const string tmp = errlog.str();
        const char* cstr = tmp.c_str();
        apr_size_t cstrlen = strlen(cstr);
        apr_file_write(errorlog_fd, cstr, &cstrlen);
    }

    cerr << flush;
>>>>>>> 5eee329... naxsi core rules parser

    return nReturnVal;
}