#include "RuntimeScanner.hpp"
#include <util_script.h>
#include "libinjection/libinjection_sqli.h"
#include "libinjection/libinjection.h"
#include "Util.h"

void RuntimeScanner::formatMatch(const http_rule_t &rule, unsigned long nbMatch, MATCH_ZONE zone, const string &name,
                                 const string &value, bool targetName) {
    if (!scfg->learning)
        return;

    stringstream ss;
    if (rulesMatchedCount > 0)
        ss << "&";

    ss << "zone" << rulesMatchedCount << "=" << match_zones[zone] << "&";
    ss << "id" << rulesMatchedCount << "=" << rule.id << "&";
    ss << "var_name" << rulesMatchedCount << "=" << name;

    cerr << formatLog(DEFLOG_ERROR, r->useragent_ip);
    cerr << KRED "⚠ Rule #" << rule.id << " ";
    cerr << "(" << rule.logMsg << ") ";
    cerr << "matched " << nbMatch << " times ";
    if (targetName)
        cerr << "in name ";
    cerr << "at " << match_zones[zone] << " " << name << ":" << value << KNRM << endl;

    matchVars << ss.str();
}

void RuntimeScanner::applyCheckRuleAction(const rule_action_t &action) {
    if (action == BLOCK)
        block = true;
    else if (action == DROP)
        drop = true;
    else if (action == ALLOW)
        allow = true;
    else if (action == LOG)
        log = true;
}

void RuntimeScanner::applyCheckRule(const http_rule_t &rule, unsigned long nbMatch, const string &name,
                                    const string &value, MATCH_ZONE zone, bool targetName) {
    if (parser.isRuleWhitelisted(rule, uri, name, zone, targetName)) {
        cerr << formatLog(DEFLOG_WARN, r->useragent_ip);
        cerr << KGRN "✓ Rule #" << rule.id << " ";
        cerr << "(" << rule.logMsg << ") ";
        cerr << "whitelisted ";
        if (targetName)
            cerr << "in name ";
        cerr << "at " << match_zones[zone] << " " << name << ":" << value << KNRM << endl;
        return;
    }
    // negative rule case
    if (nbMatch == 0)
        nbMatch = 1;
    for (const pair<string, unsigned long> &tagScore : rule.scores) {
        bool matched = false;
        int &score = matchScores[tagScore.first];
        score += tagScore.second * nbMatch;
        check_rule_t &checkRule = parser.checkRules[tagScore.first];
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

    formatMatch(rule, nbMatch, zone, name, value, targetName);
    rulesMatchedCount++;
}

bool RuntimeScanner::processRuleBuffer(const string &str, const http_rule_t &rl, unsigned long &nbMatch) {
    if (!rl.br || str.empty())
        return false;
    DEBUG_RUNTIME_PR("[" << str);
    nbMatch = 0;
    if (rl.br->rx) {
        DEBUG_RUNTIME_PR(" ? <regex>] ");
        nbMatch = (unsigned long) distance(sregex_iterator(str.begin(), str.end(), *rl.br->rx), sregex_iterator());
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
//        nbMatch = countSubstring(str, rl.br->str);
//        nbMatch = countSubstring(str.c_str(), str.size(), rl.br->str.c_str(), rl.br->str.size());
        nbMatch = countSubstring(str.c_str(), rl.br->str.c_str(), rl.br->str.size());


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

void RuntimeScanner::basestrRuleset(MATCH_ZONE zone, const string &name, const string &value,
                                    const vector<http_rule_t *> &rules) {
    if (scfg->libinjection)
        checkLibInjection(zone, name, value);

    unsigned long nbMatch = 0;
    for (int i = 0; i < rules.size() && ((!block || scfg->learning) && !drop); i++) {
        const http_rule_t &rule = *rules[i];
        DEBUG_RUNTIME_BRS(match_zones[zone] << ":#" << rule.id << " ");

        /* does the rule have a custom location ? custom location means checking only on a specific argument */
        if (!name.empty() && rule.br->customLocation) {
            DEBUG_RUNTIME_BRS("loc ");
            /* for each custom location */
            for (const custom_rule_location_t &loc : rule.br->customLocations) {
                /* check if the custom location zone match with the current zone (enhancement) */
                if (!((loc.bodyVar && zone == BODY) || (loc.argsVar && zone == ARGS) ||
                      (loc.headersVar && zone == HEADERS) || (loc.specificUrl && zone == URL))) {
                    DEBUG_RUNTIME_BRS("loc-zone-mismatch ");
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

void RuntimeScanner::checkLibInjection(MATCH_ZONE zone, const string &name, const string &value) {
    if (value.empty() && name.empty())
        return;
    char *szValue = NULL;
    size_t valueLen = 0;
    char *szName = NULL;
    size_t nameLen = 0;
    if (!value.empty()) {
        szValue = strdup(value.c_str());
        valueLen = strlen(value.c_str());
    }
    if (!name.empty()) {
        szName = strdup(value.c_str());
        nameLen = strlen(value.c_str());
    }

    if (scfg->libinjection_sql) {
        struct libinjection_sqli_state state;

        if (szValue) {
            libinjection_sqli_init(&state, szValue, valueLen, FLAG_NONE);

            if (libinjection_is_sqli(&state)) {
                http_rule_t &sqliRule = parser.libsqliRule;
                sqliRule.logMsg = state.fingerprint;
                formatMatch(sqliRule, 1, zone, name, value, false);
            }
        }

        if (szName) {
            libinjection_sqli_init(&state, szName, nameLen, FLAG_NONE);

            if (libinjection_is_sqli(&state)) {
                http_rule_t &sqliRule = parser.libsqliRule;
                sqliRule.logMsg = state.fingerprint;
                formatMatch(sqliRule, 1, zone, name, value, true);
            }
        }
    }

    if (scfg->libinjection_xss) {
        if (szValue && libinjection_xss(szValue, valueLen)) {
            formatMatch(parser.libxssRule, 1, zone, name, value, false);
        }

        if (szName && libinjection_xss(szName, nameLen)) {
            formatMatch(parser.libxssRule, 1, zone, name, value, true);
        }
    }
}

bool RuntimeScanner::contentDispositionParser(unsigned char *str, unsigned char *line_end,
                                              unsigned char **fvarn_start, unsigned char **fvarn_end,
                                              unsigned char **ffilen_start, unsigned char **ffilen_end) {
    unsigned char *varn_start = NULL, *varn_end = NULL, *filen_start = NULL, *filen_end = NULL;
    /* we have two cases :
    ** ---- file upload
    ** Content-Disposition: form-data; name="somename"; filename="NetworkManager.conf"\r\n
    ** Content-Type: application/octet-stream\r\n\r\n
    ** <DATA>
    ** ---- normal post var
    ** Content-Disposition: form-data; name="lastname"\r\n\r\n
    ** <DATA>
    */

    while (str < line_end) {
        /* rfc allow spaces and tabs inbetween */
        while (str < line_end && *str && (*str == ' ' || *str == '\t'))
            str++;
        if (str < line_end && *str && *str == ';')
            str++;
        while (str < line_end && *str && (*str == ' ' || *str == '\t'))
            str++;

        if (str >= line_end || !*str)
            break;

        if (!strncmp((const char *) str, "name=\"", 6)) {
            /* we already successfully parsed a name, reject that. */
            if (varn_end || varn_start)
                return false;
            varn_end = varn_start = str + 6;
            do {
                varn_end = (unsigned char *) strchr((const char *) varn_end, '"');
                if (!varn_end || (*(varn_end - 1) != '\\'))
                    break;
                varn_end++;
            } while (varn_end && varn_end < line_end);
            if (!varn_end || !*varn_end)
                return false;
            str = varn_end;
            if (str < line_end + 1)
                str++;
            else
                return false;
            *fvarn_start = varn_start;
            *fvarn_end = varn_end;
        }
        else if (!strncmp((const char *) str, "filename=\"", 10)) {
            /* we already successfully parsed a filename, reject that. */
            if (filen_end || filen_start)
                return false;
            filen_end = filen_start = str + 10;
            do {
                filen_end = (unsigned char *) strchr((const char *) filen_end, '"');
                if (!filen_end) break;
                if (*(filen_end - 1) != '\\')
                    break;
                filen_end++;
            } while (filen_end && filen_end < line_end);
            if (!filen_end)
                return false;
            str = filen_end;
            if (str < line_end + 1)
                str++;
            else
                return false;
            *ffilen_end = filen_end;
            *ffilen_start = filen_start;
        }
        else if (str == line_end - 1)
            break;
        else {
            /* gargabe is present ?*/
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                         "extra data in content-disposition ? end:%s, str:%s, diff=%ld", line_end, str, line_end - str);
            return false;
        }
    }
    return !(filen_end > line_end || varn_end > line_end);
}

bool RuntimeScanner::parseFormDataBoundary(unsigned char **boundary, unsigned long *boundary_len) {
    unsigned char *h = (unsigned char *) &rawContentType[20];
    unsigned char *end = (unsigned char *) &rawContentType[rawContentType.length()];

    /* skip potential whitespace/tabs */
    while (h < end && *h && (*h == ' ' || *h == '\t'))
        h++;
    if (strncmp((const char *) h, "boundary=", 9))
        return false;
    h += 9;
    *boundary_len = end - h;
    *boundary = h;
    /* RFC 1867/1341 says 70 char max,
       I arbitrarily set min to 3 (yes) */
    return !(*boundary_len > 70 || *boundary_len < 3);
}

void RuntimeScanner::multipartParse(u_char *src, unsigned long len) {
    str_t final_var, final_data;
    u_char *boundary, *varn_start, *varn_end;
    u_char *filen_start, *filen_end;
    u_char *end, *line_end;
    unsigned long boundary_len, varn_len, varc_len, idx;
    int nullbytes;

    /*extract boundary*/
    if (!parseFormDataBoundary(&boundary, &boundary_len)) {
        if (boundary && boundary_len > 1)
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "XX-POST boundary : (%s) : %ld", (const char *) boundary,
                         boundary_len);
        formatMatch(parser.uncommonPostBoundary, 1, BODY, "multipart/form-data boundary error", string(), false);
        block = true;
        return;
    }

    /* fetch every line starting with boundary */
    idx = 0;
    while (idx < len) {
        /* if we've reached the last boundary '--' + boundary + '--' + '\r\n'$END */
        /* Authorize requests that don't have the leading \r\n */
        if (idx + boundary_len + 6 == len || idx + boundary_len + 4 == len) {
            if (strncmp((const char *) src + idx, "--", 2) ||
                strncmp((const char *) src + idx + 2, (const char *) boundary, boundary_len) ||
                strncmp((const char *) src + idx + boundary_len + 2, "--", 2)) {
                /* bad closing boundary ?*/
                formatMatch(parser.uncommonPostBoundary, 1, BODY, "multipart/form-data bad closing boundary",
                            (const char *) boundary, false);
                block = true;
                return;
            } else
                break;
        }

        /* --boundary\r\n : New var */
        if ((len - idx < 4 + boundary_len) || src[idx] != '-' || src[idx + 1] != '-' ||
            /* and if it's really followed by a boundary */
            strncmp((const char *) src + idx + 2, (const char *) boundary, boundary_len) ||
            /* and if it's not the last boundary of the buffer */
            idx + boundary_len + 2 + 2 >= len ||
            /* and if it's followed by \r\n */
            src[idx + boundary_len + 2] != '\r' || src[idx + boundary_len + 3] != '\n') {
            /* bad boundary */
            formatMatch(parser.uncommonPostBoundary, 1, BODY, "multipart/form-data bad boundary",
                        (const char *) boundary, false);
            block = true;
            return;
        }
        idx += boundary_len + 4;
        /* we have two cases :
        ** ---- file upload
        ** Content-Disposition: form-data; name="somename"; filename="NetworkManager.conf"\r\n
        ** Content-Type: application/octet-stream\r\n\r\n
        ** <DATA>
        ** ---- normal post var
        ** Content-Disposition: form-data; name="lastname"\r\n\r\n
        ** <DATA>
        */
        if (strncasecmp((const char *) src + idx, "content-disposition: form-data;", 31)) {
            formatMatch(parser.uncommonPostFormat, 1, BODY, "POST data : unknown content-disposition",
                        (const char *) src + idx, false);
            block = true;
            return;
        }
        idx += 31;
        line_end = (u_char *) strchr((const char *) src + idx, '\n');
        if (!line_end) {
            formatMatch(parser.uncommonPostFormat, 1, BODY, "POST data : malformed boundary line", string(), false);
            block = true;
            return;
        }
        /* Parse content-disposition, extract name / filename */
        varn_start = varn_end = filen_start = filen_end = NULL;
        if (!contentDispositionParser(src + idx, line_end, &varn_start, &varn_end, &filen_start, &filen_end)) {
            formatMatch(parser.uncommonPostFormat, 1, BODY, string(), string(), false);
            block = true;
            return;
        }
        /* var name is mandatory */
        if (!varn_start || !varn_end || varn_end <= varn_start) {
            formatMatch(parser.uncommonPostFormat, 1, BODY, "POST data : no 'name' in POST var", string(), false);
            block = true;
            return;
        }
        varn_len = varn_end - varn_start;

        /* If there is a filename, it is followed by a "content-type" line, skip it */
        if (filen_start && filen_end) {
            line_end = (u_char *) strchr((const char *) line_end + 1, '\n');
            if (!line_end) {
                formatMatch(parser.uncommonPostFormat, 1, BODY, "POST data : malformed filename (no content-type ?)",
                            string(), false);
                block = true;
                return;
            }
        }
        /*
        ** now idx point to the end of the
        ** content-disposition: form-data; filename="" name=""
        */
        idx += line_end - (src + idx) + 1;
        if (src[idx] != '\r' || src[idx + 1] != '\n') {
            formatMatch(parser.uncommonPostFormat, 1, BODY, "POST data : malformed content-disposition line", string(),
                        false);
            block = true;
            return;
        }
        idx += 2;
        /* seek the end of the data */
        end = NULL;
        while (idx < len) {
            end = (u_char *) strstr((char *) src + idx, "\r\n--");
            /* file data can contain \x0 */
            while (!end) {
                idx += strlen((const char *) src + idx);
                if (idx < len - 2) {
                    idx++;
                    end = (u_char *) strstr((char *) src + idx, "\r\n--");
                }
                else
                    break;
            }
            if (!end) {
                formatMatch(parser.uncommonPostFormat, 1, BODY, "POST data : malformed content-disposition line",
                            string(), false);
                block = true;
                return;
            }
            if (!strncmp((const char *) end + 4, (const char *) boundary, boundary_len))
                break;
            else {
                idx += (end - (src + idx)) + 1;
                end = NULL;
            }
        }
        if (!end) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "POST data : malformed line");
            return;
        }
        if (filen_start) {
            final_var.data = varn_start;
            final_var.len = varn_len;
            final_data.data = filen_start;
            final_data.len = filen_end - filen_start;
            nullbytes = naxsi_unescape(&final_var);
            if (nullbytes > 0) {
                formatMatch(parser.uncommonHexEncoding, 1, BODY, string(), string(), true);
                block = true;
            }
            nullbytes = naxsi_unescape(&final_data);
            if (nullbytes > 0) {
                formatMatch(parser.uncommonHexEncoding, 1, BODY, string(), string(), false);
                block = true;
            }

            /* here we got val name + val content !*/
            string finalVar = string((char *) final_var.data, final_var.len);
            string finalData = string((char *) final_data.data, final_data.len);
            transform(finalVar.begin(), finalVar.end(), finalVar.begin(), tolower);
            transform(finalData.begin(), finalData.end(), finalData.begin(), tolower);
//            cerr << finalVar << ":" << finalData << endl;
            basestrRuleset(FILE_EXT, finalVar, finalData, parser.bodyRules);

            idx += end - (src + idx);
        }
        else if (varn_start) {
            varc_len = end - (src + idx);
            final_var.data = varn_start;
            final_var.len = varn_len;
            final_data.data = src + idx;
            final_data.len = varc_len;
            nullbytes = naxsi_unescape(&final_var);
            if (nullbytes > 0) {
                formatMatch(parser.uncommonHexEncoding, 1, BODY, string(), string(), true);
                block = true;
            }
            nullbytes = naxsi_unescape(&final_data);
            if (nullbytes > 0) {
                formatMatch(parser.uncommonHexEncoding, 1, BODY, string(), string(), false);
                block = true;
            }

            /* here we got val name + val content !*/
            string finalVar = string((char *) final_var.data, final_var.len);
            string finalData = string((char *) final_data.data, final_data.len);
            transform(finalVar.begin(), finalVar.end(), finalVar.begin(), tolower);
            transform(finalData.begin(), finalData.end(), finalData.begin(), tolower);
//            cerr << finalVar << ":" << finalData << endl;
            basestrRuleset(BODY, finalVar, finalData, parser.bodyRules);

            idx += end - (src + idx);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "(multipart) : ");
        }
        if (!strncmp((const char *) end, "\r\n", 2))
            idx += 2;
    }
}

/*
 * decode url (key=val&key2=val2...)
 * splits the string into key/val pair
 * apply rules to key/val
 */
bool RuntimeScanner::splitUrlEncodedRuleset(char *str, const vector<http_rule_t *> &rules, MATCH_ZONE zone) {
    str_t name, val;
    char *eq, *ev, *orig;
    unsigned long len, full_len;
    int nullbytes = 0;

    orig = str;
    full_len = strlen(orig);
    while (str < (orig + full_len) && *str) {
        if (*str == '&') {
            str++;
            continue;
        }
        if ((block && !scfg->learning) || drop)
            return false;
        eq = strchr(str, '=');
        ev = strchr(str, '&');

        if ((!eq && !ev) /*?foobar */ || (eq && ev && eq > ev)) /*?foobar&bla=test*/ {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "XX-url has no '&' and '=' or has both [%s]", str);

            if (!ev)
                ev = str + strlen(str);
            /* len is now [name] */
            len = ev - str;
            val.data = (unsigned char *) str;
            val.len = ev - str;
            name.data = (unsigned char *) NULL;
            name.len = 0;
        }
            /* ?&&val | ?var&& | ?val& | ?&val | ?val&var */
        else if (!eq) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "XX-url has no '=' but has '&' [%s]", str);

            formatMatch(parser.uncommonUrl, 1, zone, string(), string(), false);
            if (ev > str) /* ?var& | ?var&val */ {
                val.data = (unsigned char *) str;
                val.len = ev - str;
                name.data = (unsigned char *) NULL;
                name.len = 0;
                len = ev - str;
            }
            else /* ?& | ?&&val */ {
                val.data = name.data = NULL;
                val.len = name.len = 0;
                len = 1;
            }
        }
        else /* should be normal like ?var=bar& ..*/ {
            if (!ev) /* ?bar=lol */
                ev = str + strlen(str);
            /* len is now [name]=[content] */
            len = ev - str;
            eq = strnchr(str, '=', len);
            if (!eq) {
                formatMatch(parser.uncommonUrl, 1, zone, "malformed url, possible attack", string(), false);
                return true;
            }
            eq++;
            val.data = (unsigned char *) eq;
            val.len = ev - eq;
            name.data = (unsigned char *) str;
            name.len = eq - str - 1;
        }
        if (name.len) {
            nullbytes = naxsi_unescape(&name);
            if (nullbytes > 0) {
                formatMatch(parser.uncommonUrl, 1, zone, (char *) name.data, (char *) val.data, true);
            }
        }
        if (val.len) {
            nullbytes = naxsi_unescape(&val);
            if (nullbytes > 0) {
                formatMatch(parser.uncommonUrl, 1, zone, (char *) name.data, (char *) val.data, false);
            }
        }

        string key = string((char *) name.data, name.len);
        string value = string((char *) val.data, val.len);
//        cerr << key << ":" << value << endl;
        transform(key.begin(), key.end(), key.begin(), tolower);
        transform(value.begin(), value.end(), value.begin(), tolower);
        basestrRuleset(zone, key, value, rules);

        str += len;
    }

    return false;
}

int RuntimeScanner::postReadRequest(request_rec *rec) {
    r = rec;

    /* Store every HTTP header received */
    const apr_array_header_t *headerFields = apr_table_elts(r->headers_in);
    apr_table_entry_t *headerEntry = (apr_table_entry_t *) headerFields->elts;
    for (int i = 0; i < headerFields->nelts; i++) {
//        cerr << headerEntry[i].key << ":" << headerEntry[i].val << endl;
        string key = string(headerEntry[i].key);
        string val = string(headerEntry[i].val);
        transform(key.begin(), key.end(), key.begin(), tolower);
        transform(val.begin(), val.end(), val.begin(), tolower);
        /* Retrieve Content-Length */
        if (key == "content-length") {
            try {
                contentLength = std::stoul(val);
            }
            catch (std::exception const &e) {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "%s cannot convert content-type: \"%s\" to interger",
                             e.what(), val.c_str());
            }
        }
            /* Store Content-Type for further processing */
        else if (key == "content-type") {
//            cerr << key << ": " << val << endl;
            if (caseEqual(val, "application/x-www-form-urlencoded")) {
                contentType = URL_ENC;
            }
            else if (caseEqual(val.substr(0, 20), "multipart/form-data;")) {
                contentType = MULTIPART;
                rawContentType = string(val);
            }
            else if (caseEqual(val, "application/json")) {
                contentType = APP_JSON;
            }
            contentTypeFound = true;
        }
        basestrRuleset(HEADERS, key, val, parser.headerRules);
    }

    /* Retrieve GET parameters */
    apr_table_t *getTable = NULL;
    ap_args_to_table(r, &getTable);
    const apr_array_header_t *getParams = apr_table_elts(getTable);
    apr_table_entry_t *getParam = (apr_table_entry_t *) getParams->elts;
    for (int i = 0; i < getParams->nelts; i++) {
//        cerr << getParam[i].key << ":" << getParam[i].val << endl;
        string key = string(getParam[i].key);
        string val = string(getParam[i].val);
        transform(key.begin(), key.end(), key.begin(), tolower);
        transform(val.begin(), val.end(), val.begin(), tolower);
        basestrRuleset(ARGS, key, val, parser.getRules);
    }

    uri = string(r->parsed_uri.path);
    transform(uri.begin(), uri.end(), uri.begin(), tolower);
    basestrRuleset(URL, string(), uri, parser.genericRules);

    if (r->method_number == M_POST || r->method_number == M_PUT)
        return DECLINED;

    writeLearningLog();

    if (block)
        return HTTP_FORBIDDEN;
    return DECLINED;
}

int RuntimeScanner::processBody() {
    /* Process only if POST / PUT request */
    if (r->method_number != M_POST && r->method_number != M_PUT) {
        return DECLINED;
    }

    if (!contentTypeFound) {
        formatMatch(parser.uncommonContentType, 1, HEADERS, string(), string(), false);
        return HTTP_FORBIDDEN;
    }

    if (rawBody.empty()) {
        return DECLINED;
    }

    /* If Content-Type: application/x-www-form-urlencoded */
    if (contentType == URL_ENC) {
        if (splitUrlEncodedRuleset(&rawBody[0], parser.bodyRules, BODY)) {
            formatMatch(parser.uncommonUrl, 1, BODY, string(), string(), false);
            block = true;
        }
    }
        /* If Content-Type: multipart/form-data */
    else if (contentType == MULTIPART) {
        multipartParse((u_char *) &rawBody[0], rawBody.length());
    }
        /* If Content-Type: application/json */
    else if (contentType == APP_JSON) {
        jsonParse((u_char *) &rawBody[0], rawBody.length());
    }
    else {
        str_t body;
        body.data = (u_char *) &rawBody[0];
        body.len = rawBody.length();

        naxsi_unescape(&body);
        rawBody.resize(body.len);

        basestrRuleset(RAW_BODY, string(), rawBody, parser.rawBodyRules);
    }

    writeLearningLog();

    if (block) {
        return HTTP_FORBIDDEN;
    }
    return DECLINED;
}

void RuntimeScanner::writeLearningLog() {
    if (!scfg->learning || rulesMatchedCount == 0)
        return;

    std::time_t tt = system_clock::to_time_t(system_clock::now());
    std::tm *ptm = std::localtime(&tt);
    stringstream errlog;
    errlog << std::put_time(ptm, "%Y/%m/%d %T") << " ";
    errlog << "[error] ";
    errlog << "NAXSI_FMT: ";

    errlog << "ip=" << r->useragent_ip << "&";
    errlog << "server=" << r->hostname << "&";
    errlog << "uri=" << r->parsed_uri.path << "&";

    errlog << "block=" << block << "&";
    int i = 0;
    for (const auto &match : matchScores) {
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
    const char *szStr = tmp.c_str();
    apr_size_t szStrlen = strlen(szStr);
    apr_file_write(scfg->errorlog_fd, szStr, &szStrlen);
}

bool RuntimeScanner::jsonForward(json_t *js) {
    while ((*(js->src + js->off) == ' ' ||
            *(js->src + js->off) == '\t' ||
            *(js->src + js->off) == '\n' ||
            *(js->src + js->off) == '\r') && js->off < js->len) {
        js->off++;
    }
    js->c = *(js->src + js->off);
    return true;
}

/*
** used to fast forward in json POSTS,
** we skip whitespaces/tab/CR/LF
*/
bool RuntimeScanner::jsonSeek(json_t *js, unsigned char seek) {
    jsonForward(js);
    return js->c == seek;
}

/*
** extract a quoted strings,
** JSON spec only supports double-quoted strings,
** so do we.
*/
bool RuntimeScanner::jsonQuoted(json_t *js, str_t *ve) {
    u_char *vn_start, *vn_end = NULL;

    if (*(js->src + js->off) != '"')
        return false;
    js->off++;
    vn_start = js->src + js->off;
    /* extract varname inbetween "..."*/
    while (js->off < js->len) {
        /* skip next character if backslashed */
        if (*(js->src + js->off) == '\\') {
            js->off += 2;
            if (js->off >= js->len) break;
        }
        if (*(js->src + js->off) == '"') {
            vn_end = js->src + js->off;
            js->off++;
            break;
        }
        js->off++;
    }
    if (!vn_start || !vn_end)
        return false;
    if (!*vn_start || !*vn_end)
        return false;
    ve->data = vn_start;
    ve->len = vn_end - vn_start;
    return true;
}

/*
** an array is values separated by ','
*/
bool RuntimeScanner::jsonArray(json_t *js) {
    bool rc;

    js->c = *(js->src + js->off);
    if (js->c != '[' || js->depth > JSON_MAX_DEPTH)
        return false;
    js->off++;
    do {
        rc = jsonVal(js);
        /* if we cannot extract the value,
           we may have reached array end. */
        if (!rc)
            break;
        jsonForward(js);
        if (js->c == ',') {
            js->off++;
            jsonForward(js);
        } else break;
    } while (rc);
    return js->c == ']';
}


bool RuntimeScanner::jsonVal(json_t *js) {
    str_t val;
    bool ret;

    val.data = NULL;
    val.len = 0;

    jsonForward(js);
    if (js->c == '"') {
        ret = jsonQuoted(js, &val);
        if (ret) {
            /* parse extracted values. */
            string jsckey = string((char *) js->ckey.data, js->ckey.len);
            string value = string((char *) val.data, val.len);
            transform(jsckey.begin(), jsckey.end(), jsckey.begin(), tolower);
            transform(value.begin(), value.end(), value.begin(), tolower);
            basestrRuleset(BODY, jsckey, value, parser.bodyRules);

            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "JSON '%s' : '%s'", (char*) &(js->ckey.data), (char*) &(val.data));
        }
        return ret;
    }
    if ((js->c >= '0' && js->c <= '9') || js->c == '-') {
        val.data = js->src + js->off;
        while (((*(js->src + js->off) >= '0' && *(js->src + js->off) <= '9') ||
                *(js->src + js->off) == '.' || *(js->src + js->off) == '-') && js->off < js->len) {
            val.len++;
            js->off++;
        }
        /* parse extracted values. */
        string jsckey = string((char *) js->ckey.data, js->ckey.len);
        string value = string((char *) val.data, val.len);
        transform(jsckey.begin(), jsckey.end(), jsckey.begin(), tolower);
        transform(value.begin(), value.end(), value.begin(), tolower);
        basestrRuleset(BODY, jsckey, value, parser.bodyRules);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "JSON '%s' : '%s'", (char*) &(js->ckey.data), (char*) &(val.data));
        return true;
    }
    if (!strncasecmp((const char *) (js->src + js->off), (const char *) "true", 4) ||
        !strncasecmp((const char *) (js->src + js->off), (const char *) "false", 5) ||
        !strncasecmp((const char *) (js->src + js->off), (const char *) "null", 4)) {
        js->c = *(js->src + js->off);
        /* we don't check static values, do we ?! */
        val.data = js->src + js->off;
        if (js->c == 'F' || js->c == 'f') {
            js->off += 5;
            val.len = 5;
        }
        else {
            js->off += 4;
            val.len = 4;
        }
        /* parse extracted values. */
        string jsckey = string((char *) js->ckey.data, js->ckey.len);
        string value = string((char *) val.data, val.len);
        transform(jsckey.begin(), jsckey.end(), jsckey.begin(), tolower);
        transform(value.begin(), value.end(), value.begin(), tolower);
        basestrRuleset(BODY, jsckey, value, parser.bodyRules);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "JSON '%s' : '%s'", (char*) &(js->ckey.data), (char*) &(val.data));
        return true;
    }

    if (js->c == '[') {
        ret = jsonArray(js);
        if (js->c != ']')
            return false;
        js->off++;
        return (ret);
    }
    if (js->c == '{') {
        /*
        ** if sub-struct, parse key without value :
        ** "foobar" : { "bar" : [1,2,3]} => "foobar" parsed alone.
        ** this is to avoid "foobar" left unparsed, as we won't have
        ** key/value here with "foobar" as a key.
        */
        string jsckey = string((char *) js->ckey.data, js->ckey.len);
        transform(jsckey.begin(), jsckey.end(), jsckey.begin(), tolower);
        basestrRuleset(BODY, jsckey, string(), parser.bodyRules);

        ret = jsonObj(js);
        jsonForward(js);
        if (js->c != '}')
            return false;
        js->off++;
        return (ret);
    }
    return false;
}


bool RuntimeScanner::jsonObj(json_t *js) {
    js->c = *(js->src + js->off);

    if (js->c != '{' || js->depth > JSON_MAX_DEPTH)
        return false;
    js->off++;

    do {
        jsonForward(js);
        /* check subs (arrays, objects) */
        switch (js->c) {
            case '[': /* array */
                js->depth++;
                jsonArray(js);
                if (!jsonSeek(js, ']'))
                    return false;
                js->off++;
                js->depth--;
                break;
            case '{': /* sub-object */
                js->depth++;
                jsonObj(js);
                if (js->c != '}')
                    return false;
                js->off++;
                js->depth--;
                break;
            case '"': /* key : value, extract and parse. */
                if (!jsonQuoted(js, &(js->ckey)))
                    return false;
                if (!jsonSeek(js, ':'))
                    return false;
                js->off++;
                jsonForward(js);
                if (!jsonVal(js))
                    return false;
            default:break;
        }
        jsonForward(js);
        /* another element ? */
        if (js->c == ',') {
            js->off++;
            jsonForward(js);
            continue;

        } else if (js->c == '}') {
            js->depth--;
            /* or maybe we just finished parsing this object */
            return true;
        } else {
            /* nothing we expected, die. */
            return false;
        }
    } while (js->off < js->len);

    return false;
}

/*
** Parse a JSON request
*/
void RuntimeScanner::jsonParse(u_char *src, unsigned long len) {
    json_t *js = (json_t*) apr_pcalloc(r->pool, sizeof(json_t));
    if (!js) return;
    js->json.data = js->src = src;
    js->json.len = js->len = len;

    if (!jsonSeek(js, '{')) {
        formatMatch(parser.invalidJson, 1, BODY, "missing opening brace", string(), false);
        block = true;
        return;
    }
    if (!jsonObj(js)) {
        formatMatch(parser.invalidJson, 1, BODY, "malformed json object", string(), false);
        block = true;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "jsonObj returned error, apply invalid json.");
        return;
    }
    /* we are now on closing bracket, check for garbage. */
    js->off++;
    jsonForward(js);
    if (js->off != js->len) {
        formatMatch(parser.invalidJson, 1, BODY, "garbage after the closing brace", string(), false);
        block = true;
    }
}