#include <apr_strings.h>
#include "NxParser.h"

vector<nxrule_t> NxParser::parseCoreRules(apr_pool_t* pool, apr_array_header_t *mainRules) {
    vector<nxrule_t> rules;
    for (int i = 0; i < mainRules->nelts; i+=5) {
        nxrule_t rule;
        pair<string, string> matchpatern = Util::splitAtFirst(((const char **) mainRules->elts)[i+0], ':');
        rule.IsMatchPaternRx = (matchpatern.first == "rx");
        if (matchpatern.first == "rx") {
            rule.matchPaternRx = regex(matchpatern.second);
        }
        if (matchpatern.first == "str") {
            rule.matchPaternStr = apr_pstrdup(pool, matchpatern.second.c_str());
        }

        rule.msg = apr_pstrdup(pool, Util::stringAfter(((const char **) mainRules->elts)[i+1], ':').c_str());
        rule.matchZone = apr_pstrdup(pool, Util::stringAfter(((const char **) mainRules->elts)[i+2], ':').c_str());

        string score = Util::stringAfter(((const char **) mainRules->elts)[i+3], ':');
        vector<string> scores = Util::split(score, ',');
        for (const string &sc : scores) {
            pair<string, string> scorepair = Util::splitAtFirst(sc, ':');
            rule.scores.emplace_back(apr_pstrdup(pool, scorepair.first.c_str()), std::stoi(scorepair.second));
        }

        rule.id = Util::intAfter(((const char **) mainRules->elts)[i+4], ':');

        rules.push_back(rule);
    }

//    for (const nxrule_t &rule : rules) {
//        cerr << rule.IsMatchPaternRx << " ";
//        const char* matchPaternStr;
//        if (rule.IsMatchPaternRx)
//            cerr << "<regex> ";
//        else
//            cerr << rule.matchPaternStr << " ";
//
//        for (const pair<const char*, unsigned int> &sc : rule.scores)
//            cerr << sc.first << " " << sc.second << " ";
//
//        cerr << rule.msg << " ";
//        cerr << rule.matchZone << " ";
//        cerr << rule.id << " ";
//        cerr << endl;
//    }
    return rules;
}
