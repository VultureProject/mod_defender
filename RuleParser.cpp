#include <apr_strings.h>
#include "RuleParser.h"

RuleParser::RuleParser(apr_pool_t* pool, string &nxcorerules) {
    this->pool = pool;
    this->nxcorerules = nxcorerules;
}

vector<nxrule_t> RuleParser::parse() {
    vector<nxrule_t> rules;
    istringstream iss(nxcorerules);
    for (string line; std::getline(iss, line); ) {
        if (line.substr(0, 8) != "MainRule") // skip non rule lines
            continue;
        line.erase(0, 9); // remove "MainRule "
        line = Util::trim(line); // trim the line
        line.pop_back(); // remove the trailing semicolon

        vector<string> parts = Util::split(line, '"', true);

        nxrule_t rule;

        pair<string, string> matchpatern = Util::splitAtFirst(parts[0], ':');
        rule.IsMatchPaternRx = (matchpatern.first == "rx");
        if (matchpatern.first == "rx") {
            rule.matchPaternRx = regex(matchpatern.second);
        }
        if (matchpatern.first == "str") {
            rule.matchPaternStr = apr_pstrdup(pool, matchpatern.second.c_str());
        }

        rule.msg = apr_pstrdup(pool, Util::stringAfter(parts[1], ':').c_str());
        rule.matchZone = apr_pstrdup(pool, Util::stringAfter(parts[2], ':').c_str());

        string score = Util::stringAfter(parts[3], ':');
        vector<string> scores = Util::split(score, ',');
        for (const string &sc : scores) {
            pair<string, string> scorepair = Util::splitAtFirst(sc, ':');
            rule.scores.emplace_back(apr_pstrdup(pool, scorepair.first.c_str()),
                                     std::stoi(scorepair.second));
        }

        rule.id = Util::intAfter(parts[4], ':');

        rules.push_back(rule);
    }
    return rules;
}
