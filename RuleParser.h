#ifndef MOD_DEFENDER_RULEPARSER_H
#define MOD_DEFENDER_RULEPARSER_H

#include <apr_file_io.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <iterator>
#include "Util.h"
#include <regex>

using std::pair;
using std::vector;
using std::string;
using std::cerr;
using std::stringstream;
using std::endl;
using std::flush;
using std::istream_iterator;
using std::istringstream;
using std::regex;

typedef struct {
    bool IsMatchPaternRx;
    regex matchPaternRx;
    const char* matchPaternStr;
    vector<pair<const char*, unsigned int>> scores;
    const char* msg;
    const char* matchZone;
    unsigned int id;
} nxrule_t;

class RuleParser {
private:
    apr_pool_t* pool;
    string nxcorerules;

public:
    RuleParser(apr_pool_t* pool, string &nxcorerules);
    vector<nxrule_t> parse();
};


#endif //MOD_DEFENDER_RULEPARSER_H
