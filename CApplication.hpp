#ifndef CAPPLICATION_HPP
#define CAPPLICATION_HPP

<<<<<<< HEAD
#include "mod_defender.hpp"

class CApplication {
private:
    request_rec*    m_pRequestRec;

public:
    CApplication(request_rec* inpRequestRec):
            m_pRequestRec(inpRequestRec)
    {}

    int RunHandler();
=======
#include <map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <chrono>
#include <httpd.h>
#include "RuleParser.h"

using std::chrono::system_clock;

using std::pair;
using std::vector;
using std::string;
using std::cerr;
using std::stringstream;
using std::endl;
using std::flush;
using std::regex_match;

class CApplication {
private:
    request_rec* r;
    apr_file_t *errorlog_fd;
    apr_pool_t* pool;
    stringstream errlog;
    stringstream attacks;
    unsigned int attack = 0;
    vector<pair<const char *, const char *>> headers;
    vector<pair<const char *, const char *>> args;
    vector<pair<const char *, const char *>> body;
    vector<nxrule_t> rules;

public:
    CApplication(request_rec* rec, apr_file_t *errorlog_fd, vector<nxrule_t>& rules);

    static int storeTable(void*, const char*, const char*);
    static int storeHeaders(void*, const char*, const char*);
    void readPost();
    int runHandler();
    void checkAttack(const char *varName, const char *value, const char *zone);
    void checkVector(const char *zone, vector<pair<const char *, const char *>> &v);
    void formatAttack(const nxrule_t &rule, string zone, string varname);
>>>>>>> 5eee329... naxsi core rules parser
};

#endif /* CAPPLICATION_HPP */

