#ifndef CAPPLICATION_HPP
#define CAPPLICATION_HPP

#include "mod_defender.hpp"

class CApplication {
private:
    request_rec*    m_pRequestRec;

public:
    CApplication(request_rec* inpRequestRec):
            m_pRequestRec(inpRequestRec)
    {}

    int RunHandler();
};

#endif /* CAPPLICATION_HPP */

