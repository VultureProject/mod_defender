#include "CApplication.hpp"

int CApplication::RunHandler() {
    int nReturnVal = DECLINED;

    if (m_pRequestRec->handler != NULL && strcmp(m_pRequestRec->handler, "defender") == 0) {
        ap_rputs("Hello World from DEFENDER", m_pRequestRec);
        nReturnVal = OK;
    }

    return nReturnVal;
}