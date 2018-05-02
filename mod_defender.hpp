/**
 * \file     mod_defender.hpp
 * \author   Kevin Guillemot
 * \version  1.0
 * \date     30/03/2018
 * \license  GPLv3
 * \brief    Header file of the mod_defender module
 */

#ifndef MOD_DEFENDER_HPP
#define MOD_DEFENDER_HPP


/*************************/
/* Inclusion of .H files */
/*************************/

#include <http_request.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_strings.h>
#include <util_script.h>
#include "RuleParser.h"
#include "RuntimeScanner.hpp"


/*************/
/* Constants */
/*************/

    /*---------------------------*/
    /* MODULE-part needed macros */
    /*---------------------------*/

/**
 *  Extra Apache 2.4+ C++ module declaration.
 *  Needed cause of C++ use.
 */
#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(defender);
#endif

extern module AP_MODULE_DECLARE_DATA defender_module;

/**
 * \def MAX_BB_SIZE
 *      The length of the 403 response body, in bytes
 */
#define MAX_BB_SIZE 0x7FFFFFFF

/**
 * \def CHUNK_CAPACITY
 *      The length of the 403 response body, in bytes
 */
#define CHUNK_CAPACITY 8192

/**
 * \def IF_STATUS_NONE
 *      The length of the 403 response body, in bytes
 */
#define IF_STATUS_NONE 0

/**
 * \def IF_STATUS_WANTS_TO_RUN
 *      The length of the 403 response body, in bytes
 */
#define IF_STATUS_WANTS_TO_RUN 1

/**
 * \def IF_STATUS_COMPLETE
 *      The length of the 403 response body, in bytes
 */
#define IF_STATUS_COMPLETE 2


/**************/
/* Structures */
/**************/

/**
 * \struct  dir_config_t mod_defender.h
 *          Regroup all server directives in a structure
 */
typedef struct {
    RuleParser *parser;
    vector<pair<string, string>> tmpCheckRules;
    vector<string> tmpBasicRules;
    char *loc_path;
    apr_file_t *matchlog_file;
    apr_file_t *jsonmatchlog_file;
    unsigned long requestBodyLimit;
    bool libinjection_sql;
    bool libinjection_xss;
    bool defender;
    bool learning;
    bool extensive;
    bool useenv;
} dir_config_t;

/**
 * \struct  chunk_t mod_defender.h
 *          Chunk structure used to save/restore brigades
 */
typedef struct {
    char                    *data;
    apr_size_t               length;
    unsigned int             is_permanent;
} chunk_t;

/**
 * \struct  defender_t mod_defender.h
 *          Defender structure used to save/restore brigades
 */
typedef struct {
    int fixups_done;
    int body_error;
    const char *body_error_msg;
    unsigned int status;
    unsigned int started_forwarding;
    unsigned int stream_changed;
    apr_size_t           stream_input_length;
    char                *stream_input_data;
    unsigned int         if_seen_eos;
    int                  body_chunk_position;
    unsigned int         body_chunk_offset;
    apr_pool_t *body_pool;
    apr_array_header_t *body_chunks;
    chunk_t *body_chunk;
    apr_size_t         body_length;
    chunk_t *body_chunk_current;
    char *body_buffer;
    unsigned int         body_should_exist;
    unsigned int         body_read;
} defender_t;

/**
 * \struct  defender_config_t mod_defender.h
 *          Custom definition to hold any configuration data we may need.
 */
typedef struct {
    RuntimeScanner *vpRuntimeScanner;
    defender_t *def;
} defender_config_t;


/************************/
/* Functions signatures */
/************************/

/**
 * \brief   Initialize all variables used to forward request body.
 * \param   def             Defender structure.
 * \param   char**          Error message pointer.
 * \param   r               Apache request structure to work on.
 * \return  apr_status_t    Return status code of function.
 */
apr_status_t body_retrieve_start(defender_t *def, char **error_msg, request_rec *r);

/**
 * \brief   Retrieve stocked chunk of request body and return it.
 * \param   def             Defender structure.
 * \param   chunk_t**       List of chunks to add the chunk onto.
 * \param   nbytes          Chunk max bytes length.
 * \param   char**          Error message pointer.
 * \param   r               Apache request structure to work on.
 * \return  apr_status_t    Return status code of function.
 */
apr_status_t body_retrieve(defender_t *def, chunk_t **chunk, long int nbytes, char **error_msg, request_rec *r);

/**
 * \brief   Initialize all variables used to forward request body.
 * \param   def             Defender structure.
 * \param   char**          Error message pointer.
 * \param   r               Apache request structure to work on.
 * \param   body_limit      Value of requestBodyLimit directive, to not exceed.
 * \return  apr_status_t    Return status code of function.
 */
apr_status_t read_request_body(defender_t *def, char **error_msg, request_rec *r, unsigned long body_limit);

/**
 * \brief   Initialize all variables used to forward request body.
 * \param   data            Defender structure, as void*, called by apache hook.
 * \return  apr_status_t    Return status code of function.
 */
apr_status_t body_clear(void *data);


#endif //MOD_DEFENDER_HPP
