//
// Created by kguillemot on 30/04/18.
//
#ifndef MOD_DEFENDER_HPP
#define MOD_DEFENDER_HPP


extern module AP_MODULE_DECLARE_DATA defender_module;


#define MAX_BB_SIZE 0x7FFFFFFF
#define CHUNK_CAPACITY 8192

#define IF_STATUS_NONE                  0
#define IF_STATUS_WANTS_TO_RUN          1
#define IF_STATUS_COMPLETE              2

/*
 * Per-directory configuration structure
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

typedef struct {
    char                    *data;
    apr_size_t               length;
    unsigned int             is_permanent;
} chunk_t;

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


/* Custom definition to hold any configuration data we may need. */
typedef struct {
    RuntimeScanner *vpRuntimeScanner;
    defender_t *def;
} defender_config_t;

apr_status_t body_retrieve_start(defender_t *def, char **error_msg, request_rec *r);
apr_status_t body_retrieve(defender_t *def, chunk_t **chunk, long int nbytes, char **error_msg, request_rec *r);
apr_status_t read_request_body(defender_t *def, char **error_msg, request_rec *r, unsigned long body_limit);
apr_status_t body_clear(void *data);

#endif //MOD_DEFENDER_HPP
