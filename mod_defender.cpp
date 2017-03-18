/*                       _        _       __                _
 *   _ __ ___   ___   __| |    __| | ___ / _| ___ _ __   __| | ___ _ __
 *  | '_ ` _ \ / _ \ / _` |   / _` |/ _ \ |_ / _ \ '_ \ / _` |/ _ \ '__|
 *  | | | | | | (_) | (_| |  | (_| |  __/  _|  __/ | | | (_| |  __/ |
 *  |_| |_| |_|\___/ \__,_|___\__,_|\___|_|  \___|_| |_|\__,_|\___|_|
 *                       |_____|
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#include <apr_strings.h>
#include <http_request.h>
#include "mod_defender.hpp"
#include "RuntimeScanner.hpp"

extern module AP_MODULE_DECLARE_DATA defender_module;

/* Custom definition to hold any configuration data we may need. */
typedef struct {
    RuntimeScanner *vpRuntimeScanner;
} defender_config_t;

static RuleParser parser;

static vector<string> tmpMainRules;
static vector<string> tmpBasicRules;

/* Custom function to ensure our RuntimeScanner get's deleted at the
   end of the request cycle. */
static apr_status_t defender_delete_runtimescanner_object(void *inPtr) {
    if (inPtr)
        delete (RuntimeScanner *) inPtr;
    return OK;
}

static int post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
    /* Figure out if we are here for the first time */
    void *init_flag = NULL;
    apr_pool_userdata_get(&init_flag, "moddefender-init-flag", s->process->pool);
    if (init_flag == NULL) { // first load
        apr_pool_userdata_set((const void *) 1, "moddefender-init-flag", apr_pool_cleanup_null, s->process->pool);
        tmpMainRules.clear();
        tmpBasicRules.clear();
    } else { // second (last) load
        parser.parseMainRules(tmpMainRules);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "%lu CheckRules loaded", parser.checkRules.size());
        parser.parseBasicRules(tmpBasicRules);
        parser.generateHashTables();

        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, plog, "RuleParser initialized successfully");
    }
    return OK;
}

static int post_read_request(request_rec *r) {
    // Get the module configuration
    server_config_t *scfg = (server_config_t *) ap_get_module_config(r->server->module_config, &defender_module);

    RuntimeScanner *runtimeScanner = new RuntimeScanner(scfg, parser);

    /* Register a C function to delete runtimeScanner
       at the end of the request cycle. */
    apr_pool_cleanup_register(r->pool, (void *) runtimeScanner, defender_delete_runtimescanner_object,
                              apr_pool_cleanup_null);

    /* Reserve a temporary memory block from the
       request pool to store data between hooks. */
    defender_config_t *pDefenderConfig = (defender_config_t *) apr_palloc(r->pool, sizeof(defender_config_t));

    /* Remember our application pointer for future calls. */
    pDefenderConfig->vpRuntimeScanner = runtimeScanner;

    /* Register our config data structure for our module for retrieval later as required */
    ap_set_module_config(r->request_config, &defender_module, (void *) pDefenderConfig);

    /* Run our application handler. */
    return runtimeScanner->postReadRequest(r);
}

static char *get_apr_error(apr_pool_t *p, apr_status_t rc) {
    char *text = (char *) apr_pcalloc(p, 201);
    if (text == NULL) return NULL;
    apr_strerror(rc, text, 200);
    return text;
}


static int fixer_upper(request_rec *r) {
    /* Stop if this is not the main request */
    if ((r->main != NULL) || (r->prev != NULL)) {
        return DECLINED;
    }

    /* Process only if POST / PUT request */
    if (r->method_number != M_POST && r->method_number != M_PUT) {
        return DECLINED;
    }

    defender_config_t *defc = (defender_config_t *) ap_get_module_config(r->request_config, &defender_module);
    RuntimeScanner *runtimeScanner = defc->vpRuntimeScanner;

    /* Check if supported Content-Type */
    if (runtimeScanner->contentType == UNSUPPORTED) {
        return DECLINED;
    }

    server_config_t *scfg = (server_config_t *) ap_get_module_config(r->server->module_config, &defender_module);

    /* Read the request body */
    bool eos = false;
    apr_bucket_brigade *bb_in = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (bb_in == NULL) return -1;
    do {
        int rc = ap_get_brigade(r->input_filters, bb_in, AP_MODE_SPECULATIVE, APR_BLOCK_READ, runtimeScanner->contentLength);
        if (rc != APR_SUCCESS) {
            switch (rc) {
                case APR_EOF:
                    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, r->pool, "Error reading request body: %s",
                                  get_apr_error(r->pool, rc));
                    return -6;
                case APR_TIMEUP:
                    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, r->pool, "Error reading request body: %s",
                                  get_apr_error(r->pool, rc));
                    return -4;
                case AP_FILTER_ERROR:
                    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, r->pool,
                                  "Error reading request body: HTTP Error 413 - Request entity too large. (Most likely.)");
                    return -3;
                case APR_EGENERAL:
                    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, r->pool,
                                  "Error reading request body: Client went away.");
                    return -2;
                default:
                    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, r->pool, "Error reading request body: %s",
                                  get_apr_error(r->pool, rc));
                    return -1;
            }
        }

        /* Iterate on the buckets in the brigade
         * to retrieve the body of the request */
        if (runtimeScanner->contentLength <= scfg->requestBodyLimit) {
            runtimeScanner->rawBody.reserve(runtimeScanner->contentLength);
        }
        for (apr_bucket *bucket = APR_BRIGADE_FIRST(bb_in);
             bucket != APR_BRIGADE_SENTINEL(bb_in); bucket = APR_BUCKET_NEXT(bucket)) {
            if (APR_BUCKET_IS_EOS(bucket)) {
                eos = true;
            }

            if (APR_BUCKET_IS_FLUSH(bucket)) {
                continue;
            }

            const char *buf;
            apr_size_t nbytes;

            rc = apr_bucket_read(bucket, &buf, &nbytes, APR_BLOCK_READ);
            if (rc != APR_SUCCESS) {
                ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, r->pool, "Failed reading input / bucket (%d): %s", rc,
                              get_apr_error(r->pool, rc));
                return -1;
            }

            if (runtimeScanner->rawBody.length() + nbytes > runtimeScanner->contentLength) {
                eos = true;
                ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, r->pool, "Too much POST data");
                break;
            }

            runtimeScanner->rawBody += string(buf, nbytes);

            if (runtimeScanner->rawBody.length() > scfg->requestBodyLimit) {
                runtimeScanner->applyRuleMatch(parser.bigRequest, 1, BODY, empty, empty, false);
                return -1;
            }

            if (runtimeScanner->rawBody.length() == runtimeScanner->contentLength) {
                eos = true;
                break;
            }
        }

        apr_brigade_cleanup(bb_in);
    } while (!eos);
//    ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, r->pool, "post data (%lu): %s", runtimeScanner->rawBody.length(),
//                  runtimeScanner->rawBody.c_str());

    return runtimeScanner->processBody();
}

/* Apache callback to register our hooks.
 */
static void defender_register_hooks(apr_pool_t *p) {
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_REALLY_LAST);
    ap_hook_post_read_request(post_read_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_fixups(fixer_upper, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

/**
 * This function is called when the "MatchLog" configuration directive is parsed.
 */
static const char *set_errorlog_path(cmd_parms *cmd, void *_scfg, const char *arg) {
    // get the module configuration (this is the structure created by create_server_config())
    server_config_t *scfg = (server_config_t *) ap_get_module_config(cmd->server->module_config, &defender_module);

    scfg->errorlog_path = apr_pstrdup(cmd->pool, arg);

    if (scfg->errorlog_path[0] == '|') {
        const char *pipe_name = scfg->errorlog_path + 1;
        piped_log *pipe_log;

        pipe_log = ap_open_piped_log(cmd->pool, pipe_name);
        if (pipe_log == NULL) {
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the errorlog pipe: %s", pipe_name);
        }
        scfg->errorlog_fd = ap_piped_log_write_fd(pipe_log);
    } else {
        const char *file_name = ap_server_root_relative(cmd->pool, scfg->errorlog_path);
        apr_status_t rc;

        rc = apr_file_open(&scfg->errorlog_fd, file_name,
                           APR_WRITE | APR_APPEND | APR_CREATE | APR_BINARY,
                           APR_UREAD | APR_UWRITE | APR_GREAD, cmd->pool);

        if (rc != APR_SUCCESS) {
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the errorlog file: %s", file_name);
        }
    }

    return NULL; // success
}

static const char *set_request_body_limit(cmd_parms *cmd, void *_dcfg, const char *arg) {
    server_config_t *scfg = (server_config_t *) ap_get_module_config(cmd->server->module_config, &defender_module);
    unsigned long limit;
    limit = strtoul(arg, NULL, 10);
    if ((limit == LONG_MAX) || (limit == LONG_MIN) || (limit <= 0)) {
        return apr_psprintf(cmd->pool, "mod_defender: Invalid value for SecRequestBodyLimit: %s", arg);
    }
    scfg->requestBodyLimit = limit;
    return NULL;
}

static const char *set_libinjection_sql_flag(cmd_parms *cmd, void *_dcfg, int flag) {
    server_config_t *scfg = (server_config_t *) ap_get_module_config(cmd->server->module_config, &defender_module);
    scfg->libinjection_sql = (bool) flag;
    scfg->libinjection = (scfg->libinjection_sql || scfg->libinjection_xss);
    return NULL;
}

static const char *set_libinjection_xss_flag(cmd_parms *cmd, void *_dcfg, int flag) {
    server_config_t *scfg = (server_config_t *) ap_get_module_config(cmd->server->module_config, &defender_module);
    scfg->libinjection_xss = (bool) flag;
    scfg->libinjection = (scfg->libinjection_sql || scfg->libinjection_xss);
    return NULL;
}

static const char *set_learning_flag(cmd_parms *cmd, void *_dcfg, int flag) {
    server_config_t *scfg = (server_config_t *) ap_get_module_config(cmd->server->module_config, &defender_module);
    scfg->learning = (bool) flag;
    return NULL;
}

static const char *set_mainrules(cmd_parms *cmd, void *_dcfg, const char *arg) {
    if (!strcmp(arg, ";")) {
        return NULL;
    }
    tmpMainRules.push_back(apr_pstrdup(cmd->pool, arg));
    return NULL;
}

static const char *set_checkrules(cmd_parms *cmd, void *_dcfg, const char *arg1, const char *arg2) {
    return parser.parseCheckRule(cmd->pool, arg1, arg2);
}

static const char *set_basicrules(cmd_parms *cmd, void *_dcfg, const char *arg) {
    tmpBasicRules.push_back(apr_pstrdup(cmd->pool, arg));
    return NULL;
}

/**
 * A declaration of the configuration directives that are supported by this module.
 */
static const command_rec directives[] = {
        {"MainRule",         (cmd_func) set_mainrules,             NULL, RSRC_CONF, ITERATE, "Match directive"},
        {"CheckRule",        (cmd_func) set_checkrules,            NULL, RSRC_CONF, TAKE2,   "Score directive"},
        {"BasicRule",        (cmd_func) set_basicrules,            NULL, RSRC_CONF, ITERATE, "Whitelist directive"},
        {"MatchLog",         (cmd_func) set_errorlog_path,         NULL, RSRC_CONF, TAKE1,   "Path to the match log"},
        {"RequestBodyLimit", (cmd_func) set_request_body_limit,    NULL, RSRC_CONF, TAKE1,   "Set Request Body Limit"},
        {"LearningMode",     (cmd_func) set_learning_flag,         NULL, RSRC_CONF, FLAG,    "Learning mode toggle"},
        {"LibinjectionSQL",  (cmd_func) set_libinjection_sql_flag, NULL, RSRC_CONF, FLAG,    "Libinjection SQL toggle"},
        {"LibinjectionXSS",  (cmd_func) set_libinjection_xss_flag, NULL, RSRC_CONF, FLAG,    "Libinjection XSS toggle"},
        {NULL}
};

/**
 * Creates the per-server configuration records.
 */
static void *create_server_config(apr_pool_t *p, server_rec *s) {
    // allocate space for the configuration structure from the provided pool p.
    server_config_t *scfg = (server_config_t *) apr_pcalloc(p, sizeof(server_config_t));

    // return the new server configuration structure.
    return scfg;
}

/* Our standard module definition.
 */
module AP_MODULE_DECLARE_DATA defender_module = {
        STANDARD20_MODULE_STUFF,
        NULL,
        NULL,
        create_server_config, // create per-server configuration structures.,
        NULL,
        directives, // configuration directive handlers,
        defender_register_hooks // request handlers
};