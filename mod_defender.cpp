/*                       _        _       __                _
 *   _ __ ___   ___   __| |    __| | ___ / _| ___ _ __   __| | ___ _ __
 *  | '_ ` _ \ / _ \ / _` |   / _` |/ _ \ |_ / _ \ '_ \ / _` |/ _ \ '__|
 *  | | | | | | (_) | (_| |  | (_| |  __/  _|  __/ | | | (_| |  __/ |
 *  |_| |_| |_|\___/ \__,_|___\__,_|\___|_|  \___|_| |_|\__,_|\___|_|
 *                       |_____|
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */

#include <http_request.h>
#include "mod_defender.hpp"
#include "RuntimeScanner.hpp"

std::vector<dir_config_t *> dir_cfgs;

extern module AP_MODULE_DECLARE_DATA defender_module;

/* Custom definition to hold any configuration data we may need. */
typedef struct {
    RuntimeScanner *vpRuntimeScanner;
} defender_config_t;

/* Custom function to ensure our RuntimeScanner get's deleted at the
   end of the request cycle. */
static apr_status_t defender_delete_runtimescanner_object(void *inPtr) {
    if (inPtr)
        delete (RuntimeScanner *) inPtr;
    return OK;
}

static apr_status_t defender_delete_ruleparser_object(void *inPtr) {
    if (inPtr) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "Unloading Defender for a loc");
        delete (RuleParser *) inPtr;
    }
    return OK;
}

/*
 * This routine is called after the server finishes the configuration
 * process.  At this point the module may review and adjust its configuration
 * settings in relation to one another and report any problems.  On restart,
 * this routine will be called only once, in the running server process.
 */
static int post_config(apr_pool_t *pconf, apr_pool_t *, apr_pool_t *, server_rec *s) {
    /* Figure out if we are here for the first time */
    void *init_flag = NULL;
    apr_pool_userdata_get(&init_flag, "defender-init-flag", s->process->pool);
    if (init_flag == NULL) { // first load
        apr_pool_userdata_set((const void *) 1, "defender-init-flag", apr_pool_cleanup_null, s->process->pool);
        tmpMainRules.clear();
    } else { // second (last) load
        unsigned int mainRuleCount = RuleParser::parseMainRules(tmpMainRules);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Defender active on server %s: %d MainRules loaded",
                     s->server_hostname, mainRuleCount);

        for (int i = 0; i < dir_cfgs.size(); i++) {
            dir_config_t *dcfg = dir_cfgs[i];
            if (dcfg->defender) {
                dcfg->parser = new RuleParser();
                apr_pool_cleanup_register(pconf, (void *) dcfg->parser, defender_delete_ruleparser_object,
                                          apr_pool_cleanup_null);
                dcfg->parser->parseCheckRule(dcfg->tmpCheckRules);
                unsigned int basicRuleCount = dcfg->parser->parseBasicRules(dcfg->tmpBasicRules);
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                             "Defender active on loc %s: %lu CheckRules loaded, %d BasicRules loaded",
                             dcfg->loc_path, dcfg->parser->checkRules.size(), basicRuleCount);
                dcfg->parser->generateHashTables();
            } else {
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Defender scanner disabled for loc %s",
                             dcfg->loc_path);
            }
        }
    }
    dir_cfgs.clear();
    return OK;
}

/*
 * this routine gives our module another chance to examine the request
 * headers and to take special action. This is the first phase whose
 * hooks' configuration directives can appear inside the <Directory>
 * and similar sections, because at this stage the URI has been mapped
 * to the filename. For example this phase can be used to block evil
 * clients, while little resources were wasted on these.
 *
 * This is a RUN_ALL hook.
 */
static int header_parser(request_rec *r) {
    // Get the module configuration
    dir_config_t *dcfg = (dir_config_t *) ap_get_module_config(r->per_dir_config, &defender_module);

    // Stop if Defender not enabled
    if (!dcfg->defender)
        return DECLINED;

    RuntimeScanner *scanner = new RuntimeScanner(dcfg, *dcfg->parser);

    // Register a C function to delete scanner at the end of the request cycle
    apr_pool_cleanup_register(r->pool, (void *) scanner, defender_delete_runtimescanner_object,
                              apr_pool_cleanup_null);

    // Reserve a temporary memory block from the request pool to store data between hooks
    defender_config_t *pDefenderConfig = (defender_config_t *) apr_palloc(r->pool, sizeof(defender_config_t));

    // Remember our application pointer for future calls
    pDefenderConfig->vpRuntimeScanner = scanner;

    // Register our config data structure for our module for retrieval later as required
    ap_set_module_config(r->request_config, &defender_module, (void *) pDefenderConfig);

    // Run our application handler
    return scanner->processHeaders(r);
}

static char *get_apr_error(apr_pool_t *p, apr_status_t rc) {
    char *text = (char *) apr_pcalloc(p, 201);
    if (text == NULL) return NULL;
    apr_strerror(rc, text, 200);
    return text;
}

/*
 * This routine is called to perform any module-specific fixing of header
 * fields, et cetera.  It is invoked just before any content-handler.
 *
 * This is a RUN_ALL HOOK.
 */
static int fixups(request_rec *r) {
    dir_config_t *dcfg = (dir_config_t *) ap_get_module_config(r->per_dir_config, &defender_module);
    // Stop if Defender not enabled
    if (!dcfg->defender)
        return DECLINED;

    // Stop if this is not the main request
    if ((r->main != NULL) || (r->prev != NULL))
        return DECLINED;

    // Process only if POST / PUT request
    if (r->method_number != M_POST && r->method_number != M_PUT)
        return DECLINED;

    defender_config_t *defc = (defender_config_t *) ap_get_module_config(r->request_config, &defender_module);
    RuntimeScanner *scanner = defc->vpRuntimeScanner;

    // Check if supported Content-Type
    if (scanner->contentType == UNSUPPORTED)
        return DECLINED;

    if (scanner->contentLength <= 0)
        return -1;

    // Iterate on the buckets in the brigade to retrieve the body of the request
    if (scanner->contentLength <= dcfg->requestBodyLimit)
        scanner->rawBody.reserve(scanner->contentLength);

    // Read the request body
    bool eos = false;
    apr_bucket_brigade *bb_in = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (bb_in == NULL) return -1;
    do {
        int rc = ap_get_brigade(r->input_filters, bb_in, AP_MODE_SPECULATIVE, APR_BLOCK_READ,
                                scanner->contentLength);
        if (rc != APR_SUCCESS) {
            switch (rc) {
                case APR_EOF:
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Error reading request body: %s",
                                  get_apr_error(r->pool, rc));
                    return -6;
                case APR_TIMEUP:
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Error reading request body: %s",
                                  get_apr_error(r->pool, rc));
                    return -4;
                case AP_FILTER_ERROR:
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                                  "Error reading request body: HTTP Error 413 - Request entity too large. (Most likely.)");
                    return -3;
                case APR_EGENERAL:
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                                  "Error reading request body: Client went away.");
                    return -2;
                default:
                    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Error reading request body: %s",
                                  get_apr_error(r->pool, rc));
                    return -1;
            }
        }

        for (apr_bucket *bucket = APR_BRIGADE_FIRST(bb_in);
             bucket != APR_BRIGADE_SENTINEL(bb_in); bucket = APR_BUCKET_NEXT(bucket)) {
            if (APR_BUCKET_IS_EOS(bucket))
                eos = true;

            if (APR_BUCKET_IS_FLUSH(bucket))
                continue;

            const char *buf;
            apr_size_t nbytes;

            rc = apr_bucket_read(bucket, &buf, &nbytes, APR_BLOCK_READ);
            if (rc != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Failed reading input / bucket (%d): %s", rc,
                              get_apr_error(r->pool, rc));
                return -1;
            }

            if (scanner->rawBody.length() + nbytes > scanner->contentLength) {
                eos = true;
                ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Too much POST data");
                break;
            }

            scanner->rawBody += string(buf, nbytes);

            if (scanner->rawBody.length() > dcfg->requestBodyLimit) {
                scanner->applyRuleMatch(dcfg->parser->bigRequest, 1, BODY, empty, empty, false);
                return -1;
            }

            if (scanner->rawBody.length() == scanner->contentLength) {
                eos = true;
                break;
            }
        }

        apr_brigade_cleanup(bb_in);
    } while (!eos);
//    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "post data (%lu): %s", scanner->rawBody.length(),
//                  scanner->rawBody.c_str());
    return scanner->processBody();
}

/* Apache callback to register our hooks.
 */
static void defender_register_hooks(apr_pool_t *) {
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_header_parser(header_parser, NULL, NULL, APR_HOOK_REALLY_FIRST - 20);
    ap_hook_fixups(fixups, NULL, NULL, APR_HOOK_REALLY_FIRST - 20);
}

/**
 * This function is called when the "MatchLog" configuration directive is parsed.
 */
static const char *set_matchlog_path(cmd_parms *cmd, void *cfg, const char *arg) {
    dir_config_t *dcfg = (dir_config_t *) cfg;

    dcfg->matchlog_path = apr_pstrdup(cmd->pool, arg);

    if (dcfg->matchlog_path[0] == '|') {
        const char *pipe_name = dcfg->matchlog_path + 1;
        piped_log *pipe_log;

        pipe_log = ap_open_piped_log(cmd->pool, pipe_name);
        if (pipe_log == NULL)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the match log pipe: %s", pipe_name);
        dcfg->matchlog_fd = ap_piped_log_write_fd(pipe_log);
    } else {
        const char *file_name = ap_server_root_relative(cmd->pool, dcfg->matchlog_path);
        apr_status_t rc;

        rc = apr_file_open(&dcfg->matchlog_fd, file_name,
                           APR_WRITE | APR_APPEND | APR_CREATE | APR_BINARY,
                           APR_UREAD | APR_UWRITE | APR_GREAD, cmd->pool);

        if (rc != APR_SUCCESS)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the match log file: %s", file_name);
    }

    return NULL; // success
}

/**
 * This function is called when the "JSONMatchLog" configuration directive is parsed.
 */
static const char *set_jsonerrorlog_path(cmd_parms *cmd, void *cfg, const char *arg) {
    dir_config_t *dcfg = (dir_config_t *) cfg;

    dcfg->jsonmatchlog_path = apr_pstrdup(cmd->pool, arg);

    if (dcfg->jsonmatchlog_path[0] == '|') {
        const char *pipe_name = dcfg->jsonmatchlog_path + 1;
        piped_log *pipe_log;

        pipe_log = ap_open_piped_log(cmd->pool, pipe_name);
        if (pipe_log == NULL)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the json match log pipe: %s", pipe_name);
        dcfg->jsonmatchlog_fd = ap_piped_log_write_fd(pipe_log);
    } else {
        const char *file_name = ap_server_root_relative(cmd->pool, dcfg->jsonmatchlog_path);
        apr_status_t rc;

        rc = apr_file_open(&dcfg->jsonmatchlog_fd, file_name,
                           APR_WRITE | APR_APPEND | APR_CREATE | APR_BINARY,
                           APR_UREAD | APR_UWRITE | APR_GREAD, cmd->pool);

        if (rc != APR_SUCCESS)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the json match log file: %s", file_name);
    }

    return NULL; // success
}

static const char *set_request_body_limit(cmd_parms *cmd, void *cfg, const char *arg) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    unsigned long limit = strtoul(arg, NULL, 10);
    if (limit <= 0)
        return apr_psprintf(cmd->pool, "mod_defender: Invalid value for RequestBodyLimit: %s", arg);
    dcfg->requestBodyLimit = limit;
    return NULL;
}

static const char *set_libinjection_sql_flag(cmd_parms *cmd, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->libinjection_sql = (bool) flag;
    dcfg->libinjection = (dcfg->libinjection_sql || dcfg->libinjection_xss);
    return NULL;
}

static const char *set_libinjection_xss_flag(cmd_parms *cmd, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->libinjection_xss = (bool) flag;
    dcfg->libinjection = (dcfg->libinjection_sql || dcfg->libinjection_xss);
    return NULL;
}

static const char *set_defender_flag(cmd_parms *cmd, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->defender = (bool) flag;
    return NULL;
}

static const char *set_learning_flag(cmd_parms *cmd, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->learning = (bool) flag;
    return NULL;
}

static const char *set_extensive_flag(cmd_parms *cmd, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->extensive = (bool) flag;
    return NULL;
}

static const char *set_useenv_flag(cmd_parms *cmd, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->useenv = (bool) flag;
    return NULL;
}

static const char *set_mainrules(cmd_parms *cmd, void *, const char *arg) {
    if (!strcmp(arg, ";"))
        return NULL;
    tmpMainRules.push_back(apr_pstrdup(cmd->pool, arg));
    return NULL;
}

static const char *set_checkrules(cmd_parms *cmd, void *cfg, const char *arg1, const char *arg2) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->tmpCheckRules.push_back(std::make_pair(apr_pstrdup(cmd->pool, arg1), apr_pstrdup(cmd->pool, arg2)));
    return NULL;
}

static const char *set_basicrules(cmd_parms *cmd, void *cfg, const char *arg) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->tmpBasicRules.push_back(apr_pstrdup(cmd->pool, arg));
    return NULL;
}

/**
 * A declaration of the configuration directives that are supported by this module.
 */
static const command_rec directives[] = {
        {"Defender",         (cmd_func) set_defender_flag,         NULL, ACCESS_CONF, FLAG,    "Defender toggle"},
        {"MainRule",         (cmd_func) set_mainrules,             NULL, RSRC_CONF,   ITERATE, "Match directive"},
        {"CheckRule",        (cmd_func) set_checkrules,            NULL, ACCESS_CONF, TAKE2,   "Score directive"},
        {"BasicRule",        (cmd_func) set_basicrules,            NULL, ACCESS_CONF, ITERATE, "Whitelist directive"},
        {"MatchLog",         (cmd_func) set_matchlog_path,         NULL, ACCESS_CONF, TAKE1,   "Path to the match log"},
        {"JSONMatchLog",     (cmd_func) set_jsonerrorlog_path,     NULL, ACCESS_CONF, TAKE1,   "Path to the JSON match log"},
        {"RequestBodyLimit", (cmd_func) set_request_body_limit,    NULL, ACCESS_CONF, TAKE1,   "Set Request Body Limit"},
        {"LearningMode",     (cmd_func) set_learning_flag,         NULL, ACCESS_CONF, FLAG,    "Learning mode toggle"},
        {"ExtensiveLog",     (cmd_func) set_extensive_flag,        NULL, ACCESS_CONF, FLAG,    "Extensive log toggle"},
        {"LibinjectionSQL",  (cmd_func) set_libinjection_sql_flag, NULL, ACCESS_CONF, FLAG,    "Libinjection SQL toggle"},
        {"LibinjectionXSS",  (cmd_func) set_libinjection_xss_flag, NULL, ACCESS_CONF, FLAG,    "Libinjection XSS toggle"},
        {"UseEnv",           (cmd_func) set_useenv_flag,           NULL, ACCESS_CONF, FLAG,    "UseEnv toggle"},
        {NULL}
};

/**
 * Creates the per-server configuration records.
 */
static void *create_dir_config(apr_pool_t *p, char *path) {
    // allocate space for the configuration structure from the provided pool p.
    dir_config_t *dcfg = (dir_config_t *) apr_pcalloc(p, sizeof(dir_config_t));

    dir_cfgs.push_back(dcfg);
    dcfg->loc_path = apr_pstrdup(p, path);

    dcfg->requestBodyLimit = 131072;
    dcfg->learning = 1;
    return dcfg;
}

/* Our standard module definition.
 */
module AP_MODULE_DECLARE_DATA defender_module = {
        STANDARD20_MODULE_STUFF,
        create_dir_config,
        NULL,
        NULL, // create per-server configuration structures.,
        NULL, // merge per-server configurations
        directives, // configuration directive handlers,
        defender_register_hooks // request handlers
};