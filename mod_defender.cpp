#include <apr_strings.h>
#include "mod_defender.hpp"
#include "RuntimeScanner.hpp"

extern module AP_MODULE_DECLARE_DATA defender_module;

RuleParser* parser = nullptr;

vector<string> *tmpMainRules;
vector<string> *tmpBasicRules;

/* Custom function to ensure our RuntimeScanner get's deleted at the
   end of the request cycle. */
apr_status_t defender_delete_runtimescanner_object(void *inPtr) {
    if (inPtr)
        delete (RuntimeScanner *) inPtr;
    return OK;
}

int pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp) {
    parser = new RuleParser();
    tmpMainRules = new vector<string>();
    tmpBasicRules = new vector<string>();
    return OK;
}

int post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
    /* Figure out if we are here for the first time */
    void *init_flag = NULL;
    apr_pool_userdata_get(&init_flag, "moddefender-init-flag", s->process->pool);
    if (init_flag == NULL) {
        apr_pool_userdata_set((const void *)1, "moddefender-init-flag", apr_pool_cleanup_null, s->process->pool);
    }
    else {
        parser->parseMainRules(*tmpMainRules);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "%lu CheckRules loaded", parser->checkRules.size());
        parser->parseBasicRules(*tmpBasicRules);
        parser->generateHashTables();

        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, plog, "RuleParser initialized successfully");

        /* clear the temporary arrays */
        delete tmpMainRules;
        delete tmpBasicRules;
    }
    return OK;
}

/* Our custom handler
 */
int defender_handler(request_rec *r) {
    // Get the module configuration
    server_config_t *scfg = (server_config_t *) ap_get_module_config(r->server->module_config, &defender_module);

    if (parser == nullptr)
        return HTTP_SERVICE_UNAVAILABLE;

    /* Create an instance of our application. */
    RuntimeScanner *runtimeScanner = new RuntimeScanner(r, scfg, *parser);

    if (runtimeScanner == nullptr)
        return HTTP_SERVICE_UNAVAILABLE;

    /* Register a C function to delete runtimeScanner
       at the end of the request cycle. */
    apr_pool_cleanup_register(r->pool, (void *) runtimeScanner, defender_delete_runtimescanner_object, apr_pool_cleanup_null);

    /* Run our application handler. */
    return runtimeScanner->runHandler();
}

/* Apache callback to register our hooks.
 */
void defender_register_hooks(apr_pool_t *p) {
    ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(defender_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/**
 * This function is called when the "MatchLog" configuration directive is parsed.
 */
const char *set_errorlog_path(cmd_parms *cmd, void *_scfg, const char *arg) {
    // get the module configuration (this is the structure created by create_server_config())
    server_config_t *scfg = (server_config_t *) ap_get_module_config(cmd->server->module_config, &defender_module);

    // make a duplicate of the argument's value using the command parameters pool.
    scfg->errorlog_path = apr_pstrdup(cmd->pool, arg);

    if (scfg->errorlog_path[0] == '|') {
        const char *pipe_name = scfg->errorlog_path + 1;
        piped_log *pipe_log;

        pipe_log = ap_open_piped_log(cmd->pool, pipe_name);
        if (pipe_log == NULL) {
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the errorlog pipe: %s",
                                pipe_name);
        }
        scfg->errorlog_fd = ap_piped_log_write_fd(pipe_log);
    }
    else {
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

const char *set_libinjection_sql_flag(cmd_parms *cmd, void *_scfg, int flag) {
    server_config_t *scfg = (server_config_t *) ap_get_module_config(cmd->server->module_config, &defender_module);
    scfg->libinjection_sql = (bool) flag;
    scfg->libinjection = (scfg->libinjection_sql || scfg->libinjection_xss);
    return NULL;
}

const char *set_libinjection_xss_flag(cmd_parms *cmd, void *_scfg, int flag) {
    server_config_t *scfg = (server_config_t *) ap_get_module_config(cmd->server->module_config, &defender_module);
    scfg->libinjection_xss = (bool) flag;
    scfg->libinjection = (scfg->libinjection_sql || scfg->libinjection_xss);
    return NULL;
}

const char *set_learning_flag(cmd_parms *cmd, void *_scfg, int flag) {
    server_config_t *scfg = (server_config_t *) ap_get_module_config(cmd->server->module_config, &defender_module);
    scfg->learning = (bool) flag;
    return NULL;
}

const char *set_mainrules(cmd_parms *cmd, void *sconf_, const char *arg) {
    if (!strcmp(arg, ";")) {
        return NULL;
    }
    tmpMainRules->push_back(arg);
    return NULL;
}

const char *set_checkrules(cmd_parms *cmd, void *sconf_, const char *arg1, const char *arg2) {
    return parser->parseCheckRule(cmd->pool, arg1, arg2);
}

const char *set_basicrules(cmd_parms *cmd, void *sconf_, const char *arg) {
    tmpBasicRules->push_back(arg);
    return NULL;
}

/**
 * A declaration of the configuration directives that are supported by this module.
 */
const command_rec directives[] = {
        {"MainRule",     (cmd_func) set_mainrules,  NULL, RSRC_CONF, ITERATE,  "Match directive"},
        {"CheckRule",    (cmd_func) set_checkrules, NULL, RSRC_CONF, TAKE2, "Score directive"},
        {"BasicRule",    (cmd_func) set_basicrules, NULL, RSRC_CONF, ITERATE,  "Whitelist directive"},
        {"MatchLog",   (cmd_func) set_errorlog_path,  NULL, RSRC_CONF, TAKE1,    "Path to the match log"},
        {"LearningMode", (cmd_func) set_learning_flag,     NULL, RSRC_CONF, FLAG,    ""},
        {"LibinjectionSQL", (cmd_func) set_libinjection_sql_flag,     NULL, RSRC_CONF, FLAG,    "Libinjection SQL toggle"},
        {"LibinjectionXSS", (cmd_func) set_libinjection_xss_flag,     NULL, RSRC_CONF, FLAG,    "Libinjection XSS toggle"},
        {NULL}
};

/**
 * Creates the per-server configuration records.
 */
void *create_server_config(apr_pool_t *p, server_rec *s) {
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