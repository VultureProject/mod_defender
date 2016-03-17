#include <apr_strings.h>
#include "mod_defender.hpp"
#include "CApplication.hpp"

extern module AP_MODULE_DECLARE_DATA defender_module;

/* Custom definition to hold any configuration data we may need.
   At this stage we just use it to keep a copy of the CApplication
   object pointer. Later we will add more when we need specific custom
   configuration information. */
typedef struct {
    void *vpCApplication;
} defender_config_t;

NxParser* parser = nullptr;

apr_array_header_t *tmpMainRulesArray;
apr_array_header_t *tmpCheckRulesArray;
apr_array_header_t *tmpBasicRulesArray;

/* Custom function to ensure our CApplication get's deleted at the
   end of the request cycle. */
apr_status_t defender_delete_capplication_object(void *inPtr) {
    if (inPtr)
        delete (CApplication *) inPtr;
    return OK;
}

/* Custom function to retrieve our defender_config_t* pointer previously
   registered with Apache on this request cycle. */
defender_config_t *defender_get_config_ptr(request_rec *inpRequest) {
    defender_config_t *pReturnValue = NULL;
    if (inpRequest != NULL)
        pReturnValue = (defender_config_t *) ap_get_module_config(inpRequest->request_config, &defender_module);
    return pReturnValue;
}

apr_status_t defender_delete_nxparser_object(void *inPtr) {
    if (inPtr) {
        cerr <<  "mod_defender: " << KYEL "deleting parser..." KNRM << endl;
        delete (NxParser *) inPtr;
    }
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
//        for (int i = 0; i < tmpMainRulesArray->nelts; i++) {
//            const char *s = ((const char **) tmpMainRulesArray->elts)[i];
//            fprintf(stderr, "%d: %s\n", i, s);
//        }

//        cerr << Util::formatLog(DEFLOG_NOTICE, NULL);
//        cerr << "NxParser loaded" << endl;

        ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, plog, "NxParser initializing...");

        parser = new NxParser(s->process->pool);
        parser->parseMainRules(tmpMainRulesArray);
        parser->parseCheckRules(tmpCheckRulesArray);
        parser->parseBasicRules(tmpBasicRulesArray);


        parser->createHashTables();

        /* clear the temporary arrays */
        apr_array_clear(tmpMainRulesArray);
        apr_array_clear(tmpCheckRulesArray);
        apr_array_clear(tmpBasicRulesArray);

        /* Schedule main cleanup for later, when the main pool is destroyed. */
//        apr_pool_cleanup_register(pconf, (void *)s, defender_delete_nxparser_object, apr_pool_cleanup_null);
    }
}

/* Our custom handler
 */
int defender_handler(request_rec *r) {
    // Get the module configuration
    server_config_t *scfg = (server_config_t *) ap_get_module_config(r->server->module_config, &defender_module);

    if (parser == nullptr)
        return HTTP_SERVICE_UNAVAILABLE;

//    for (const main_rule_t &rule : dcfg->mainRules) {
//        fprintf(stderr, "%d ", rule.rxMz);
//        if (rule.rxMz)
//            fprintf(stderr, "%s ", "<regex> ");
//        else
//            fprintf(stderr, "%s ", rule.matchPaternStr);
//
//        for (const pair<const char*, int> &sc : rule.scores)
//            fprintf(stderr, "%s %d ", sc.first, sc.second);
//
//        fprintf(stderr, "%s ", rule.msg);
//        fprintf(stderr, "%d ", rule.id);
//        fprintf(stderr, "\n");
//    }

//    for (const auto& match : dcfg->checkRules) {
//        cerr <<  match.first << " ";
//        cerr <<  match.second.comparator << " ";
//        cerr <<  match.second.limit << " ";
//        cerr <<  match.second.action << " ";
//        cerr << endl;
//    }

//    return DECLINED; // STOP THE HANDLE

    /* Create an instance of our application. */
    CApplication *pApp = new CApplication(r, scfg, *parser);

    if (pApp == nullptr)
        return HTTP_SERVICE_UNAVAILABLE;

    /* Register a C function to delete pApp
       at the end of the request cycle. */
    apr_pool_cleanup_register(r->pool, (void *) pApp, defender_delete_capplication_object, apr_pool_cleanup_null);

    /* Reserve a temporary memory block from the
       request pool to store data between hooks. */
    defender_config_t *pDefenderConfig = (defender_config_t *) apr_palloc(r->pool, sizeof(defender_config_t));

    /* Remember our application pointer for future calls. */
    pDefenderConfig->vpCApplication = (void *) pApp;

    /* Register our config data structure for our module for retrieval later as required */
    ap_set_module_config(r->request_config, &defender_module, (void *) pDefenderConfig);

    /* Run our application handler. */
    return pApp->runHandler();
}

int pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp) {
    tmpMainRulesArray = apr_array_make(pconf, 209, sizeof(const char *));
    tmpCheckRulesArray = apr_array_make(pconf, 5, sizeof(const char *));
    tmpBasicRulesArray = apr_array_make(pconf, 32, sizeof(const char *));
    return OK;
}

/* Apache callback to register our hooks.
 */
void defender_register_hooks(apr_pool_t *p) {
    ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(defender_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/**
 * This function is called when the "NxErrorLog" configuration directive is parsed.
 */
const char *set_errorlog_path(cmd_parms *cmd, void *_scfg, const char *arg) {
    // get the module configuration (this is the structure created by create_server_config())
    server_config_t *scfg = (server_config_t *) ap_get_module_config(cmd->server->module_config, &defender_module);

    // make a duplicate of the argument's value using the command parameters pool.
    scfg->errorlog_path = (char *) arg;

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

const char *set_nx_main_rules(cmd_parms *cmd, void *sconf_, const char *arg) {
    *(const char **) apr_array_push(tmpMainRulesArray) = apr_pstrdup(tmpMainRulesArray->pool, arg);
    return NULL;
}

const char *set_nx_check_rules(cmd_parms *cmd, void *sconf_, const char *arg1, const char *arg2) {
    *(const char **) apr_array_push(tmpCheckRulesArray) = apr_pstrdup(tmpCheckRulesArray->pool, arg1);
    *(const char **) apr_array_push(tmpCheckRulesArray) = apr_pstrdup(tmpCheckRulesArray->pool, arg2);
    return NULL;
}

const char *set_nx_basic_rules(cmd_parms *cmd, void *sconf_, const char *arg) {
    *(const char **) apr_array_push(tmpBasicRulesArray) = apr_pstrdup(tmpBasicRulesArray->pool, arg);
    return NULL;
}

// Dummy function
const char *skip_directive() { return NULL; }

/**
 * A declaration of the configuration directives that are supported by this module.
 */
const command_rec directives[] = {
        {"NxErrorLog",   (cmd_func) set_errorlog_path,  NULL, RSRC_CONF, TAKE1,    "Path to the errorlog file"},
        {"MainRule",     (cmd_func) set_nx_main_rules,  NULL, RSRC_CONF, ITERATE,  "Match directive"},
        {"LearningMode", (cmd_func) skip_directive,     NULL, RSRC_CONF, TAKE1,    ""},
        {"SecRules",     (cmd_func) skip_directive,     NULL, RSRC_CONF, TAKE1,    ""},
        {"CheckRule",    (cmd_func) set_nx_check_rules, NULL, RSRC_CONF, ITERATE2, "Score directive"},
        {"BasicRule",    (cmd_func) set_nx_basic_rules, NULL, RSRC_CONF, ITERATE,  "Whitelist directive"},
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