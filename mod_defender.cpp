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

typedef struct {
    apr_array_header_t *mainRulesArray;
    apr_array_header_t *checkRulesArray;
    apr_array_header_t *basicRulesArray;
} dir_config_t;

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

/* Our custom handler
 */
int defender_handler(request_rec *r) {
    // Get the module configuration
    server_config_t *scfg = (server_config_t *) ap_get_module_config(r->server->module_config, &defender_module);
    dir_config_t *dcfg = (dir_config_t *) ap_get_module_config(r->per_dir_config, &defender_module);

//    for (int i = 0; i < dcfg->mainRulesArray->nelts; i++) {
//        const char *s = ((const char **) dcfg->mainRulesArray->elts)[i];
//        fprintf(stderr, "%d: %s\n", i, s);
//    }

    if (!scfg->confParsed) {
        cerr << "RRRRRRRRREEEEEEEEEEEEAAAAAAAAAAADDDDDDDDIIIIIIINNNNNNGGGGGG !!!!!!!!!!!!!!" << endl;
        scfg->parser = NxParser(r->server->process->pool);
        scfg->parser.parseMainRules(dcfg->mainRulesArray);
        scfg->parser.parseCheckRules(dcfg->checkRulesArray);
        scfg->parser.parseBasicRules(dcfg->basicRulesArray);
        scfg->parser.createHashTables();
        scfg->confParsed = true;
    }


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
    CApplication *pApp = new CApplication(r, scfg);

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

/* Apache callback to register our hooks.
 */
void defender_register_hooks(apr_pool_t *p) {
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
    dir_config_t *scfg = (dir_config_t *) sconf_;
    *(const char **) apr_array_push(scfg->mainRulesArray) = apr_pstrdup(scfg->mainRulesArray->pool, arg);
    return NULL;
}

const char *set_nx_check_rules(cmd_parms *cmd, void *sconf_, const char *arg1, const char *arg2) {
    dir_config_t *scfg = (dir_config_t *) sconf_;
    *(const char **) apr_array_push(scfg->checkRulesArray) = apr_pstrdup(scfg->checkRulesArray->pool, arg1);
    *(const char **) apr_array_push(scfg->checkRulesArray) = apr_pstrdup(scfg->checkRulesArray->pool, arg2);
    return NULL;
}

const char *set_nx_basic_rules(cmd_parms *cmd, void *sconf_, const char *arg) {
    dir_config_t *scfg = (dir_config_t *) sconf_;
    *(const char **) apr_array_push(scfg->basicRulesArray) = apr_pstrdup(scfg->basicRulesArray->pool, arg);
    return NULL;
}

// Dummy function
const char *skip_directive() { return NULL; }

/**
 * A declaration of the configuration directives that are supported by this module.
 */
const command_rec directives[] = {
        {"NxErrorLog",        (cmd_func) set_errorlog_path, NULL, RSRC_CONF, TAKE1, "Path to the errorlog file"},
        {"MainRule",          (cmd_func) set_nx_main_rules,  NULL, RSRC_CONF |
                                                                   ACCESS_CONF,             ITERATE,  "Match directive"},
        {"LearningMode",     (cmd_func) skip_directive,    NULL, RSRC_CONF | ACCESS_CONF, TAKE1, ""},
        {"SecRules",  (cmd_func) skip_directive,    NULL, RSRC_CONF | ACCESS_CONF, TAKE1,  ""},
        {"CheckRule",         (cmd_func) set_nx_check_rules,    NULL, RSRC_CONF | ACCESS_CONF, ITERATE2,    "Score directive"},
        {"BasicRule",         (cmd_func) set_nx_basic_rules,    NULL, RSRC_CONF | ACCESS_CONF, ITERATE,    "Whitelist directive"},
        {NULL}
};

void *create_dir_config(apr_pool_t *p, char *context) {
    dir_config_t *dcfg = (dir_config_t *) apr_palloc(p, sizeof(*dcfg));
    dcfg->mainRulesArray = apr_array_make(p, 209, sizeof(const char *));
    dcfg->checkRulesArray = apr_array_make(p, 5, sizeof(const char *));
    dcfg->basicRulesArray = apr_array_make(p, 32, sizeof(const char *));
    return dcfg;
}

void *merge_dir_configs(apr_pool_t *p, void *basev, void *addv) {
    dir_config_t *base = (dir_config_t *) basev;
    dir_config_t *add = (dir_config_t *) addv;
    dir_config_t *res = (dir_config_t *) apr_palloc(p, sizeof(*res));

    res->mainRulesArray = apr_array_copy(p, base->mainRulesArray);
    res->checkRulesArray = apr_array_copy(p, base->checkRulesArray);
    return res;
}

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
        create_dir_config,
        merge_dir_configs,
        create_server_config, // create per-server configuration structures.,
        NULL,
        directives, // configuration directive handlers,
        defender_register_hooks // request handlers
};