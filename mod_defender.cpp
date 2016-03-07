#include "mod_defender.hpp"
#include "CApplication.hpp"
#include "NxParser.h"

<<<<<<< HEAD
<<<<<<< HEAD
=======
/*
 * This module
 */
=======
>>>>>>> fd0f819... scoring system
extern module AP_MODULE_DECLARE_DATA defender_module;

>>>>>>> 5eee329... naxsi core rules parser
/* Custom definition to hold any configuration data we may need.
   At this stage we just use it to keep a copy of the CApplication
   object pointer. Later we will add more when we need specific custom
   configuration information. */
typedef struct {
<<<<<<< HEAD
    void* vpCApplication;
}
DEFENDERCONFIG_t;
EXTERN_C_BLOCK_END

/* Forward reference to our custom function to save the DEFENDERCONFIG_t* 
   configuration pointer with Apache. */
//EXTERN_C_FUNC
//void defender_register_config_ptr(request_rec* inpRequest, DEFENDERCONFIG_t* inpFooConfig);

/* Forward reference to our custom function to get the DEFENDERCONFIG_t* 
   configuration pointer when we need it. */
EXTERN_C_FUNC
DEFENDERCONFIG_t* defender_get_config_ptr(request_rec* inpRequest);

/* Custom function to ensure our CApplication get's deleted at the
   end of the request cycle. */
EXTERN_C_FUNC
apr_status_t defender_delete_capplication_object(void* inPtr) {
=======
    void *vpCApplication;
} defender_config_t;

typedef struct {
    apr_array_header_t *mainRulesTable;
    apr_array_header_t *checkRulesTable;
} dir_config_t;

/* Custom function to ensure our CApplication get's deleted at the
   end of the request cycle. */
apr_status_t defender_delete_capplication_object(void *inPtr) {
>>>>>>> 5eee329... naxsi core rules parser
    if (inPtr)
        delete ( CApplication*) inPtr;

    return OK;
}

<<<<<<< HEAD
/* Our custom handler (content generator) 
 */
EXTERN_C_FUNC
int defender_handler(request_rec* inpRequest) {
    /* Create an instance of our application. */
    CApplication* pApp = new CApplication(inpRequest);
=======
/* Custom function to retrieve our defender_config_t* pointer previously
   registered with Apache on this request cycle. */
defender_config_t *defender_get_config_ptr(request_rec *inpRequest) {
    defender_config_t *pReturnValue = NULL;

    if (inpRequest != NULL) {
        pReturnValue = (defender_config_t *) ap_get_module_config(inpRequest->request_config, &defender_module);
    }

    return pReturnValue;
}

/* Our custom handler
 */
int defender_handler(request_rec *r) {
    // Get the module configuration
    server_config_t *scfg = (server_config_t *) ap_get_module_config(r->server->module_config, &defender_module);
    dir_config_t *dcfg = (dir_config_t *) ap_get_module_config(r->per_dir_config, &defender_module);

//    for (int i = 0; i < dcfg->mainRulesTable->nelts; i++) {
//        const char *s = ((const char **) dcfg->mainRulesTable->elts)[i];
//        fprintf(stderr, "%d: %s\n", i, s);
//    }
    if (scfg->mainRules.size() == 0)
        scfg->mainRules = NxParser::parseMainRules(r->server->process->pool, dcfg->mainRulesTable);
    if (scfg->checkRules.size() == 0)
        scfg->checkRules = NxParser::parseCheckRules(dcfg->checkRulesTable);

//    for (const main_rule_t &rule : scfg->mainRules) {
//        cerr << rule.IsMatchPaternRx << " ";
//        const char* matchPaternStr;
//        if (rule.IsMatchPaternRx)
//            cerr << "<regex> ";
//        else
//            cerr << rule.matchPaternStr << " ";
//
//        for (const pair<const char*, int> &sc : rule.scores)
//            cerr << sc.first << " " << sc.second << " ";
//
//        cerr << rule.msg << " ";
//        cerr << rule.matchZone << " ";
//        cerr << rule.id << " ";
//        cerr << endl;
//    }

//    for (const auto& match : scfg->checkRules) {
//        cerr <<  match.first << " ";
//        cerr <<  match.second.comparator << " ";
//        cerr <<  match.second.limit << " ";
//        cerr <<  match.second.action << " ";
//        cerr << endl;
//    }

    /* Create an instance of our application. */
<<<<<<< HEAD
    CApplication *pApp = new CApplication(r, scfg->errorlog_fd, scfg->rules);
>>>>>>> 5eee329... naxsi core rules parser
=======
    CApplication *pApp = new CApplication(r, scfg);
>>>>>>> fd0f819... scoring system

    if (pApp == nullptr)
        return HTTP_SERVICE_UNAVAILABLE;

    /* Register a C function to delete pApp
       at the end of the request cycle. */
<<<<<<< HEAD
<<<<<<< HEAD
    apr_pool_cleanup_register(
            inpRequest->pool,
            (void*) pApp,
            defender_delete_capplication_object,
            apr_pool_cleanup_null
            );

    /* Reserve a temporary memory block from the
       request pool to store data between hooks. */
    DEFENDERCONFIG_t* pFooConfig =
            (DEFENDERCONFIG_t*) apr_palloc(
            inpRequest->pool, sizeof ( DEFENDERCONFIG_t));
=======
    apr_pool_cleanup_register(r->pool, (void*)pApp, defender_delete_capplication_object, apr_pool_cleanup_null);
=======
    apr_pool_cleanup_register(r->pool, (void *) pApp, defender_delete_capplication_object, apr_pool_cleanup_null);
>>>>>>> 90f8163... per-directory config handler

    /* Reserve a temporary memory block from the
       request pool to store data between hooks. */
    defender_config_t *pDefenderConfig = (defender_config_t *) apr_palloc(r->pool, sizeof(defender_config_t));
>>>>>>> 5eee329... naxsi core rules parser

    /* Remember our application pointer for future calls. */
    pFooConfig->vpCApplication = (void*) pApp;

<<<<<<< HEAD
    /* Register our config data structure for our module. */
//    defender_register_config_ptr(inpRequest, pFooConfig);
=======
    /* Register our config data structure for our module for retrieval later as required */
    ap_set_module_config(r->request_config, &defender_module, (void *) pDefenderConfig);
>>>>>>> 5eee329... naxsi core rules parser

    /* Run our application handler. */
    return pApp->RunHandler();
}

/* Apache callback to register our hooks.
 */
<<<<<<< HEAD
EXTERN_C_FUNC
void defender_hooks(apr_pool_t* inpPool) {
    ap_hook_handler(defender_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Our standard module definition.
 */
EXTERN_C_BLOCK_BEGIN
module AP_MODULE_DECLARE_DATA defender_module ={
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    defender_hooks
};

EXTERN_C_BLOCK_END

/* Custom function to register our DEFENDERCONFIG_t* pointer with Apache
   for retrieval later as required. */
EXTERN_C_FUNC
void defender_register_capplication_ptr(request_rec* inpRequest, DEFENDERCONFIG_t* inpPtr) {
    ap_set_module_config(inpRequest->request_config, &defender_module, (void*) inpPtr);
}

/* Custom function to retrieve our DEFENDERCONFIG_t* pointer previously
   registered with Apache on this request cycle. */
EXTERN_C_FUNC
DEFENDERCONFIG_t* defender_get_capplication_ptr(request_rec* inpRequest) {
    DEFENDERCONFIG_t* pReturnValue = NULL;
=======
void defender_register_hooks(apr_pool_t *pool) {
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
    *(const char **) apr_array_push(scfg->mainRulesTable) = apr_pstrdup(scfg->mainRulesTable->pool, arg);
//        return apr_psprintf(cmd->pool, "mod_defender: MainRule variable %s was undefined", arg);
    return NULL;
}

const char *set_nx_check_rules(cmd_parms *cmd, void *sconf_, const char *arg1, const char *arg2) {
    dir_config_t *scfg = (dir_config_t *) sconf_;
    *(const char **) apr_array_push(scfg->checkRulesTable) = apr_pstrdup(scfg->checkRulesTable->pool, arg1);
    *(const char **) apr_array_push(scfg->checkRulesTable) = apr_pstrdup(scfg->checkRulesTable->pool, arg2);
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
                                                                  ACCESS_CONF,             ITERATE,  "NxCoreRules directives"},
        {"LearningMode",     (cmd_func) skip_directive,    NULL, RSRC_CONF | ACCESS_CONF, TAKE1, ""},
        {"SecRules",  (cmd_func) skip_directive,    NULL, RSRC_CONF | ACCESS_CONF, TAKE1,  ""},
        {"CheckRule",         (cmd_func) set_nx_check_rules,    NULL, RSRC_CONF | ACCESS_CONF, ITERATE2,    "Nx score directives"},
        {"BasicRule",         (cmd_func) skip_directive,    NULL, RSRC_CONF | ACCESS_CONF, ITERATE,    "Nx score directives"},
        {NULL}
};

/**
 * Creates the per-server configuration records.
 */
void *create_server_config(apr_pool_t *p, server_rec *s) {
    // allocate space for the configuration structure from the provided pool p.
<<<<<<< HEAD
    srvcfg = (server_config_t *) apr_pcalloc(p, sizeof(server_config_t));
>>>>>>> 5eee329... naxsi core rules parser

    if (inpRequest != NULL) {
        pReturnValue =
                (DEFENDERCONFIG_t*) ap_get_module_config(
                inpRequest->request_config, &defender_module);
    }
=======
    server_config_t *scfg = (server_config_t *) apr_pcalloc(p, sizeof(server_config_t));

    // return the new server configuration structure.
    return scfg;
}

static void *create_dir_config(apr_pool_t *p, char *dummy) {
    dir_config_t *dcfg = (dir_config_t *) apr_palloc(p, sizeof(*dcfg));
    dcfg->mainRulesTable = apr_array_make(p, 209, sizeof(const char *));
    dcfg->checkRulesTable = apr_array_make(p, 5, sizeof(const char *));
    return dcfg;
}

static void *merge_dir_configs(apr_pool_t *p, void *basev, void *addv) {
    dir_config_t *base = (dir_config_t *) basev;
    dir_config_t *add = (dir_config_t *) addv;
    dir_config_t *res = (dir_config_t *) apr_palloc(p, sizeof(*res));

    res->mainRulesTable = apr_array_copy(p, base->mainRulesTable);
    res->checkRulesTable = apr_array_copy(p, base->checkRulesTable);
    return res;
}
>>>>>>> 90f8163... per-directory config handler

<<<<<<< HEAD
    return pReturnValue;
}
=======
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
>>>>>>> 5eee329... naxsi core rules parser
