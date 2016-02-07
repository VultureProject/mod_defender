#include "mod_defender.hpp"
#include "CApplication.hpp"

/* Custom definition to hold any configuration data we may need.
   At this stage we just use it to keep a copy of the CApplication
   object pointer. Later we will add more when we need specific custom
   configuration information. */
EXTERN_C_BLOCK_BEGIN
typedef struct {
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
    if (inPtr)
        delete ( CApplication*) inPtr;

    return OK;
}

/* Our custom handler (content generator) 
 */
EXTERN_C_FUNC
int defender_handler(request_rec* inpRequest) {
    /* Create an instance of our application. */
    CApplication* pApp = new CApplication(inpRequest);

    if (pApp == NULL)
        return HTTP_SERVICE_UNAVAILABLE;

    /* Register a C function to delete pApp
       at the end of the request cycle. */
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

    /* Remember our application pointer for future calls. */
    pFooConfig->vpCApplication = (void*) pApp;

    /* Register our config data structure for our module. */
//    defender_register_config_ptr(inpRequest, pFooConfig);

    /* Run our application handler. */
    return pApp->RunHandler();
}

/* Apache callback to register our hooks.
 */
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

    if (inpRequest != NULL) {
        pReturnValue =
                (DEFENDERCONFIG_t*) ap_get_module_config(
                inpRequest->request_config, &defender_module);
    }

    return pReturnValue;
}