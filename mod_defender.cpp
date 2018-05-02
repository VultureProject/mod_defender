/*                       _        _       __                _
 *   _ __ ___   ___   __| |    __| | ___ / _| ___ _ __   __| | ___ _ __
 *  | '_ ` _ \ / _ \ / _` |   / _` |/ _ \ |_ / _ \ '_ \ / _` |/ _ \ '__|
 *  | | | | | | (_) | (_| |  | (_| |  __/  _|  __/ | | | (_| |  __/ |
 *  |_| |_| |_|\___/ \__,_|___\__,_|\___|_|  \___|_| |_|\__,_|\___|_|
 *                       |_____|
 *  Copyright (c) 2017 Annihil
 *  Released under the GPLv3
 */
/**
 * \file     mod_defender.c
 * \authors  Annihil, Kevin Guillemot
 * \version  2.0
 * \date     28/02/2017
 * \license  GPLv3
 * \brief    mod_defender principal code and handlers
 */


/*************************/
/* Inclusion of .H files */
/*************************/

#include "mod_defender.hpp"


/********************/
/* Global variables */
/********************/

/**
 *  Configuration structure
 */
std::vector<dir_config_t *> dir_cfgs;


/***************************/
/* Definition of functions */
/***************************/

/**
 *  Custom function to ensure our RuntimeScanner get's deleted at the
 *   end of the request cycle.
 */
static apr_status_t defender_delete_runtimescanner_object(void *inPtr) {
    if (inPtr)
        delete (RuntimeScanner *) inPtr;
    return OK;
}

/**
 *  Custom function to ensure our RuleParser get's deleted at the
 *   end of the request cycle.
 */
static apr_status_t defender_delete_ruleparser_object(void *inPtr) {
    if (inPtr) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, "Unloading Defender for a loc");
        delete (RuleParser *) inPtr;
    }
    return OK;
}

/**
 *  This routine is called after the server finishes the configuration process.
 *  At this point the module may review and adjust its configuration
 *   settings in relation to one another and report any problems.
 *  On restart, this routine will be called only once, in the running server process.
 */
static int post_config(apr_pool_t *pconf, apr_pool_t *, apr_pool_t *, server_rec *s) {
    /* Figure out if we are here for the first time */
    void *init_flag = NULL;
    apr_pool_userdata_get(&init_flag, "defender-init-flag", s->process->pool);
    if (init_flag == NULL) { // first load
        apr_pool_userdata_set((const void *) 1, "defender-init-flag", apr_pool_cleanup_null, s->process->pool);
        tmpMainRules.clear();
    } else { // second (last) load
        string mainruleErr;
        unsigned int mainRuleCount = RuleParser::parseMainRules(tmpMainRules, mainruleErr);
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "Defender active on server %s: %d MainRules loaded",
                     s->server_hostname, mainRuleCount);
        if (!mainruleErr.empty())
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "MainRules error %s", mainruleErr.c_str());

        for (size_t i = 0; i < dir_cfgs.size(); i++) {
            dir_config_t *dcfg = dir_cfgs[i];
            if (dcfg->defender) {
                dcfg->parser = new RuleParser();
                apr_pool_cleanup_register(pconf, (void *) dcfg->parser, defender_delete_ruleparser_object,
                                          apr_pool_cleanup_null);
                string checkruleErr;
                dcfg->parser->parseCheckRule(dcfg->tmpCheckRules, checkruleErr);
                string basicruleErr;
                unsigned int basicRuleCount = dcfg->parser->parseBasicRules(dcfg->tmpBasicRules, basicruleErr);
                ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                             "Defender active%s on loc %s: %lu CheckRules loaded, %d BasicRules loaded",
                             (dcfg->learning ? " (learning)" : ""), dcfg->loc_path, dcfg->parser->checkRules.size(),
                             basicRuleCount);
                if (!checkruleErr.empty())
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "CheckRule parsing error %s", checkruleErr.c_str());
                if (!basicruleErr.empty())
                    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "BasicRule parsing error %s", basicruleErr.c_str());
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

/**
 *  If learning is not activated, add all mod_defender score types into env.
 *  They will be retrieved into mod_security and in mod_vulture to increment global score.
 */
static int pass_in_env(request_rec *r, RuntimeScanner *scanner) {
    // if ((scanner->block && !scanner->learning) || scanner->drop) {  // NOT USING BLOCK OR DROP IN VULTURE
    if (!scanner->learning) {
        for (const auto &match : scanner->matchScores) {
            apr_table_set(r->subprocess_env, apr_psprintf(r->pool, "defender_%s", match.first.c_str()),
                          apr_itoa(r->pool, match.second));
        }
    }

    return DECLINED;
}

/**
 *  Function used to write into error file. Used as scanner->writeLogFn attribute.
 */
static int write_log(void *thefile, const void *buf, size_t *nbytes) {
    return apr_file_write((apr_file_t *) thefile, buf, nbytes);
}

/**
 *  This routine gives our module another chance to examine the request
 *   headers and to take special action. This is the first phase whose
 *   hooks' configuration directives can appear inside the <Directory>
 *   and similar sections, because at this stage the URI has been mapped
 *   to the filename. For example this phase can be used to block evil
 *   clients, while little resources were wasted on these.
 *
 *  This is a RUN_ALL hook.
 */
static int header_parser(request_rec *r) {
    // Get the module configuration
    dir_config_t *dcfg = (dir_config_t *) ap_get_module_config(r->per_dir_config, &defender_module);

    // Stop if Defender not enabled
    if (!dcfg->defender)
        return DECLINED;

    RuntimeScanner *scanner = new RuntimeScanner(*dcfg->parser);

    // Register a C function to delete scanner at the end of the request cycle
    apr_pool_cleanup_register(r->pool, (void *) scanner, defender_delete_runtimescanner_object,
                              apr_pool_cleanup_null);

    // Reserve a temporary memory block from the request pool to store data between hooks
    defender_config_t *pDefenderConfig = (defender_config_t *) apr_palloc(r->pool, sizeof(defender_config_t));

    // Remember our application pointer for future calls
    pDefenderConfig->vpRuntimeScanner = scanner;

    // Register our config data structure for our module for retrieval later as required
    ap_set_module_config(r->request_config, &defender_module, (void *) pDefenderConfig);


    // Create our structure
    defender_t *def = NULL;
    def = (defender_t *)apr_pcalloc(r->pool, sizeof(defender_t));
    if( def == NULL ) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, 0, NULL, "Failed to allocate %lu bytes for defender_t structure.",
                                                        sizeof(defender_t));
    }

    /* Initialise C-L */
    const char *s = NULL;
    long request_content_length = -1;
    s = apr_table_get(r->headers_in, "Content-Length");
    if (s != NULL) {
        request_content_length = strtol(s, NULL, 10);
    }

    /* Figure out whether this request has a body */
    def->body_should_exist = 0;
    if (request_content_length == -1) {
        /* There's no C-L, but is chunked encoding used? */
        char *transfer_encoding = (char *)apr_table_get(r->headers_in, "Transfer-Encoding");
        if( (transfer_encoding != NULL) && (strcasecmp(transfer_encoding, "chunked") == 0) ) {
            def->body_should_exist = 1;
        }
    } else {
        /* C-L found */
        def->body_should_exist = 1;
    }


    pDefenderConfig->def = def;

    // And register a cleanup hook
    apr_pool_cleanup_register(r->pool, def, body_clear, apr_pool_cleanup_null);


    // Set method
    if (r->method_number == M_GET)
        scanner->method = METHOD_GET;
    else if (r->method_number == M_POST)
        scanner->method = METHOD_POST;
    else if (r->method_number == M_PUT)
        scanner->method = METHOD_PUT;

    // Set logger info
    scanner->pid = getpid();
    apr_os_thread_t tid = apr_os_thread_current();
    unsigned int pid_buffer_len = 16;
    char pid_buffer[pid_buffer_len];
    apr_snprintf(pid_buffer, pid_buffer_len, "%pT", &tid);
    scanner->threadId = string(pid_buffer);
    scanner->connectionId = r->connection->id;
    scanner->clientIp = r->useragent_ip;
    scanner->requestedHost = r->hostname;
    scanner->serverHostname = r->server->server_hostname;
    scanner->fullUri = r->unparsed_uri;
    scanner->protocol = r->protocol;
    ap_version_t vers;
    ap_get_server_revision(&vers);
    scanner->softwareVersion = std::to_string(vers.major) + "." + std::to_string(vers.minor) + "." +
                               std::to_string(vers.patch);
    scanner->logLevel = static_cast<LOG_LVL>(r->log->level);
    if (scanner->logLevel >= APLOG_DEBUG)
        scanner->logLevel = LOG_LVL_DEBUG;
    scanner->writeLogFn = write_log;
    scanner->errorLogFile = r->server->error_log;
    scanner->learningLogFile = dcfg->matchlog_file;
    scanner->learningJSONLogFile = dcfg->jsonmatchlog_file;
    scanner->learning = dcfg->learning;
    scanner->extensiveLearning = dcfg->extensive;

    // Set runtime modifiers
    scanner->libinjSQL = dcfg->libinjection_sql;
    scanner->libinjXSS = dcfg->libinjection_xss;
    scanner->bodyLimit = dcfg->requestBodyLimit;

    // Set the uri path
    scanner->setUri(r->parsed_uri.path);

    // Pass every HTTP header received
    const apr_array_header_t *headerFields = apr_table_elts(r->headers_in);
    apr_table_entry_t *headerEntry = (apr_table_entry_t *) headerFields->elts;
    for (int i = 0; i < headerFields->nelts; i++)
        scanner->addHeader(headerEntry[i].key, headerEntry[i].val);

    // Pass GET parameters
    apr_table_t *getTable = NULL;
    ap_args_to_table(r, &getTable);
    const apr_array_header_t *getParams = apr_table_elts(getTable);
    apr_table_entry_t *getParam = (apr_table_entry_t *) getParams->elts;
    for (int i = 0; i < getParams->nelts; i++)
        scanner->addGETParameter(getParam[i].key, getParam[i].val);

    // Run scanner
    int ret = scanner->processHeaders();

    if (dcfg->useenv)
        ret = pass_in_env(r, scanner);

    return ret;
}

/**
 *  This routine is called to perform any module-specific fixing of header
 *   fields, et cetera.  It is invoked just before any content-handler.
 *
 *  This is a RUN_ALL HOOK.
 */
static int fixups(request_rec *r) {

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Fixups beginning.");

    dir_config_t *dcfg = (dir_config_t *) ap_get_module_config(r->per_dir_config, &defender_module);
    // Stop if Defender not enabled
    if (!dcfg->defender)
        return DECLINED;

    // Stop if this is not the main request
    if (r->main != NULL || r->prev != NULL)
        return DECLINED;

    // Process only if POST / PUT request
    if (r->method_number != M_POST && r->method_number != M_PUT)
        return DECLINED;

    defender_config_t *defc = (defender_config_t *) ap_get_module_config(r->request_config, &defender_module);
    RuntimeScanner *scanner = defc->vpRuntimeScanner;
    defender_t *def = defc->def;

    /* Has this phase been completed already? */
    if( def->fixups_done ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Internal Error: Attempted to process the request body more than once.");
        return DECLINED;
    }
    def->fixups_done = 1;

    if (scanner->contentLengthProvided && scanner->contentLength == 0)
        return scanner->processBody();

    if (scanner->contentType == CONTENT_TYPE_UNSUPPORTED)
        return scanner->processBody();

    if (scanner->bodyLimitExceeded)
        return scanner->processBody();

    if (!scanner->contentLengthProvided)
        return HTTP_NOT_IMPLEMENTED;

    if (scanner->transferEncodingProvided /*&& scanner->transferEncoding == TRANSFER_ENCODING_UNSUPPORTED*/)
        return HTTP_NOT_IMPLEMENTED;

    if( scanner->contentLength >= MAX_BB_SIZE ) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Content-Length '%lu' is greater than process limit : %d",
                      scanner->contentLength, MAX_BB_SIZE);
        return DECLINED;
    }

    // Retrieve the body
    // Pre-allocate necessary bytes
    scanner->body.reserve(scanner->contentLength);

    /* Read body */
    int ret;
    char *error_msg = NULL;
    ret = read_request_body(def, &error_msg, r, dcfg->requestBodyLimit);
    if( ret < 0 ) {
        switch( ret ) {
            case -1 :
                if( error_msg != NULL ) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", error_msg);
                }
                return HTTP_INTERNAL_SERVER_ERROR;
            case -4 : /* Timeout. */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", error_msg);
                r->connection->keepalive = AP_CONN_CLOSE;
                return HTTP_REQUEST_TIME_OUT;
            case -5 : /* Request body limit reached. */
                r->connection->keepalive = AP_CONN_CLOSE;
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s. Deny with code (%d)", error_msg, HTTP_REQUEST_ENTITY_TOO_LARGE);
                return HTTP_REQUEST_ENTITY_TOO_LARGE;
            case -6 : /* EOF when reading request body. */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", error_msg);
                r->connection->keepalive = AP_CONN_CLOSE;
                return HTTP_BAD_REQUEST;
            case -7 : /* Partial recieved */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", error_msg);
                r->connection->keepalive = AP_CONN_CLOSE;
                return HTTP_BAD_REQUEST;
            default :
                /* allow through */
                break;
        }
        def->body_error = 1;
        def->body_error_msg = error_msg;
    }

    scanner->body.append(def->stream_input_data, def->stream_input_length);

//    cerr << "[pid " << getpid() << "] read " << scanner->body.length() << " bytes, ";
//    cerr << "content-length: " << scanner->contentLength << endl;
//    cerr << "body: " << scanner->body << endl;

    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Brigades processing completed. Process body.");

    // Run scanner
    ret = scanner->processBody();

    if (dcfg->useenv)
        ret = pass_in_env(r, scanner);

//    cerr << "[pid " << getpid() << "] body (" << scanner->body.length() << ") scanned" << endl;

    /* Add the input filter. */
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Insert_filter: Adding input forwarding filter %s(r %pp).",
            (((r->main != NULL)||(r->prev != NULL)) ? "for subrequest " : ""), r);

    ap_add_input_filter("DEFENDER_IN", NULL, r, r->connection);

    return ret;
}

/**
 *  This request filter will forward the previously stored
 *   request body further down the chain (most likely to the
 *   processing module).
 */
apr_status_t input_filter(ap_filter_t *f, apr_bucket_brigade *bb_out,
                          ap_input_mode_t mode, apr_read_type_e block, apr_off_t nbytes)
{
    request_rec *r = f->r;
    apr_bucket *bucket = NULL;
    apr_status_t rc;
    char *error_msg = NULL;
    chunk_t *chunk = NULL;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Defender input filter begins.");

    defender_config_t *config = (defender_config_t *) ap_get_module_config(r->request_config, &defender_module);
    defender_t *def = config->def;

    // Stop if this is not the main request
    if (r->main != NULL || r->prev != NULL)
        return DECLINED;

    // Process only if POST / PUT request
    if (r->method_number != M_POST && r->method_number != M_PUT)
        return DECLINED;

    if( config->def == NULL ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Internal error in input filter: structure is null !");
        ap_remove_input_filter(f);
        return APR_EGENERAL;
    }

    if( (def->status == IF_STATUS_COMPLETE) || (def->status == IF_STATUS_NONE) ) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Input filter: Input forwarding already complete, "
                "skipping (f %pp, r %pp).", f, f->r);
        ap_remove_input_filter(f);
        return ap_get_brigade(f->next, bb_out, mode, block, nbytes);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Input filter: Forwarding input: mode=%d, block=%d, nbytes=%"
            APR_OFF_T_FMT " (f %pp, r %pp).", mode, block, nbytes, f, f->r);

    if( def->started_forwarding == 0) {
        def->started_forwarding = 1;
        rc = body_retrieve_start(def, &error_msg, r);
        if( rc == -1 ) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s", error_msg);
            return APR_EGENERAL;
        }
    }

    rc = body_retrieve(def, &chunk, (unsigned int)nbytes, &error_msg, r);
    if (rc == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s", error_msg);
        return APR_EGENERAL;
    }

    if( chunk && def->stream_changed == 0 ) {
        /* Copy the data we received in the chunk */
        bucket = apr_bucket_heap_create(chunk->data, chunk->length, NULL, r->connection->bucket_alloc);

        if( bucket == NULL ) {
            /* FIXME : Correct log level ? */
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Input filter: Heap bucket is NULL.");
            return APR_EGENERAL;
        }
        /* Append the bucket at the end of the brigade */
        APR_BRIGADE_INSERT_TAIL(bb_out, bucket);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Input filter: Forwarded %" APR_SIZE_T_FMT " bytes.", chunk->length);

    } else if( def->stream_input_data != NULL ) {

        def->stream_changed = 0;

        bucket = apr_bucket_heap_create(def->stream_input_data, def->stream_input_length, NULL,
                                        f->r->connection->bucket_alloc);

        if(def->stream_input_data != NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Input filter: Freeing stream input data.");
            free(def->stream_input_data);
            def->stream_input_data = NULL;
        }

        if( bucket == NULL ) {
            /* FIXME : Correct log level ? */
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Input filter: Heap bucket is NULL.");
            return APR_EGENERAL;
        }
        APR_BRIGADE_INSERT_TAIL(bb_out, bucket);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Input filter: Forwarded %" APR_SIZE_T_FMT " bytes.",
                      def->stream_input_length);
    }

    if( rc == 0 ) {
        if( def->if_seen_eos ) {
            bucket = apr_bucket_eos_create(f->r->connection->bucket_alloc);
            if (bucket == NULL) return APR_EGENERAL;
            APR_BRIGADE_INSERT_TAIL(bb_out, bucket);

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Input filter: Sent EOS.");
        }

        /* We're done */
        def->status = IF_STATUS_COMPLETE;
        ap_remove_input_filter(f);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Input filter: Input forwarding complete.");
    }

    return APR_SUCCESS;
}

/**
 *  Apache callback to register our hooks.
 */
static void defender_register_hooks(apr_pool_t *) {
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    static const char *const aszSucc[] = {"mod_security2.c", NULL};
    ap_hook_header_parser(header_parser, NULL, aszSucc, APR_HOOK_REALLY_FIRST - 20);
    /* We must intervene BEFORE mod_security */
    ap_hook_fixups(fixups, NULL, aszSucc, APR_HOOK_REALLY_FIRST - 20);
    /* Insert input filter to give back data */
    ap_register_input_filter("DEFENDER_IN", input_filter, NULL, AP_FTYPE_CONTENT_SET);
}

/**
 *  This function is called when the "MatchLog" configuration directive is parsed.
 */
static const char *set_matchlog_path(cmd_parms *cmd, void *cfg, const char *arg) {
    dir_config_t *dcfg = (dir_config_t *) cfg;

    char *matchlog_path = apr_pstrdup(cmd->pool, arg);

    if (matchlog_path[0] == '|') {
        const char *pipe_name = matchlog_path + 1;
        piped_log *pipe_log;

        pipe_log = ap_open_piped_log(cmd->pool, pipe_name);
        if (pipe_log == NULL)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the match log pipe: %s", pipe_name);
        dcfg->matchlog_file = ap_piped_log_write_fd(pipe_log);
    } else {
        const char *file_name = ap_server_root_relative(cmd->pool, matchlog_path);
        apr_status_t rc;

        rc = apr_file_open(&dcfg->matchlog_file, file_name,
                           APR_WRITE | APR_APPEND | APR_CREATE | APR_BINARY,
                           APR_UREAD | APR_UWRITE | APR_GREAD, cmd->pool);

        if (rc != APR_SUCCESS)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the match log file: %s", file_name);
    }

    return NULL; // success
}

/**
 *  This function is called when the "JSONMatchLog" configuration directive is parsed.
 */
static const char *set_jsonerrorlog_path(cmd_parms *cmd, void *cfg, const char *arg) {
    dir_config_t *dcfg = (dir_config_t *) cfg;

    char *jsonmatchlog_path = apr_pstrdup(cmd->pool, arg);

    if (jsonmatchlog_path[0] == '|') {
        const char *pipe_name = jsonmatchlog_path + 1;
        piped_log *pipe_log;

        pipe_log = ap_open_piped_log(cmd->pool, pipe_name);
        if (pipe_log == NULL)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the json match log pipe: %s", pipe_name);
        dcfg->jsonmatchlog_file = ap_piped_log_write_fd(pipe_log);
    } else {
        const char *file_name = ap_server_root_relative(cmd->pool, jsonmatchlog_path);
        apr_status_t rc;

        rc = apr_file_open(&dcfg->jsonmatchlog_file, file_name,
                           APR_WRITE | APR_APPEND | APR_CREATE | APR_BINARY,
                           APR_UREAD | APR_UWRITE | APR_GREAD, cmd->pool);

        if (rc != APR_SUCCESS)
            return apr_psprintf(cmd->pool, "mod_defender: Failed to open the json match log file: %s", file_name);
    }

    return NULL; // success
}

/**
 *  This function is called when the "RequestBodyLimit" configuration directive is parsed.
 */
static const char *set_request_body_limit(cmd_parms *cmd, void *cfg, const char *arg) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    unsigned long limit = strtoul(arg, NULL, 10);
    if (limit <= 0)
        return apr_psprintf(cmd->pool, "mod_defender: Invalid value for RequestBodyLimit: %s", arg);
    dcfg->requestBodyLimit = limit;
    return NULL;
}

/**
 * This function is called when the "LibinjectionSQL" configuration directive is parsed.
 */
static const char *set_libinjection_sql_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->libinjection_sql = (bool) flag;
    return NULL;
}

/**
 * This function is called when the "LibinjectionXSS" configuration directive is parsed.
 */
static const char *set_libinjection_xss_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->libinjection_xss = (bool) flag;
    return NULL;
}

/**
 * This function is called when the "Defender" configuration directive is parsed.
 */
static const char *set_defender_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->defender = (bool) flag;
    return NULL;
}

/**
 * This function is called when the "LearningMode" configuration directive is parsed.
 */
static const char *set_learning_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->learning = (bool) flag;
    return NULL;
}

/**
 * This function is called when the "ExtensiveLog" configuration directive is parsed.
 */
static const char *set_extensive_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->extensive = (bool) flag;
    return NULL;
}

/**
 * This function is called when the "UseEnv" configuration directive is parsed.
 */
static const char *set_useenv_flag(cmd_parms *, void *cfg, int flag) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->useenv = (bool) flag;
    return NULL;
}

/**
 * This function is called when the "MainRule" configuration directives are parsed.
 */
static const char *set_mainrules(cmd_parms *, void *, const char *line) {
    tmpMainRules.push_back(string(line));
    return NULL;
}

/**
 * This function is called when the "CheckRule" configuration directives are parsed.
 */
static const char *set_checkrules(cmd_parms *, void *cfg, const char *arg1, const char *arg2) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->tmpCheckRules.push_back(std::make_pair(string(arg1), string(arg2)));
    return NULL;
}

/**
 * This function is called when the "BasicRule" configuration directives are parsed.
 */
static const char *set_basicrules(cmd_parms *, void *cfg, const char *line) {
    dir_config_t *dcfg = (dir_config_t *) cfg;
    dcfg->tmpBasicRules.push_back(string(line));
    return NULL;
}

/**
 * A declaration of the configuration directives that are supported by this module.
 */
static const command_rec directives[] = {
    {"Defender",         (cmd_func) set_defender_flag,         NULL, ACCESS_CONF, FLAG,     "Defender toggle"},
    {"MainRule",         (cmd_func) set_mainrules,             NULL, RSRC_CONF,   RAW_ARGS, "Match directive"},
    {"CheckRule",        (cmd_func) set_checkrules,            NULL, ACCESS_CONF, TAKE2,    "Score directive"},
    {"BasicRule",        (cmd_func) set_basicrules,            NULL, ACCESS_CONF, RAW_ARGS, "Whitelist directive"},
    {"MatchLog",         (cmd_func) set_matchlog_path,         NULL, ACCESS_CONF, TAKE1,    "Path to the match log"},
    {"JSONMatchLog",     (cmd_func) set_jsonerrorlog_path,     NULL, ACCESS_CONF, TAKE1,    "Path to the JSON match log"},
    {"RequestBodyLimit", (cmd_func) set_request_body_limit,    NULL, ACCESS_CONF, TAKE1,    "Set Request Body Limit"},
    {"LearningMode",     (cmd_func) set_learning_flag,         NULL, ACCESS_CONF, FLAG,     "Learning mode toggle"},
    {"ExtensiveLog",     (cmd_func) set_extensive_flag,        NULL, ACCESS_CONF, FLAG,     "Extensive log toggle"},
    {"LibinjectionSQL",  (cmd_func) set_libinjection_sql_flag, NULL, ACCESS_CONF, FLAG,     "Libinjection SQL toggle"},
    {"LibinjectionXSS",  (cmd_func) set_libinjection_xss_flag, NULL, ACCESS_CONF, FLAG,     "Libinjection XSS toggle"},
    {"UseEnv",           (cmd_func) set_useenv_flag,           NULL, ACCESS_CONF, FLAG,     "UseEnv toggle"},
    {NULL,               NULL,                                 NULL, RSRC_CONF,   TAKE1,    NULL} /* End by an empty */
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
#if defined(AP_MODULE_HAS_FLAGS)
        ,AP_MODULE_FLAG_ALWAYS_MERGE /* flags */
#endif
};