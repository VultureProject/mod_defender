//
// Created by kguillemot on 30/04/18.
//

#include <http_request.h>
#include <http_protocol.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_strings.h>
#include <util_script.h>
#include "RuntimeScanner.hpp"
#include "mod_defender.hpp"

// Extra Apache 2.4+ C++ module declaration
#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(defender);
#endif


static char *get_apr_error(apr_pool_t *p, apr_status_t rc) {
    char *text = (char *) apr_pcalloc(p, 201);
    if (text == NULL) return NULL;
    apr_strerror(rc, text, 200);
    return text;
}

/**
 * Initialize all variables used to forward request body
 */
apr_status_t body_retrieve_start(defender_t *def, char **error_msg, request_rec *r) {
    *error_msg = NULL;

    def->body_chunk_position = 0;
    def->body_chunk_offset = 0;

    def->body_chunk = (chunk_t *)apr_pcalloc(def->body_pool, sizeof(chunk_t));
    if( def->body_chunk == NULL ) {
        *error_msg = apr_psprintf(r->pool, "Failed to allocate %lu bytes for request body disk chunk.",
                                  (unsigned long)sizeof(chunk_t));
        return -1;
    }

    return 1;
}

/**
 * Returns one chunk of request body data. It stores a NULL
 * in the chunk pointer when there is no data to return. The
 * return code is 1 if more calls can be made to retrieve more
 * data, 0 if there is no more data to retrieve, or -1 on error.
 *
 * The caller can limit the amount of data returned by providing
 * a non-negative value in nbytes.
 */
apr_status_t body_retrieve(defender_t *def, chunk_t **chunk, long int nbytes, char **error_msg, request_rec *r)
{
    chunk_t **chunks;
    *error_msg = NULL;

    if (chunk == NULL) {
        *error_msg = apr_pstrdup(r->pool, "Internal error, retrieving request body chunk.");
        return -1;
    }
    *chunk = NULL;

    /* Are there any chunks left? */
    if (def->body_chunk_position >= def->body_chunks->nelts) {
        /* No more chunks. */
        return 0;
    }

    /* We always respond with the same chunk, just different information in it. */
    *chunk = def->body_chunk;

    /* Advance to the current chunk and position on the
     * next byte we need to send.
     */
    chunks = (chunk_t **)def->body_chunks->elts;
    def->body_chunk->data = chunks[def->body_chunk_position]->data + def->body_chunk_offset;

    if (nbytes < 0) {
        /* Send what's left in this chunk as there is no limit on the size. */
        def->body_chunk->length = chunks[def->body_chunk_position]->length;
        def->body_chunk_position++;
        def->body_chunk_offset = 0;
    } else {
        /* We have a limit we must obey. */

        if (chunks[def->body_chunk_position]->length - def->body_chunk_offset <= (unsigned int)nbytes)
        {
            /* If what's left in our chunk is less than the limit
             * then send it all back.
             */
            def->body_chunk->length = chunks[def->body_chunk_position]->length - def->body_chunk_offset;
            def->body_chunk_position++;
            def->body_chunk_offset = 0;
        } else {
            /* If we have more data in our chunk, send the
             * maximum bytes we can (nbytes).
             */
            def->body_chunk->length = nbytes;
            def->body_chunk_offset += nbytes;
        }
    }

    /* If we've advanced beyond our last chunk then
     * we have no more data to send.
     */
    if (def->body_chunk_position >= def->body_chunks->nelts) {
        return 0; /* No more chunks. */
    }

    /* More data available. */
    return 1;
}

/**
 * Prepare to accept the request body (part 2).
 */
static apr_status_t body_start_init(defender_t *def, char **error_msg, request_rec *r) {
    *error_msg = NULL;

    /* Prepare to store request body in memory. */

    def->body_chunks = apr_array_make(def->body_pool, 32, sizeof(chunk_t *));
    if( def->body_chunks == NULL ) {
        *error_msg = apr_pstrdup(r->pool, "Body start init: Failed to prepare in-memory storage.");
        return -1;
    }

    return 1;
}

/**
 * Prepare to accept the request body (part 1).
 */
apr_status_t body_start(defender_t *def, char **error_msg, request_rec *r) {
    *error_msg = NULL;
    def->body_length = 0;
    def->stream_input_length = 0;

    /* Create a separate memory pool that will be used
     * to allocate structures from (not data, which is allocated
     * via malloc).
     */
    apr_pool_create(&def->body_pool, NULL);

    return body_start_init(def, error_msg, r);
}

/**
 *
 * Store data into msr->stream_input_data to
 */
apr_status_t body_to_stream(defender_t *def, const char *buffer, int buflen, char **error_msg, request_rec *r) {
    char *stream_input_body = NULL;
    char *data = NULL;
    int first_pkt = 0;

    if(def->stream_input_data == NULL)  {
        def->stream_input_data = (char *)calloc(sizeof(char), def->stream_input_length + 1);
        first_pkt = 1;
    }
    else {

        data = (char *)malloc(def->stream_input_length + 1 - buflen);

        if(data == NULL) {
            *error_msg = apr_psprintf(r->pool, "Unable to allocate memory to hold request body on stream. Asked for %"
                                               APR_SIZE_T_FMT " bytes.", def->stream_input_length + 1 - buflen);
            return -1;
        }

        memset(data, 0, def->stream_input_length + 1 - buflen);
        memcpy(data, def->stream_input_data, def->stream_input_length - buflen);

        stream_input_body = (char *)realloc(def->stream_input_data, def->stream_input_length + 1);

        def->stream_input_data = (char *)stream_input_body;
    }

    if (def->stream_input_data == NULL) {
        if(data)    {
            free(data);
            data = NULL;
        }
        *error_msg = apr_psprintf(r->pool, "Unable to allocate memory to hold request body on stream. Asked for %"
                                          APR_SIZE_T_FMT " bytes.", def->stream_input_length + 1);
        return -1;
    }

    memset(def->stream_input_data, 0, def->stream_input_length+1);

    if(first_pkt)   {
        memcpy(def->stream_input_data, buffer, def->stream_input_length);
    } else {
        memcpy(def->stream_input_data, data, def->stream_input_length - buflen);
        memcpy(def->stream_input_data+(def->stream_input_length - buflen), buffer, buflen);
    }

    if(data)    {
        free(data);
        data = NULL;
    }

    return 1;
}

/**
 * Stores one chunk of request body data in memory.
 */
static apr_status_t body_store_memory(defender_t *def, const char *data, apr_size_t length, char **error_msg,
                                      request_rec *r) {

    *error_msg = NULL;

    /* If we're here that means we are not over the
     * request body in-memory limit yet.
     */
    {
        unsigned long int bucket_offset, bucket_left;

        bucket_offset = 0;
        bucket_left = length;

        /* Although we store the request body in chunks we don't
         * want to use the same chunk sizes as the incoming memory
         * buffers. They are often of very small sizes and that
         * would make us waste a lot of memory. That's why we
         * use our own chunks of CHUNK_CAPACITY sizes.
         */

        /* Loop until we empty this bucket into our chunks. */
        while(bucket_left > 0) {
            /* Allocate a new chunk if we have to. */
            if (def->body_chunk_current == NULL) {
                def->body_chunk_current = (chunk_t *)apr_pcalloc(def->body_pool, sizeof(chunk_t));
                if( def->body_chunk_current == NULL ) {
                    *error_msg = apr_psprintf(r->pool, "Input filter: Failed to allocate %lu bytes "
                            "for request body chunk.", (unsigned long)sizeof(chunk_t));
                    return -1;
                }

                def->body_chunk_current->data = (char *)malloc(CHUNK_CAPACITY);
                if( def->body_chunk_current->data == NULL ) {
                    *error_msg = apr_psprintf(r->pool, "Input filter: Failed to allocate %d bytes "
                            "for request body chunk data.", CHUNK_CAPACITY);
                    return -1;
                }

                def->body_chunk_current->length = 0;
                def->body_chunk_current->is_permanent = 1;

                *(const chunk_t **)apr_array_push(def->body_chunks) = def->body_chunk_current;
            }

            if( bucket_left < (CHUNK_CAPACITY - def->body_chunk_current->length) ) {
                /* There's enough space in the current chunk. */
                memcpy(def->body_chunk_current->data +
                       def->body_chunk_current->length, data + bucket_offset, bucket_left);
                def->body_chunk_current->length += bucket_left;
                bucket_left = 0;
            } else {
                /* Fill the existing chunk. */
                unsigned long int copy_length = CHUNK_CAPACITY - def->body_chunk_current->length;

                memcpy(def->body_chunk_current->data + def->body_chunk_current->length, data + bucket_offset, copy_length);
                bucket_offset += copy_length;
                bucket_left -= copy_length;
                def->body_chunk_current->length += copy_length;

                /* We're done with this chunk. Setting the pointer
                 * to NULL is going to force a new chunk to be allocated
                 * on the next go.
                 */
                def->body_chunk_current = NULL;
            }
        }
    }

    return 1;
}

/**
 * Replace a bunch of chunks holding a request body with a single large chunk.
 */
static apr_status_t body_end_raw(defender_t *def, char **error_msg, request_rec *r) {
    chunk_t **chunks, *one_chunk;
    char *d;
    int i, sofar;

    *error_msg = NULL;

    /* Allocate a buffer large enough to hold the request body. */

    if( def->body_length + 1 == 0 ) {
        *error_msg = apr_psprintf(r->pool, "Internal error, request body length will overflow: %" APR_SIZE_T_FMT,
                                            def->body_length);
        return -1;
    }

    def->body_buffer = (char *)malloc(def->body_length + 1);
    if( def->body_buffer == NULL ) {
        *error_msg = apr_psprintf(r->pool, "Unable to allocate memory to hold request body. Asked for %" APR_SIZE_T_FMT
                                          " bytes.",  def->body_length + 1);
        return -1;
    }

    def->body_buffer[def->body_length] = '\0';

    /* Copy the data we keep in chunks into the new buffer. */

    sofar = 0;
    d = def->body_buffer;
    chunks = (chunk_t **)def->body_chunks->elts;
    for( i = 0; i < def->body_chunks->nelts; i++ ) {
        if( sofar + chunks[i]->length <= def->body_length ) {
            memcpy(d, chunks[i]->data, chunks[i]->length);
            d += chunks[i]->length;
            sofar += chunks[i]->length;
        } else {
            *error_msg = apr_psprintf(r->pool, "Internal error, request body buffer overflow.");
            return -1;
        }
    }


    /* Now free the memory used by the chunks. */

    chunks = (chunk_t **)def->body_chunks->elts;
    for( i = 0; i < def->body_chunks->nelts; i++ ) {
        free(chunks[i]->data);
        chunks[i]->data = NULL;
    }

    /* Create a new array with only one chunk in it. */

    def->body_chunks = apr_array_make(def->body_pool, 2, sizeof(chunk_t *));
    if( def->body_chunks == NULL ) {
        *error_msg = apr_pstrdup(r->pool, "Failed to create structure to hold request body.");
        return -1;
    }

    one_chunk = (chunk_t *)apr_pcalloc(def->body_pool, sizeof(chunk_t));
    one_chunk->data = def->body_buffer;
    one_chunk->length = def->body_length;
    one_chunk->is_permanent = 1;
    *(const chunk_t **)apr_array_push(def->body_chunks) = one_chunk;

    /* FIXME : Code needed ?
    if( def->txcfg->reqbody_limit > 0 && msr->txcfg->reqbody_limit < msr->msc_reqbody_length)    {
        msr->msc_reqbody_length = msr->txcfg->reqbody_limit;
    }
    */

    return 1;
}

/**
 * Stops receiving the request body.
 */
apr_status_t body_end(defender_t *def, char **error_msg, request_rec *r) {
    *error_msg = NULL;

    /* Note that we've read the body. */
    def->body_read = 1;

    /* Convert to a single continous buffer, but don't do anything else. */
    return body_end_raw(def, error_msg, r);
}

/**
 * Reads request body from a client.
 */
apr_status_t read_request_body(defender_t *def, char **error_msg, request_rec *r, unsigned long body_limit) {

    unsigned int finished_reading;
    apr_bucket_brigade *bb_in;
    apr_bucket *bucket;

    if( error_msg == NULL ) return -1;
    *error_msg = NULL;

    if( def->body_should_exist != 1 ) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "This request does not have a body.");
        return 0;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Input filter: Reading request body.");

    if( body_start(def, error_msg, r) < 0 ) {
        return -1;
    }

    finished_reading = 0;
    def->if_seen_eos = 0;
    bb_in = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if( bb_in == NULL ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Read body: Failed to allocate new brigade.");
        return -1;
    }
    do {
        apr_status_t rc;

        rc = ap_get_brigade(r->input_filters, bb_in, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
        if (rc != APR_SUCCESS) {
            /* NOTE Apache returns AP_FILTER_ERROR here when the request is
             *      too large and APR_EGENERAL when the client disconnects.
             */
            switch(rc) {
                case APR_INCOMPLETE :
                    *error_msg = apr_psprintf(r->pool, "Error reading request body: %s", get_apr_error(r->pool, rc));
                    return -7;
                case APR_EOF :
                    *error_msg = apr_psprintf(r->pool, "Error reading request body: %s", get_apr_error(r->pool, rc));
                    return -6;
                case APR_TIMEUP :
                    *error_msg = apr_psprintf(r->pool, "Error reading request body: %s", get_apr_error(r->pool, rc));
                    return -4;
                case AP_FILTER_ERROR :
                    *error_msg = apr_psprintf(r->pool, "Error reading request body: HTTP Error 413 - Request entity too large. (Most likely.)");
                    return -3;
                case APR_EGENERAL :
                    *error_msg = apr_psprintf(r->pool, "Error reading request body: Client went away.");
                    return -2;
                default :
                    *error_msg = apr_psprintf(r->pool, "Error reading request body: %s", get_apr_error(r->pool, rc));
                    return -1;
            }
        }

        /* Loop through the buckets in the brigade in order
         * to extract the size of the data available.
         */
        for( bucket = APR_BRIGADE_FIRST(bb_in);
            bucket != APR_BRIGADE_SENTINEL(bb_in);
            bucket = APR_BUCKET_NEXT(bucket) ) {

            const char *buf;
            apr_size_t buflen;

            rc = apr_bucket_read(bucket, &buf, &buflen, APR_BLOCK_READ);
            if( rc != APR_SUCCESS ) {
                *error_msg = apr_psprintf(r->pool, "Failed reading input / bucket (%d): %s", rc, get_apr_error(r->pool, rc));
                return -1;
            }

            ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, "Input filter: Bucket type %s contains %" APR_SIZE_T_FMT
                                                          " bytes. Total length=%lu", bucket->type->name, buflen,
                                                           def->body_length);


            /* Check request body limit (should only trigger on chunked requests). */
            if( def->body_length + buflen > (apr_size_t)body_limit ) {
                *error_msg = apr_psprintf(r->pool, "Request body (%ld+%ld) is larger than the configured limit (%ld).",
                                                    def->body_length, buflen, body_limit);
                return -5;
            }

            def->stream_input_length += buflen;
            body_to_stream(def, buf, buflen, error_msg, r);

            def->body_length += buflen;

            if( buflen != 0 ) {
                int rcbs = body_store_memory(def, buf, buflen, error_msg, r);
            }

            if( APR_BUCKET_IS_EOS(bucket) ) {
                finished_reading = 1;
                def->if_seen_eos = 1;
            }
        }

        apr_brigade_cleanup(bb_in);
    } while( !finished_reading );

    // TODO: Why ignore the return code here?
    int ret = 0;
    if( (ret=body_end(def, error_msg, r)) < 0 ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Error while ending bb saving : %s", *error_msg);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Input filter: Completed receiving request body (length %"
                                                  APR_SIZE_T_FMT ").", def->body_length);

    def->status = IF_STATUS_WANTS_TO_RUN;

    return 1;
}

/**
 *
 */
apr_status_t body_clear(void *data) {
    defender_t *def = (defender_t *)data;

    /* Release memory we used to store request body data. */
    if( def->body_chunks != NULL) {
        chunk_t **chunks = (chunk_t **)def->body_chunks->elts;
        int i;

        for(i = 0; i < def->body_chunks->nelts; i++) {
            if (chunks[i]->data != NULL) {
                free(chunks[i]->data);
                chunks[i]->data = NULL;
            }
        }
    }

    if( def->body_pool != NULL ) {
        apr_pool_destroy(def->body_pool);
        def->body_pool = NULL;
    }

    return 1;
}
