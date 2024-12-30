#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_filter_data.h"


static const u_char base64[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


static ngx_int_t ngx_http_filter_data_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static void * ngx_http_filter_data_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_filter_data_encode(ngx_http_request_t *r, ngx_chain_t *in, ngx_buf_t *out);

static ngx_int_t ngx_http_filter_data_header_filter(ngx_http_request_t *r);

static ngx_int_t ngx_http_filter_data_initialise(ngx_conf_t *cf);

static char * ngx_http_filter_data_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static void ngx_http_filter_data_parse_content_type(ngx_http_filter_data_ctx_t *ctx);


static ngx_command_t ngx_http_filter_data_commands[] = {
    { ngx_string("filter_data"),
            NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_flag_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_filter_data_loc_conf_t, enable),
            NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_filter_data_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_http_filter_data_initialise,            /* postconfiguration */
    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */
    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */
    ngx_http_filter_data_create_loc_conf,       /* create location configuration */
    ngx_http_filter_data_merge_loc_conf         /* merge location configuration */
};

ngx_module_t ngx_http_filter_data_module = {
    NGX_MODULE_V1,
    &ngx_http_filter_data_ctx,                  /* module context */
    ngx_http_filter_data_commands,              /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt ngx_http_filter_data_next_header_filter = NULL;

static ngx_http_output_body_filter_pt ngx_http_filter_data_next_body_filter = NULL;


static ngx_int_t
ngx_http_filter_data_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    ngx_http_filter_data_ctx_t *ctx;
    ngx_buf_t *buf;
    ngx_chain_t *chain, out;
    ngx_int_t rc;
    size_t c, len;

    /* assert(ngx_http_filter_data_next_body_filter != NULL); */
    ctx = ngx_http_get_module_ctx(r, ngx_http_filter_data_module);
    if (ctx == NULL) {
        return ngx_http_filter_data_next_body_filter(r, in);
    }

    /*
        The following calculate the expected length of the RFC 2397 data URL encoded 
        response message. It should be noted that while characters can be included
        without encoding, although with escaping for disallowed URL characters as 
        per RFC 3986, this alternate (simplified?) encoding mechanism is not 
        supported by this module.
    */

    len = 0;
    for (chain = in; chain; chain = chain->next) {
        len += ngx_buf_size(chain->buf);
    }
    c = (((len /* + 3 - 1 */ + 2) / 3) * 4);
    c += ctx->type.len + sizeof("data:") + sizeof(";base64,") - 1;
    if (ctx->charset != NULL) {
        c += ngx_strlen(ctx->charset) + 1;
    }

    buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (buf == NULL) {
        return NGX_ERROR;
    }
    buf->pos = ngx_pcalloc(r->pool, c);
    if (buf->pos == NULL) {
        return NGX_ERROR;
    }
    buf->last = buf->pos;
    buf->last_buf = (r == r->main) ? 1 : 0;
    buf->last_in_chain = 1;
    buf->memory = 1;

    buf->last = ngx_snprintf(buf->last, c, "data:%V", &ctx->type);
    if (ctx->charset != NULL) {
        buf->last = ngx_snprintf(buf->last,
                c - (buf->last - buf->pos),
                ";%s",
                ctx->charset);
    }
    buf->last = ngx_snprintf(buf->last, c - (buf->last - buf->pos), ";base64,");
    ngx_http_filter_data_encode(r, in, buf);
    *buf->last++ = '\n';

    out.buf = buf;
    out.next = NULL;

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;
    r->headers_out.content_length_n = /* c */ buf->last - buf->pos;
    r->headers_out.status = NGX_HTTP_OK;

    rc = ngx_http_filter_data_next_header_filter(r);
    if ((r->header_only) ||
            (rc < NGX_OK) ||
            (rc == NGX_ERROR)) {
        return NGX_ERROR;
    }

    return ngx_http_filter_data_next_body_filter(r, &out);
}


static void *
ngx_http_filter_data_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_filter_data_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_filter_data_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static ngx_int_t 
ngx_http_filter_data_encode(ngx_http_request_t *r, ngx_chain_t *in, ngx_buf_t *out) {
    ngx_buf_t *buf;
    ngx_chain_t *chain;
    ngx_int_t rc;
    u_char *ptr;
    size_t len;

    /*
        Read the entire HTTP response body into a single buffer - This is primarily 
        to simplify the subsequent encoding operation.
    */

    len = 0;
    for (chain = in; chain; chain = chain->next) {
        len += ngx_buf_size(chain->buf);
    }

    buf = ngx_create_temp_buf(r->pool, len);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    for (chain = in; chain; chain = chain->next) {
        if (ngx_buf_in_memory(chain->buf)) {
            buf->last = ngx_cpymem(buf->last, chain->buf->pos, ngx_buf_size(chain->buf));
        }
        else {
            rc = ngx_read_file(chain->buf->file, 
                    buf->last,
                    ngx_buf_size(chain->buf), 
                    chain->buf->file_pos);
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }
            buf->last += rc;
        }
    }

    for (ptr = buf->pos; (buf->last - ptr) >= 3; ptr += 3) {
        *(out->last)++ = base64[ptr[0] >> 2];
        *(out->last)++ = base64[((ptr[0] & 0x03) << 4) | (ptr[1] >> 4)];
        *(out->last)++ = base64[((ptr[1] & 0x0f) << 2) | (ptr[2] >> 6)];
        *(out->last)++ = base64[ptr[2] & 0x3f];
    }
    if (buf->last - ptr) {
        *(out->last)++ = base64[ptr[0] >> 2];
        if ((buf->last - ptr) == 1) {
            *(out->last)++ = base64[(ptr[0] & 0x03) << 4];
            *(out->last)++ = '=';
        }
        else {
            *(out->last)++ = base64[((ptr[0] & 0x03) << 4) | (ptr[1] >> 4)];
            *(out->last)++ = base64[(ptr[1] & 0x0f) << 2];
        }
        *(out->last)++ = '=';
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_filter_data_header_filter(ngx_http_request_t *r) {
    ngx_http_filter_data_ctx_t *ctx;
    ngx_http_filter_data_loc_conf_t *lcf;

    /*
        The following skips the application of this filter on any error responses or 
        where the response contains no content.
    */

    /* assert(ngx_http_filter_data_next_header_filter !+ NULL); */
    ngx_http_set_ctx(r, NULL, ngx_http_filter_data_module);
    if ((r->headers_out.status < NGX_HTTP_OK) ||
            (r->headers_out.status >= NGX_HTTP_SPECIAL_RESPONSE) ||
            (r->headers_out.status == NGX_HTTP_NO_CONTENT)) {
        return ngx_http_filter_data_next_header_filter(r);
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_filter_data_module);
    /* assert(lcf != NULL); */
    if (!lcf->enable) {
        return ngx_http_filter_data_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_filter_data_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    /* assert(r->headers_out.content_type.data != NULL); */
    ctx->type.data = ngx_pstrdup(r->pool, &r->headers_out.content_type);
    ctx->type.len = r->headers_out.content_type.len;
    ctx->charset = NULL;
    ngx_http_filter_data_parse_content_type(ctx);

    ngx_http_set_ctx(r, ctx, ngx_http_filter_data_module);

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;
    ngx_http_clear_content_length(r);

    r->filter_need_in_memory = 1;
    r->main_filter_need_in_memory = 1;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_filter_data_initialise(ngx_conf_t *cf) {
    ngx_http_filter_data_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_filter_data_header_filter;

    ngx_http_filter_data_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_filter_data_body_filter;

    return NGX_OK;
}


static char *
ngx_http_filter_data_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_filter_data_loc_conf_t *prev = parent;
    ngx_http_filter_data_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}


static void
ngx_http_filter_data_parse_content_type(ngx_http_filter_data_ctx_t *ctx) {
    ngx_int_t is_sep, state;
    u_char *param, *ptr;

    /*
        The following code is intended to parse the Media Type value from the 
        Content-Type header value. This code will additionally look to identify any 
        character-set encoding which may be included in this header. 

        This parsing is performed in the Apache mod_data module in a rather 
        simplistic manner, splitting the Content-Type header value on a space 
        character and assuming that the character-set specification immediately 
        follows the media type. The code below seeks to perform this parsing in a 
        more robust manner in compliance with the header description in RFC 7231.
    */

    state = STATE_MEDIA;
    param = NULL;

    for (ptr = ctx->type.data; *ptr; ++ptr) {
        is_sep = (((*ptr) == ' ') ||
                ((*ptr) == ';'));
        switch (state) {
            case STATE_MEDIA:
                if (is_sep) {
                    *ptr = '\0';
                    state = STATE_SEP;
                    /* assert(ptr > ctx->type.data); */
                    ctx->type.len = ptr - ctx->type.data - 1;
                }
                break;

            case STATE_SEP:
                if (!is_sep) {
                    param = ptr;
                    state = STATE_PARAM;
                }
                break;

            case STATE_PARAM:
                if (is_sep) {
                    *ptr = '\0';
                    if (ngx_strncasecmp(param, (u_char *) "charset=", 8) == 0) {
                        goto finish;
                    }
                    state = STATE_SEP;
                }
                break;

            default:
                return;     //  This can never occur!
        }
    }

finish:
    if (param != NULL) {
        if (ngx_strncasecmp(param, (u_char *) "charset=", 8) == 0) {
            ctx->charset = param;
        }
    }
}

