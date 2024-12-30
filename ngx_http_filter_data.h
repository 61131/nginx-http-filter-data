#ifndef _NGX_HTTP_FILTER_DATA_H_
#define _NGX_HTTP_FILTER_DATA_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


enum {
    STATE_MEDIA = 0,
    STATE_SEP,
    STATE_PARAM,
};

typedef struct {
    ngx_str_t type;
    u_char *charset;
}
ngx_http_filter_data_ctx_t;

typedef struct {
    ngx_flag_t enable;
}
ngx_http_filter_data_loc_conf_t;


#endif  /* _NGX_HTTP_FILTER_DATA_H_ */
