#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#if 0
#include <ngx_config.h>

#include <ngx_types.h>
#include <ngx_string.h>
#include <ngx_table.h>
#include <ngx_hunk.h>
#include <ngx_files.h>
#include <ngx_connection.h>
#include <ngx_conf_file.h>

#endif


#define NGX_HTTP_VERSION_9           9
#define NGX_HTTP_VERSION_10       1000
#define NGX_HTTP_VERSION_11       1001

#define NGX_HTTP_GET   1
#define NGX_HTTP_HEAD  2
#define NGX_HTTP_POST  3

#define NGX_HTTP_CONN_CLOSE       0
#define NGX_HTTP_CONN_KEEP_ALIVE  1


#define NGX_HTTP_PARSE_HEADER_DONE        1
#define NGX_HTTP_PARSE_INVALID_METHOD     10
#define NGX_HTTP_PARSE_INVALID_REQUEST    11
#define NGX_HTTP_PARSE_TOO_LONG_URI       12
#define NGX_HTTP_PARSE_INVALID_09_METHOD  13
#define NGX_HTTP_PARSE_INVALID_HEADER     14
#define NGX_HTTP_PARSE_TOO_LONG_HEADER    15
#define NGX_HTTP_PARSE_NO_HOST_HEADER     16
#define NGX_HTTP_PARSE_INVALID_CL_HEADER  17


#define NGX_HTTP_OK                     200
#define NGX_HTTP_PARTIAL_CONTENT        206

#define NGX_HTTP_SPECIAL_RESPONSE       300
#define NGX_HTTP_MOVED_PERMANENTLY      301
#define NGX_HTTP_MOVED_TEMPORARILY      302
#define NGX_HTTP_NOT_MODIFIED           304

#define NGX_HTTP_BAD_REQUEST            400
#define NGX_HTTP_FORBIDDEN              403
#define NGX_HTTP_NOT_FOUND              404
#define NGX_HTTP_NOT_ALLOWED            405
#define NGX_HTTP_REQUEST_TIME_OUT       408
#define NGX_HTTP_REQUEST_URI_TOO_LARGE  414
#define NGX_HTTP_RANGE_NOT_SATISFIABLE  416

#define NGX_HTTP_INTERNAL_SERVER_ERROR  500
#define NGX_HTTP_NOT_IMPLEMENTED        501
#define NGX_HTTP_BAD_GATEWAY            502
#define NGX_HTTP_SERVICE_UNAVAILABLE    503
#define NGX_HTTP_GATEWAY_TIME_OUT       504



#define NGX_HTTP_STATIC_HANDLER     0
#define NGX_HTTP_DIRECTORY_HANDLER  1


typedef struct {
    ngx_str_t  name;
    int        offset;
} ngx_http_header_t;


typedef struct {
    size_t            host_name_len;
    ssize_t           content_length_n;

    ngx_table_elt_t  *host;
    ngx_table_elt_t  *connection;
    ngx_table_elt_t  *if_modified_since;
    ngx_table_elt_t  *content_length;
    ngx_table_elt_t  *range;

    ngx_table_elt_t  *accept_encoding;

    ngx_table_elt_t  *user_agent;

    ngx_table_t      *headers;
} ngx_http_headers_in_t;


typedef struct {
    ngx_chain_t       chain[4];
    ngx_hunk_t       *header_out;
    ngx_hunk_t       *hunk;
    ngx_hunk_t       *file_hunk;
    ngx_file_t        temp_file;
    ngx_path_t       *temp_path;
    off_t             offset;
    char             *header_in_pos;
} ngx_http_request_body_t;


typedef struct {
    off_t      start;
    off_t      end;
    ngx_str_t  content_range;
} ngx_http_range_t;


typedef struct {
    int               status;
    ngx_str_t         status_line;

    ngx_table_elt_t  *server;
    ngx_table_elt_t  *date;
    ngx_table_elt_t  *content_type;
    ngx_table_elt_t  *location;
    ngx_table_elt_t  *last_modified;
    ngx_table_elt_t  *content_range;

    ngx_str_t         charset;
    ngx_array_t       ranges;

    ngx_table_t      *headers;

    off_t             content_length;
    char             *etag;
    time_t            date_time;
    time_t            last_modified_time;
} ngx_http_headers_out_t;


typedef struct ngx_http_request_s ngx_http_request_t;

struct ngx_http_request_s {
    ngx_connection_t    *connection;

    void               **ctx;
    void               **main_conf;
    void               **srv_conf;
    void               **loc_conf;

    ngx_file_t           file;

    ngx_pool_t               *pool;
    ngx_hunk_t               *header_in;
    ngx_http_request_body_t  *request_body;

    ngx_http_headers_in_t     headers_in;
    ngx_http_headers_out_t    headers_out;

    int  (*handler)(ngx_http_request_t *r);

    time_t               lingering_time;

    int                  method;
    int                  http_version;
    int                  http_major;
    int                  http_minor;

    ngx_str_t            request_line;
    ngx_str_t            uri;
    ngx_str_t            args;
    ngx_str_t            exten;
    ngx_str_t            unparsed_uri;

    ngx_http_request_t  *main;

    u_int                in_addr;
    int                  port;
    ngx_str_t           *port_name;    /* ":80" */
    ngx_str_t           *server_name;
    ngx_array_t         *virtual_names;


    char                *discarded_buffer;

    ngx_str_t            path;
    int                  path_err;

    /* URI is not started with '/' - "GET http://" */
    unsigned             unusual_uri:1;
    /* URI with "/.", "%" and on Win32 with "//" */
    unsigned             complex_uri:1;
    unsigned             header_timeout_set:1;

    unsigned             proxy:1;
#if 0
    unsigned             cachable:1;
#endif
    unsigned             pipeline:1;

    unsigned             chunked:1;
    unsigned             header_only:1;
    unsigned             keepalive:1;
    unsigned             lingering_close:1;

    /* TODO: use filter or bits ???? */
    int                  filter;

    /* used to parse HTTP headers */
    int                  state;
    char                *uri_start;
    char                *uri_end;
    char                *uri_ext;
    char                *args_start;
    char                *request_start;
    char                *request_end;
    char                *header_name_start;
    char                *header_name_end;
    char                *header_start;
    char                *header_end;
};


#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */