#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define UOA_SO_GET_LOOKUP2  2050
#define TOA_SO_GET_VNI      2064

union two_addr{
    struct{
        unsigned char saddr[4];
        unsigned char daddr[4];
    }ipv4;
    struct{
        unsigned char saddr[16];
        unsigned char daddr[16];
    }ipv6;
};

struct four_tuple_with_vni{
    unsigned int type; // indicate this is ipv4 or ipv6 addresses;

    // little endian in userspace (as getsockopt param), big endian in kernel
    uint32_t svni;
    uint16_t sport, dport;

    union two_addr addrs;
};

union uoa_sockopt_param_v2{
    struct four_tuple_with_vni input;
    struct four_tuple_with_vni output;
};

// static ngx_int_t ngx_http_toa_uoa_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_toa_uoa_add_variables(ngx_conf_t *cf);


static ngx_int_t ngx_http_vni_toa_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_vni_uoa_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


static ngx_command_t  ngx_http_toa_uoa_commands[] = {
      ngx_null_command
};


static ngx_http_module_t  ngx_http_toa_uoa_module_ctx = {
    ngx_http_toa_uoa_add_variables,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_toa_uoa_module = {
    NGX_MODULE_V1,
    &ngx_http_toa_uoa_module_ctx,          /* module context */
    ngx_http_toa_uoa_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_toa_uoa_vars[] = {
          { ngx_string("vni_toa"), NULL, ngx_http_vni_toa_variable, 0, 0, 0 },
          { ngx_string("vni_uoa"), NULL, ngx_http_vni_uoa_variable, 0, 0, 0 },

          ngx_http_null_variable
};


// static ngx_int_t
// ngx_http_toa_uoa_handler(ngx_http_request_t *r)
// {
//         return NGX_DONE;
// }


static ngx_int_t
ngx_http_toa_uoa_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_toa_uoa_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_vni_toa_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t vni;
    size_t vni_len = sizeof(vni);

    if (getsockopt(r->connection->fd, IPPROTO_IP, TOA_SO_GET_VNI, &vni, (socklen_t*) &vni_len) != 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_pnalloc(r->pool, sizeof("16777214") - 1); // 0xFFFFFF - 1
    if (vni > 0 && vni < 0xffffff) {
        v->len = ngx_sprintf(v->data, "%ui", vni) - v->data;
    }
    
    return NGX_OK;
}


static ngx_int_t
ngx_http_vni_uoa_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{    
    // struct sockaddr_in client_addr;
    // socklen_t socklen = sizeof(struct sockaddr_in);

    // // UDP recv packet
    // int recv_len = recvfrom(r->connection->fd, buf, buf_size, 0, (struct sockaddr*) &client_addr, &socklen);

    // union uoa_sockopt_param_v2 param;

    // param.input.type = 0; // 0 - IPv4，1 - IPv6
    // param.input.sport = ntohs(client_addr.sin_port);
    // param.input.dport = port;
    
    // memset(&param.input.addrs, 0, sizeof(union two_addr));
    // memcpy(param.input.addrs.ipv4.saddr, &client_addr.sin_addr.s_addr, sizeof(client_addr.sin_addr.s_addr));

    // int param_len = sizeof(union uoa_sockopt_param_v2);
    // if  (getsockopt(r->connection->fd, IPPROTO_IP, UOA_SO_GET_LOOKUP2, &param, (socklen_t*) &param_len) != 0) {
    //     v->not_found = 1;
    //     return NGX_OK;
    // }

    // v->valid = 1;
    // v->no_cacheable = 0;
    // v->not_found = 0;

    // v->data = ngx_pnalloc(r->pool, sizeof("16777214") - 1); // 0xFFFFFF - 1
    // if (param.output.svni > 0 && param.output.svni < 0xffffff) {
    //     v->len = ngx_sprintf(v->data, "%ui", param.output.svni) - v->data;
    // }

    v->not_found = 1;
    return NGX_OK;
}