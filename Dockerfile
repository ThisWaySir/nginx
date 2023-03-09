ARG NGINX_SOURCE_VERSION        = 1.23.2
ARG NGINX_INGRESS_IMAGE_VERSION = 2.4.2

FROM ubuntu:latest AS builder

USER root

# maybe useless, add for gcc -ffile-prefix-map
WORKDIR /data/builder/debuild/nginx-$NGINX_SOURCE_VERSION/debian/debuild-base/nginx-$NGINX_SOURCE_VERSION

COPY . .

RUN apt-get update && apt-get install build-essential libpcre3-dev zlib1g-dev libssl-dev -y

# same with nginx -V of nginx/nginx-ingress:$NGINX_INGRESS_IMAGE_VERSION
RUN auto/configure --add-dynamic-module=addon/ngx_http_toa_uoa_module \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --user=nginx \
    --group=nginx \
    --with-compat \
    --with-file-aio \
    --with-threads \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-cc-opt='-g -O2 -ffile-prefix-map=/data/builder/debuild/nginx-$NGINX_SOURCE_VERSION/debian/debuild-base/nginx-$NGINX_SOURCE_VERSION=. -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' \
    --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie'

RUN make modules

# same with ingress image version
FROM nginx/nginx-ingress:NGINX_INGRESS_IMAGE_VERSION

COPY --from=builder objs/ngx_http_toa_uoa_module.so /usr/lib/nginx/modules