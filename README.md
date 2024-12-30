# nginx-http-filter-data

RFC 2397 "data" URL scheme filter module for Nginx

The RFC 2397 "data" URL scheme provides a means for the inclusion of small data items as "immediate" data, as if it had been included externally. This mechanism is widely used within applications that need to embed (small) media type data directly inline.

This module provides a mechanism for presenting Nginx-delivered content in this RFC 2397 "data" URL scheme.

## Build

To build the nginx-http-filter-data module from the Nginx source directory:

```bash
./configure --add-module=/path/to/nginx-http-filter-data
make
make install
```

## Configuration

```nginx
server {
    location /media {
        filter_data on;
    }
}
```

Enable the module by adding the following at the top of `/etc/nginx/nginx.conf`:

```nginx
load_module modules/nginx_http_filter_data_module.so;
```

## Directives

### filter_data

* **syntax:** `filter_data <on>|<off>`
* **default:** `off`
* **context:** `location`

Enables the application of this filter module for all content within the current location.

All content served from the current location will be presented with the Content-Type of "text/plain" and encoded in the RFC 2397 "data" URL scheme.

## References

* [RFC 2397 The "data" URL scheme](https://datatracker.ietf.org/doc/html/rfc2397)

