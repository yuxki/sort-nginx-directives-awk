## sort-nginx-directives-awk
Sort nginx directives by their contexts.

## Usage
Can audit that see if all server context has the proxy_ssl_trusted_certificate directive.

```
# validate nginx configuration before sorting
nginx -t
awk -f sort-nginx-directives.awk nginx.conf
 | sed -n '/"server":/p'
 | grep -v 'proxy_ssl_trusted_certificate'
```

## Supported AWK Languages
- gawk
- nawk
- mawk
- busybox (Tested in nginx:1.23.1-alpine image)

## Descriptions
### Input
nginx configurations is input file.

```
# sample.conf
user nginx;
pid /var/run/nginx.pid;

events {
  worker_connections 1024;
}

http {
  log_format  main  '$remote_addr \' - \n $remote_user [$time_local] "$request" ';
  access_log  /var/log/nginx/access.log  main;
  keepalive_timeout  65;
  # proxy_redirect off;

  server {
    listen 80;
    location / {
      if ($request_method = POST) {
        return 405;
      }
      proxy_pass http://example.com;
    }
  }
  include /etc/nginx/conf.d/*.conf;
}
```

### Output
Output is sorted nginx directives by their contexts and that formated by colon delimiter.
```
Context Declared Order:   Context Depth: Directives
                     1: "main" "events": worker_connections 1024;
```

Can sort lines by context declared order.
```
$ awk -f sort-nginx-directives.awk sample.conf | sort -t: -k 1,1n
0:"main": user nginx; pid /var/run/nginx.pid;
1:"main" "events": worker_connections 1024;
2:"main" "http": log_format  main  '$remote_addr \' - \n $remote_user [$time_local] "$request" '; access_log  /var/log/nginx/access.log  main; keepalive_timeout  65; include /etc/nginx/conf.d/*.conf;
3:"main" "http" "server": listen 80;
4:"main" "http" "server" "location /": proxy_pass http://example.com;
5:"main" "http" "server" "location /" "if ($request_method = POST)": return 405;
```

### Options
#### find_path_opt_include=on (default off)
When this option is "on", this program emulate the include directive with "find -type f -path 'include directive value'" command.
In the above example, when 'include /etc/nginx/conf.d/\.conf;' matchs a file which contains "deny 10.0.0.0/24;", output will be follwing example.

```
$ awk -f sort-nginx-directives.awk sample.conf  -v find_path_opt_include=on | sort -t: -k 1,1n
0:"main": user nginx; pid /var/run/nginx.pid; include /etc/nginx/conf.d/*.conf; deny 10.0.0.0/24;
...
```
