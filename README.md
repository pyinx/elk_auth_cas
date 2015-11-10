## 1. 架构
kibana(version:4.1.1): 10.0.0.1:8080
kibana_cas: 10.0.0.1:80
elasticsearch: 10.0.0.2:9200
esproxy(nginx): 10.0.0.2:9201

## 2. kibana auth

### 原理
kibana_cas做kibana的反向代理。kibana_cas通过用户的session判断有没有登录，如果用户没有登录，会跳到登录页；如果用户已经登录，就只做内容转发。
### 实现
kibana配置如下（部分）
```
port: 8080

# The host to bind the server to.
host: "10.0.0.1"
```
kibana_cas启动方法
```
./kibana_cas -dsthost=10.0.0.1 -dstport=8080 -localhost=10.0.0.1 -localport=80 -domain="log.mi.com" -casurl="https://cas.mi.com"
```

## 3. elasticsearch auth
## 原理
nginx做elasticsearch的反向代理，通过获取session中的登录用户名判断是否是管理员。如果是管理员，有所有权限；如果不是管理员，则只有查看权限。(权限这块做的比较粗糙，只实现了管理员和只读权限，没有做到对索引的权限控制，后续考虑加上。)
## 实现
kibana配置（部分）
```
elasticsearch_url: "http://10.0.0.2:9201"
```
nginx代理配置
```
upstream es_cluster_backend {
    server   10.0.0.2:9200 weight=1 max_fails=2 fail_timeout=10s;
}
lua_shared_dict users 10m;
init_by_lua_file "/home/work/app/nginx/conf/lua/esproxy/init.lua";

server {
    listen       9201;
         
    access_log /home/work/logs/nginx/esproxy.log;
    error_log /home/work/logs/nginx/esproxy.err debug;
        
    if ( $http_cookie ~* "kibana_user=(\w+)(?:;|$)" ){ 
           set $username $1;                
    }

    location ~ "(/.kibana/dashboard/|/.kibana/visualization/|/.kibana/index-pattern/|/.kibana/config/)" {
            set $flag 0;
            if ($request_uri !~ "search") {
                    set $flag "${flag}1";
            }
            if ($request_method = 'POST') {
                    set $flag "${flag}2";
            }
            if ($flag = "012") {
                    access_by_lua '
                    local users = ngx.shared.users
                    local nowuser = users:get(ngx.var.username)
                    if not nowuser then
                            ngx.exit(403)
                    end
                    ';
            }
            if ($request_method = 'DELETE') {
                    access_by_lua '
                    local users = ngx.shared.users
                    local nowuser = users:get(ngx.var.username)
                    if not nowuser then
                            ngx.exit(403)
                    end
                    ';
            }
            proxy_set_header Host  $host;
            proxy_set_header X-Forwarded-For  $remote_addr;
            proxy_pass http://es_cluster_backend;
    }
    location / {
            if ($request_method = 'DELETE') {
                    access_by_lua '
                    local users = ngx.shared.users
                    local nowuser = users:get(ngx.var.username)
                    if not nowuser then
                            ngx.exit(403)
                    end
                    ';
            }
            proxy_set_header Host  $host;
            proxy_set_header X-Forwarded-For  $remote_addr;
            proxy_pass http://es_cluster_backend;
    }
}
```
lua脚本内容 (这部分做了偷懒，其实可以写到redis中)
```
local users = ngx.shared.users
users:set("zhangsan","admin")
users:set("lisi","admin")
users:set("wangwu","admin")
```
