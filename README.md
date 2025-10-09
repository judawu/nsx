# NSX 安装管理脚本说明文档

## 介绍

NSX 安装管理脚本是一个用于部署和管理集成 Nginx、Sing-box 和 Xray 的代理环境的 Bash 脚本。该脚本支持 Docker 和本地安装模式，提供证书管理、配置修改、订阅生成、日志管理和卸载功能。

- **作者**：JudaWu
- **版本**：v0.0.5
- **网站**：[https://github.com/judawu/nsx](https://x1.juda.autos)
- **描述**：一个集成 Nginx、Sing-box 和 Xray 的代理环境，支持 Reality、TLS 等安全设置，适用于代理服务器搭建。

脚本通过菜单式交互简化操作，支持多种操作系统，并处理证书申请、密钥生成和配置更新。

## 系统要求

- **支持的操作系统**：
  - CentOS / Rocky Linux
  - Ubuntu
  - Debian
- **架构**：x86_64 (amd64) 或 arm64 (aarch64)
- **依赖**：curl, wget, git, sudo, lsof, unzip, ufw, socat, jq, iputils-ping, dnsutils, qrencode 等（脚本会自动安装）
- **其他**：root 权限运行脚本；互联网访问用于下载依赖和证书申请。

**注意**：脚本会检查 SELinux（CentOS/Rocky Linux 上禁用以确保兼容性）。

## 安装指南

运行脚本前，确保以 root 权限执行：
```bash
git clone https://github.com/judawu/nsx.git
sudo bash install.sh
```
![安装](png/nsx_install.png)
### 1. 使用 Docker 安装 NSX
脚本会安装 Docker 和 Docker Compose，创建目录，申请证书，配置 Nginx，并启动容器。

- **步骤**：
  1. 选择菜单选项 2。
  2. 脚本自动安装 Docker、创建目录、申请证书（如果未存在）。
  3. 配置 Nginx（替换域名等）。
  4. 启动容器（Nginx、Xray、Sing-box）。
- **配置文件**：
  - Docker Compose 文件：`/usr/local/nsx/docker/docker-compose.yml`
  - Nginx 配置：`/usr/local/nsx/nginx/nginx.conf`
  - Xray 配置：`/usr/local/nsx/xray/config.json`
  - Sing-box 配置：`/usr/local/nsx/sing-box/config.json`
- **日志和证书目录**：
  - 日志：`/usr/local/nsx/log`
  - 证书：`/usr/local/nsx/certs`
- **注意**：安装后，使用 `ufw allow <port>` 开启端口，并启用防火墙（`systemctl enable ufw && systemctl start ufw`）。
![docker安装](png/dockerinstall1.png)
![docker安装2](png/dockerinstall2.png)
### 2. 本地安装 NSX
直接安装 Nginx、Xray 和 Sing-box 到本地系统，使用 systemd 管理服务。

- **步骤**：
  1. 选择菜单选项 3。
  2. 脚本安装工具、禁用 SELinux（CentOS）、创建目录、申请证书。
  3. 下载并安装 Nginx、Xray 和 Sing-box 二进制文件。
  4. 配置服务文件（`/etc/systemd/system/{nginx,xray,sing-box}.service`）。
  5. 启动服务。
- **安装路径**：
  - Nginx：系统默认（`/usr/sbin/nginx`），配置在 `/usr/local/nsx/nginx/nginx.conf`（复制到 `/etc/nginx/nginx.conf`）。
  - Xray：`/usr/local/nsx/xray/xray`（软链接到 `/usr/bin/xray`）。
  - Sing-box：`/usr/local/nsx/sing-box/sing-box`（软链接到 `/usr/bin/sing-box`）。
- **注意**：安装后手动配置防火墙。脚本会创建别名 `nsx` 指向脚本文件。
![local安装2](png/localinstall1.png)
## 证书管理

脚本使用 acme.sh 管理证书，支持 Let's Encrypt 或 ZeroSSL。

- **菜单选项**：4
- **子选项**：
  1. **申请证书**：输入域名、SSL 类型（Let's Encrypt/ZeroSSL）和 DNS 提供商（Cloudflare、阿里云、手动、独立模式）。支持保存凭据以自动续订。
  2. **更新证书**：续订现有证书，使用保存的凭据。
  3. **安装自签证书**：生成自签证书（ECDSA，365 天有效期）。
  4. **退出**。
- **日志**：`/usr/local/nsx/log/acme.log`
- **证书路径**：`/usr/local/nsx/certs/<domain>.{pem,key}`
- **自动续订**：为 Cloudflare/阿里云 DNS 设置 cron 任务（每 3 个月）。
- **注意**：手动 DNS 模式需添加 TXT 记录并验证。

## 配置管理

修改 Nginx、Xray 或 Sing-box 配置，并重启服务。

- **菜单选项**：5
- **子选项**：
  1. **复杂配置nsx服务**：复杂配置nsx服务（修改uuid，password和生成订阅等，适合本地）。
  2. **简单配置nsx服务**：简单配置nsx服务(只修改域名，适合Docker。
![配置](png/configNSX_1.png)
![配置](png/configNSX_2.png) 
![配置](png/configNSX_3.png)
![配置](png/configNSX_4.png)
![配置](png/configNSX_5.png)
![配置](png/configNSX_6.png)
![配置](png/configNSX_7.png) 

## 订阅生成
- **订阅文件**：`/usr/local/nsx/www/subscribe/{xray_sub.txt,singbox_sub.txt}`
- **注意**：配置更新会备份原文件（.bak）。Reality 设置仅在 JSON 中存在相应字段时更新。
生成代理订阅链接和二维码，支持 Xray 和 Sing-box。

- **菜单选项**：9
- **步骤**：
  1. 输入订阅域名（e.g., sing.yourdomain）。
  2. 脚本从配置文件提取 inbounds，构造链接（包括传输、安全参数）。
  3. 显示链接和二维码（使用 qrencode）。
- **支持协议**：VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, Naive。
- **访问**：通过 `http://<sub_domain>/sub/` 访问订阅文件。
- **注意**：如果订阅文件已存在，直接读取并显示。
![安装](png/sub1.png)
![安装](png/sub2.png)

 ## 手动修改客户端订阅
 
  通过 `http://<sub_domain>/sub/` 访问订阅文件后如果发现订阅链接不对，可以手动修改进行代理访问

  先看一下nginx的stream分流：
 ```
     map $ssl_preread_server_name $layer4jail {
        p1.juda.dpdns.org           xray_tls_proxy;   
        p2.juda.dpdns.org       xray_reality_proxy;  
        p3.juda.dpdns.org           unix:/dev/shm/nsx/prextls.sock;
        xtls.juda.dpdns.org         107.148.54.116:8080;
        p4.juda.dpdns.org           unix:/dev/shm/nsx/webpage.sock;
        m.baidu.com              www.google.com:443;
        default                  unix:/dev/shm/nsx/nginxproxy.sock;
        }
```

  这里通过域名进行分流，例如：

  
  *例1 VLESS-XHTTP-REALITY*：

  服务端配置如下：
  
  ```
      {
      "tag": "VLESS-VISION-REALITY",
      "listen": "/dev/shm/nsx/xray_reality_proxy.sock,0666",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "email": "vless@xtls.reality",
            "id": "uuid",
            "flow": "xtls-rprx-vision",
            "level": 0
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "path": "/vlesssplithttp",
            "dest": "/dev/shm/nsx/vlesssplithttp.sock",
            "xver": 0
          },
          {
            "path": "/vlesshttpupgrade",
            "dest": "/dev/shm/nsx/vlesshttpupgrade.sock",
            "xver": 0
          },
          {
            "path": "/vlessws",
            "dest": "/dev/shm/nsx/vlessws.sock",
            "xver": 0
          },
          {
            "path": "/vmessws",
            "dest": "/dev/shm/nsx/vmessws.sock",
            "xver": 0
          },
          {
            "dest": "/dev/shm/nsx/vless_xhttp_reality.sock",
            "xver": 0
          }
        ]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "target": "/dev/shm/nsx/xray_tls_proxy.sock",
          "xver": 0,
          "serverNames": [
            "p1.juda.dpdns.org",
            "p2.juda.dpdns.org"
          ],
          "privateKey": "wDV1NTPFhJ0uOsin7iMZaczZgLXPecwtrX6j0nVuhX4",
          "password": "dWrPthWzzXjYkzgbK40T-R51uI56vulNt0sXLMgdLWg",
          "maxTimeDiff": 0,
          "shortIds": [
            "af3dd995",
            "0c53779c5e0ed16b"
          ]
        },
        "rawSettings": {
          "acceptProxyProtocol": false
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ```
  客户端订阅地址如下
 
  ```
  vless://uuid@p1.juda.dpdns.org:443?type=xhttp&host=&path=%2Freality%2Fxhttp&security=reality&pbk=dWrPthWzzXjYkzgbK40T-R51uI56vulNt0sXLMgdLWg&fp=chrome&sni=p1.juda.dpdns.org&sid=af3dd995&flow=#VLESS-XHTTP-REALITY
  ```
  其中sni=p1.juda.dpdns.org表示为你的分流域名，在nginx。conf的stream模块中，定义了不同域名分流到不同的sock进行代理服务，p1.juda.dpdns.org可能表示我的xray_tls_proxy代理，而p1.juda.dpdns.org表示xray_reality_proxy代理，上面的vless分享链接启用了reality，所以需要手动更改sni指向p2.juda.dpdns.org
  
  也就是：
```
vless://uuid@p1.juda.dpdns.org:443?type=xhttp&host=&path=%2Freality%2Fxhttp&security=reality&pbk=dWrPthWzzXjYkzgbK40T-R51uI56vulNt0sXLMgdLWg&fp=chrome&sni=p2.juda.dpdns.org&sid=af3dd995&flow=#VLESS-XHTTP-REALITY
```
  *例2 TROJAN-XHTTP-REALITY*：
  
  xray服务端配置如下
  
  ```
  {
      "tag": "TROJAN-XHTTP-REALITY",
      "listen": "/dev/shm/nsx/trojan_xhttp_reality.sock,0666",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "email": "trojan@xhttp.reality",
            "password": "password",
            "level": 0
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": "/dev/shm/nsx/xray_tls_proxy.sock",
            "xver": 0
          }
        ]
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ```
 客户端链接：
 
  ```
  trojan://password@p1.juda.dpdns.org:443?type=tcp&security=tls&fp=chrome&sni=p1.juda.dpdns.org#TROJAN-XHTTP-REALITY
  ```
  这条链接采用trojan协议，但是因为室通过fallback访问，所以分享链接需要改成和上面的vless类似，也就是：
```
trojan://password@p1.juda.dpdns.org:443?type=xhttp&host=&path=%2Freality%2Fxhttp&security=reality&pbk=dWrPthWzzXjYkzgbK40T-R51uI56vulNt0sXLMgdLWg&fp=chrome&sni=p2.juda.dpdns.org&sid=af3dd995&flow=#TROJAN-XHTTP-REALITY
```
客户端配置如下：
  ```
  {
      "tag": "proxy_xhttp_trojan",
      "protocol": "trojan",
       "settings": {
        "servers": [
          {
            "address": "p1.juda.dpdns.org",
            "port": 443,
            "password": "password"
          }
        ]
      },
       "streamSettings": {
                 "network": "xhttp",
                  "xhttpSettings": {
                    "host": "",
                    "path": "/reality/xhttp",
                    "mode": "auto"
                  },
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                    "fingerprint": "chrome", // 必填，使用 uTLS 库模拟客户端 TLS 指纹
                    "serverName": "proxy.juda.autos", // 服务端 serverNames 之一
                    "publicKey": "dWrPthWzzXjYkzgbK40T-R51uI56vulNt0sXLMgdLWg", // 服务端私钥对应的公钥
                    "shortId": "0c53779c5e0ed16b", // 服务端 shortIds 之一
                    "spiderX": "/spiderx.block" // 爬虫初始路径与参数，建议每个客户端不同
                }
            }
    },
  ```
 *例3 NGINX-VLESS-GRPC*：
xray服务器配置：

 ```
  {
      "tag": "Vless_grpc",
      "listen": "/dev/shm/nsx/nginx_grpc_vless.sock,0666",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "",
            "email": "vless@grpc",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": {
          "serviceName": "/reality/grpc/h1|h2",
          "multiMode": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
 ```
 下面的grpc可以通过通过tuic的方式传送，而在nignx中p3.juda.dpdns.org通过prextls.sock在nginx中进行server模块的path /reality/grpc/h1进行分流

```
  server {
        listen unix:/dev/shm/nsx/prextls.sock ssl;
        http2   on; 
      
        ssl_protocols TLSv1.2 TLSv1.3;
       
        ssl_certificate     /usr/local/nsx/certs/p1.juda.dpdns.org.pem;
        ssl_certificate_key /usr/local/nsx/certs/p1.juda.dpdns.org.key;
        ssl_ciphers    TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
        ssl_prefer_server_ciphers  on;
        client_header_buffer_size  8k;
        error_log /dev/null;
        access_log /usr/local/nsx/log/nginx_prextls_access.log;
         if ($http_user_agent ~* "zgrab|bot|spider|crawler") {
            return 444;
        }
        if ($http_user_agent = "") {
        return 403;
        }
        if ($args ~* "(shell|wget|rm+-rf|\.env|phpMyAdmin|setup\.php)") {
            return 403;
        }
        if ($request_method !~ ^(GET|POST|HEAD)$) {
        return 405;
         }
         if ($request_method = CONNECT) {
        return 403;
         }
        location ~* \.(env|env-.*|secrets|key\.pem|ini\.bak|yml|log|dist|py|sh|json|dev|prod|test|crt|key|aws|old|1|2)$ {
        deny all;
        return 403;
        }
        location ~* ^/(ab2g|ab2h|download/powershell) {
        return 403;
        }
         location ~* (wordpress|cgi-bin|product|wp-admin|wp-content|wp-includes|phpinfo|wlwmanifest|phpMyAdmin|xmlrpc|dbadmin|pma|phpma|sqlmanager|scripts|setup|admin|_phpMyAdmin|sqlweb|mysql-admin|webadmin|myadmin|www|web|wwwroot|PHPMYADMIN|phpmyadmin|admin|releases|test|upload|statisch|src|stg|server|spring|qa|previous|tmp|demo|internal|keys|lara|live) {
            return 444;
        }
         location / {
            sub_filter                            $proxy_host $host;
            sub_filter_once                       off;
            set $website                          p4.juda.dpdns.org;
            proxy_pass                            https://$website;
            resolver                              1.1.1.1;
            proxy_set_header Host                 $proxy_host;
            proxy_http_version                    1.1;
            proxy_cache_bypass                    $http_upgrade;
            proxy_ssl_server_name                 on;
            proxy_set_header Upgrade              $http_upgrade;
            proxy_set_header Connection           $connection_upgrade;
            proxy_set_header X-Real-IP            $remote_addr;
            proxy_set_header Forwarded            $proxy_add_forwarded;
            proxy_set_header X-Forwarded-For      $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto    $scheme;
            proxy_set_header X-Forwarded-Host     $host;
            proxy_set_header X-Forwarded-Port     $server_port;
            proxy_connect_timeout                 60s;
            proxy_send_timeout                    60s;
            proxy_read_timeout                    60s;
        }
        location /vlesssplithttp {
            proxy_pass                          http://unix:/dev/shm/nsx/vlesssplithttp.sock;
            proxy_http_version                  1.1;
            proxy_request_buffering             off;
            proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
            proxy_redirect                      off;
        }
         location  /vlessws {
            if ($http_upgrade != "websocket") {
                return 404;
            }
            proxy_pass                          http://unix:/dev/shm/nsx/vlessws.sock;
            proxy_http_version                  1.1;
            proxy_set_header Upgrade            $http_upgrade;
            proxy_set_header Connection         "upgrade";
            proxy_set_header X-Real-IP          $remote_addr;
            proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
            proxy_set_header Host               $host;
            proxy_redirect                      off;
        }

         location  /vlesshttpupgrade {
            if ($http_upgrade != "websocket") {
                return 404;
            }
            proxy_pass                          http://unix:/dev/shm/nsx/vlesshttpupgrade.sock;
            proxy_http_version                  1.1;
            proxy_set_header Upgrade            $http_upgrade;
            proxy_set_header Connection         "upgrade";
            proxy_set_header X-Real-IP          $remote_addr;
            proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
            proxy_set_header Host               $host;
            proxy_redirect                      off;
        }
        location /reality/grpc/h1 {
            if ($content_type !~ "application/grpc") {
                return 404;
            }
            grpc_pass                    unix:/dev/shm/nsx/nginx_grpc_vless.sock;
            grpc_read_timeout            1h;
            grpc_send_timeout            1h;
            grpc_set_header X-Real-IP    $remote_addr;
            grpc_socket_keepalive        on;

            client_body_buffer_size      1m;
            client_body_timeout          1h;
            client_max_body_size         0;
        }
       location /reality/grpc/h2 {

            if ($content_type !~ "application/grpc") {
                return 404;
            }
            grpc_pass grpc://unix:/dev/shm/nsx/nginx_grpc_vless.sock;
            grpc_set_header Host $http_host;
            client_max_body_size 0;
            grpc_buffer_size 128k;
            grpc_socket_keepalive on;

            # gRPC headers
            #grpc_set_header Connection        "";
            grpc_set_header X-Real-IP $remote_addr;
            grpc_set_header Forwarded $proxy_add_forwarded;
            grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            grpc_set_header X-Forwarded-Proto $scheme;
            grpc_set_header X-Forwarded-Host $host;
            grpc_set_header X-Forwarded-Port $server_port;
            grpc_send_timeout 1h;
            grpc_read_timeout 1h;
            grpc_set_header Early-Data on;
        }   
    }
 ```
 所以： 
 ```
 vless://id@p1.juda.dpdns.org:443?type=grpc&serviceName=%2Freality%2Fgrpc%2Fh1%7Ch2&security=tls&fp=chrome&sni=p1.juda.dpdns.org&flow=#Vless_grpc
```
 需要改成
 
 ```
  vless://id@p1.juda.dpdns.org:443?type=grpc&serviceName=%2Freality%2Fgrpc%2Fh1&security=tls&fp=chrome&sni=p3.juda.dpdns.org&flow=#Vless_grpc
 ```

 *例4 naive*：
 
```
http+naive://singbox_naive:16d65f45-82eb-41ca-93b2-158cb840b420@xtls.juda.dpdns.org:8083?type=tcp&security=tls&fp=chrome&sni=xtls.juda.dpdns.org&alpn=http%2F1.1#singbox-naive-in
```

在singbox的config中，
  ```
   {
      "type": "naive",
      "tag": "singbox-naive-in",
      "listen": "::",
      "listen_port": 8083,
      "users": [
        {
          "password": "16d65f45-82eb-41ca-93b2-158cb840b420",
          "username": "singbox_naive"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "xtls.juda.dpdns.org",
        "certificate_path": "/usr/local/nsx/certs/xtls.juda.dpdns.org.pem",
        "key_path": "/usr/local/nsx/certs/xtls.juda.dpdns.org.key"
      }
    },
```
Naive在有些区域比如HK会被GFW拦截,在客户端需要启用padding

 *例5 tuic*：
  ```
tuic://90675eb8-759e-4efb-b119-0b8a7f435b6b:password@xtls.juda.dpdns.org:8082??type=tcp&security=tls&fp=chrome&sni=xtls.juda.dpdns.org&alpn=h3#singbox-tuic-in
  ```

singbox服务器配置：
   ```
  {
      "type": "tuic",
      "tag": "singbox-tuic-in",
      "listen": "::",
      "listen_port": 8082,
      "users": [
        {
          "name": "juda-singbox_tuic",
          "uuid": "90675eb8-759e-4efb-b119-0b8a7f435b6b",
          "password": "password"
        }
      ],
      "congestion_control": "bbr",
      "auth_timeout": "5s",
      "zero_rtt_handshake": false,
      "heartbeat": "10s",
      "tls": {
        "enabled": true,
        "server_name": "xtls.juda.dpdns.org",
        "alpn": "h3",
        "certificate_path": "/usr/local/nsx/certs/xtls.juda.dpdns.org.pem",
        "key_path": "/usr/local/nsx/certs/xtls.juda.dpdns.org.key"
      }
    }
  ```
 *例6 tuic*：
 
```
hysteria2://passowrd@xtls.juda.dpdns.org:8081?type=tcp&security=tls&fp=chrome&sni=xtls.juda.dpdns.org&alpn=h3#singbox-hysteria2-in
```
singbox服务器配置：
```
{
      "type": "hysteria2",
      "tag": "singbox-hysteria2-in",
      "listen": "::",
      "listen_port": 8081,
      "up_mbps": 100,
      "down_mbps": 50,
      "users": [
        {
          "name": "singbox_hysteria2",
          "password": "passowrd"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "xtls.juda.dpdns.org",
        "alpn": "h3",
        "certificate_path": "/usr/local/nsx/certs/xtls.juda.dpdns.org.pem",
        "key_path": "/usr/local/nsx/certs/xtls.juda.dpdns.org.key"
      },
      "masquerade": "https://cloudflare.com",
      "brutal_debug": true
    },

 ```

naive，tuic,hysteria2 采用UDP，会被Qos

 *例8 shadowtls*：
服务器配置，shadowtls+shadowsocks
  ```
{
      "type": "shadowsocks",
      "tag": "singbox-ss-in",
      "listen": "::",
      "listen_port": 8084,
      "network": [
        "tcp",
        "udp"
      ],
      "method": "2022-blake3-aes-128-gcm",
      "password": "p1",
      "users": [
        {
          "name": "ss@singbox",
          "password": "p2"
        }
      ],
      "multiplex": {
        "enabled": true
      }
    },
    {
      "type": "shadowtls",
      "tag": "singbox-shadowtls-in",
      "listen": "::",
      "listen_port": 8085,
      "version": 3,
      "password": "p1",
      "users": [
        {
          "name": "shadowtls@singbox",
          "password": "p2"
        }
      ],
      "handshake": {
        "server": "cloudflare.com",
        "server_port": 443
      },
      "strict_mode": true,
      "detour": "singbox-shadowsocks-in"
    }
 ```
shadowtls是一个插件，客户端需要配置ss并启用插件

 xray服务器配置VLESS-ENCRYPTION-REALITY-MIDSA65示例，这个示例中包括了vless的encrytion，reaity 量子加密等，请阅读[说明书](https://xtls.github.io/)：
```
{
      "tag": "VLESS-ENCRYPTION-REALITY-MIDSA65",
      "listen": "0.0.0.0",
      "port": 12345,
      "protocol": "vless",
      "settings": {
        "decryption": "mlkem768x25519plus.random.600s.h5wS8WM73mPNlMMPvat_gmgKF6OEnutj8jVcuDETlHSnqbmNwvGDT47Gg5F2teSGEJsnUFtY6Q9CXZh9mypYvg",
        "clients": [
          {
            "email": "forward@vless.encrytion.reality.midsa65",
            "id": "5be1f546-e72c-4bfd-948e-1b7db3e100c7"
          },
          {
            "email": "reverse@vless.encrytion.reality.midsa65",
            "id": "ac04551d-6ebf-4685-86e2-17c12491f7f4",
            "reverse": {
              "tag": "complex-reverse-out"
            }
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "host": "",
          "path": "/reality/xhttp",
          "mode": "auto",
          "noSSEHeader": false,
          "scMaxBufferedPosts": 30,
          "scStreamUpServerSecs": "20-80"
        },
        "security": "reality",
        "realitySettings": {
          "show": true,
          "target": "google.com:443",
          "xver": 0,
          "serverNames": [
            "p1.juda.dpdns.org",
            "p2.juda.dpdns.org",
            "x1.juda.autos",
            "p3.juda.dpdns.org",
            "p4.juda.dpdns.org",
            "www.google.com",
            "www.youtube.com",
            "www.facebook.com",
            "www.openai.com",
            "www.tiktok.com",
            "www.cloudflare.com",
            "www.netflix.com",
            "www.microsoft.com",
            "www.xAI.com",
            "www.pornhub.com",
            "www.github.com"
          ],
          "privateKey": "aEAZGMshjDxpOmLSIQRGlGv41IRe3lqCtOKFrWyWJ04",
          "password": "Wu_PxiDo93vrWQybmUEHOxWBGH0nNxWWg9nbph0O2Dg",
          "maxTimeDiff": 0,
          "shortIds": [
            "f0b34091",
            "c0b1faad98f8b9d0"
          ],
          "mldsa65Seed": "1eLEpBrq4LakUdpUM0AXw7fnYDKybDqCTo3R7kDftqk",
          "mldsa65Verify": "",
          "limitFallbackUpload": {
            "afterBytes": 0,
            "bytesPerSec": 0,
            "burstBytesPerSec": 0
          },
          "limitFallbackDownload": {
            "afterBytes": 0,
            "bytesPerSec": 0,
            "burstBytesPerSec": 0
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
```
## 日志管理

查看或清除日志文件。

- **菜单选项**：6
- **子选项**：
  ![日志](png/logmanager.png) 
- **日志路径**：`/usr/local/nsx/log/{nginx_*,xray_*,singbox.log}`

## 更新和卸载

### 更新脚本
- **菜单选项**：7
- **步骤**：克隆 GitHub 仓库，替换 install.sh，可选择更新配置文件，重启服务。
![更新](png/updatescript.png)
### 停止 Docker
- **菜单选项**：8
- **步骤**：停止容器，清理 `/dev/shm/nsx`。

### 卸载 NSX
- **菜单选项**：10
- **步骤**：停止服务，卸载 Nginx/Xray/Sing-box/Docker（可选），清理配置文件/证书（可选）。
![卸载](png/uninstallnsx.png)
## 使用菜单

  运行 `nsx` 或 `sudo bash install.sh` 进入主菜单

## 客户端配置（手搓）
  xray客户端配置：
  ```
  
{
  // 日志设置
  // 注意，本例中我默认注释掉了日志文件，因为windows, macOS, Linux 需要写不同的路径，请自行配置
  "log": {
    // "access": "/home/local/xray_log/access.log",    // 访问记录
    // "error": "/home/local/xray_log/error.log",    // 错误记录
    "loglevel": "debug" // 内容从少到多: "none", "error", "warning", "info", "debug"
  },
  //  支持的API服务

  "api": {
    "tag": "api",
     "listen": "127.0.0.1:10810",
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService",
      "RoutingService"
    ]
  },

  "stats": {},//目前统计信息不需要任何参数，只要 StatsObject 项存在，内部的统计即会开启

  //策略设置

   "policy": {
    "levels": {
      "0": {
        "handshake": 2,
        "connIdle": 300,
        "uplinkOnly": 1,
        "downlinkOnly": 3,
        "statsUserUplink": true,
        "statsUserDownlink": true,
        "statsUserOnline": true,
        "bufferSize": 16
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  // DNS设置
  "dns": {
      "hosts": {
            "geosite:category-ads-all": "127.0.0.1"
        },
    "servers": [
      // 国外域名使用国外DNS查询
      {
        "address": "tcp+local://94.140.14.49:53",
        "domains": ["geosite:geolocation-!cn"]	
      },
      {
      "address": "8.8.8.8",
      "port": 53,
      "domains": ["regex:\\.goo.*\\.com$"],
      "expectedIPs": ["geoip:us"],
      "skipFallback": false
     },
    {
        "address": "https+local://dns.google/dns-query",
        "domains": [
          "geosite:netflix",
          "geosite:tiktok"],
        "skipFallback": true,
        "queryStrategy": "UseIPv4"
      },
      // {
      //   "address": "https://1.1.1.1/dns-query",
      //   "domains": ["geosite:openai"],
      //   "skipFallback": true,
      //   "queryStrategy": "UseIPv6"
      // },
      // 国内域名使用国内DNS查询，并期待返回国内的IP，若不是国内IP则舍弃，用下一个查询
      {
        "address": "223.5.5.5",
        "domains": ["geosite:cn"],
        "expectIPs": ["geoip:cn"]
      },
      //对国内网站进行二次查询
      {
        "address": "114.114.114.114",
        "domains": ["geosite:cn"]
      },
      "https+local://1.1.1.1/dns-query", 
      "https+local://cloudflare-dns.com/dns-query",
      "tls://dns.unfiltered.adguard-dns.com",
      "quic+local://dns.adguard.com",
      "tcp+local://94.140.14.49:53",
      "94.140.14.59",  
      //nextDNS
      "45.90.28.0",
      "45.90.30.0",
      "146.112.61.108", //PI-HOLE
      "185.220.100.240",
      "185.220.101.240",
      "https://dns.unfiltered.adguard-dns.com/dns-query",
      "tcp://1.1.1.1:53",
      "8.8.8.8",
      "8.8.4.4",
  
      // 最后的备份，上面全部失败时，用本机DNS查询
      "localhost"
    ]
  },

  // 路由设置
  // 所谓分流，就是将符合否个条件的流量，用指定`tag`的出站协议去处理（对应配置的5.x内容）
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "domainMatcher": "hybrid",
    "rules": [
      // 域名屏蔽
      {
        "type": "field",
        "domain": ["geosite:category-ads-all"],
        "outboundTag": "block"
      },
        {
        "type": "field",
        "domain": ["m.baidu.com"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "block"
      },
      // dns分流
      {
      "inboundTag": [
            "dns-in"
                ],
      "outboundTag": "dns-out"
            },
    // {
    //     "port": "853",
    //     "network": "tcp",
    //     "outboundTag": "block"
    // },
    // {
    //     "port": "443,853",
    //     "network": "udp",
    //     "outboundTag": "block"
    // },
  //隧道路由（端口转发）
    {
      "inboundTag": "tunnel-src",
      "outboundTag": "tunnel-dist-xray-xhttp-reality-1"
    },
    //http代理出站路由
    {
       "inboundTag": "http-in",
      "outboundTag": "tunnel-dist-xray-xhttp-reality-2"
    },
    //反向代理1
    {
               "inboundTag": "reverse-in-vless-simple",
                "outboundTag": "reverse-out-redirect"
    },
    //反向代理2
             {
                "inboundTag": "reverse-in-vless-complex",
                "outboundTag": "reverse-out-redirect"
            },


  {
        "type": "field",
        "ip": [
          "127.0.0.1"
        ],
        "outboundTag": "direct"
  },
  //不允许私有ip出站

  {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "block"
  },

  //api出站回流
  {
        "inboundTag": [
          "api-in"
        ],
        "outboundTag": "api",
        "type": "field"
      },

      //广告过滤
      {
        "domainMatcher": "hybrid",
        "type": "field",
        "ruleTag": "know-ad",
        "domain": [
          "regexp:^.*\\.doubleclick\\.net$",
          "regexp:^(?:pagead2\\.googlesyndication\\.com|s\\.youtube\\.com)$" ,
          "domain:notifications-pa.googleapis.com",
          "domain:people-pa.googleapis.com",
          "domain:redirector.googlevideo.com",
          "domain:suggestqueries.google.com",
          "domain:dingxiang-inc.com",
          "domain:hubspot.com",
          "domain:hubspotusercontent-na1.ne",
          "domain:cookielaw.org",
          "domain:right.com"
        ],
       "outboundTag": "block"
      },

      //出站分流1
      {
        "type": "field",
        "domain": ["www.linkedin.com"],      
        "outboundTag": "proxy_xhttp_reality"
      },
      //出站分流2
       {
        "type": "field",
        "domain": [
         "domain:office.com",
        "domain:office.net",
        "domain:office365.com",
        "domain:vscode-cdn.net",
        "domain:live.com",
        "domain:sharepointonline.com",
        "domain:microsoftonline.com",
        "domain:static.microsoft",
        "domain:microsoft.com",
        "outlook.com"
      ],      
        "outboundTag": "direct"
 
      },
      //出站分流3
      {
                "ip": [
                    "1.1.1.1"
                ],
                "outboundTag": "proxy_xhttp_reality"
            },
      ////出站分流4 国内域名直连
      {
        "type": "field",
        "domain": ["geosite:cn"],
        "outboundTag": "direct"
      },
      //出站分流5 国内IP直连
      {
        "type": "field",
        "ip": ["geoip:cn", "geoip:private"],
        "outboundTag": "direct"
      },
      //出站分流6 国外域名代理
      {
        "type": "field",
        "domain": ["geosite:geolocation-!cn"],

      //选择出站代理
    
      //从singbox 选择
     //  "outboundTag": "proxy_trojan_singbox"
    //   "outboundTag": "proxy_shadowsocks_singbox"
     // "outboundTag": "proxy_vless_reality_singbox"
    //   "outboundTag": "proxy_vless_reality_grpc_singbox"
   //    "outboundTag": "proxy_vless_tcp_singbox"

    //从xray选择
      // "outboundTag": "proxy_vless_reality"
        "outboundTag": "proxy_xhttp_reality"
       //  "outboundTag": "proxy_xhttp_trojan"


        //下面两个要启用不安全证书，不然会连不上, 重新上传正确的域名证书就可以了
       //  "outboundTag": "proxy_vless_tls_tcp"
       //  "outboundTag": "proxy_trojan_tls_tcp"      
       //   "outboundTag": "proxy_vless_splithttp"
       //  "outboundTag": "proxy_vless_ws"
        // "outboundTag": "proxy_vless_httpupgrade"
       // "outboundTag": "proxy_grpc_vless_tcp"
       //"outboundTag": "proxy_udp_shadowsocks"

      },
   
    
      //  默认规则
      // 在Xray中，任何不符合上述路由规则的流量，都会默认使用【第一个outbound（5.1）】的设置，所以一定要把转发VPS的outbound放第一个
      // 3.6 走国内"223.5.5.5"的DNS查询流量分流走direct出站
      {
        "type": "field",
        "ip": ["223.5.5.5","114.114.114.114"],
        "outboundTag": "direct"
      }
    ]
  },

  // 4_入站设置
  "inbounds": [
    // 一般都默认使用socks5协议作本地转发，可以在windows 的proxy setting里面设置全局代理
    {
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1", // 这个是通过socks5协议做本地转发的地址
      "port": 10800, // 这个是通过socks5协议做本地转发的端口
      "settings": {
        "udp": true
      },
      "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ],
                "routeOnly": true
            }
    },
   //  有少数APP不兼容socks协议，需要用http协议做转发，则可以用下面的端口
    {
      "tag": "http-in",
      "protocol": "http",
      "listen": "127.0.0.1", // 这个是通过http协议做本地转发的地址
      "port": 10801 // 这个是通过http协议做本地转发的端口
    },
   
     //  api的入站,通过端口转发查询本地xray api的接口，例如可以用./xray api lsi -s 127.0.0.1:10802查询xray api的入站列表
    // 也可以通过端口转发查询服务器的API
     {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 10802,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 10810//,
        // "portMap": {
        //             "10802": ":10810"
        //           }
      },
      
      "sniffing": null
    },
    //dns入站
    {     
      "tag": "dns-in",
      "listen": "127.0.0.1",
      "port": 10853,
      "protocol": "dokodemo-door",
      "settings": {
          "address": "223.5.5.5",
          "port": 53,
          "network": "udp"
            }
    },

  //端口转发
   //隧道功能入站https://github.com/XTLS/Xray-core/pull/4968
   //通过配置即可简单地把客户端的 IPv4/TCP/10830-10850 端口通过 VLESS 协议转发到服务端相应的 IPv4/TCP/10830-10850 端口
  //以设置 tunnel 入站 settings 的 address/port 或 direct 出站的 redirect 以强制覆写目标地址或端口，或都覆写
  //由 tunnel 入站 10848 端口接收的流量会通过 VLESS 协议转发到 1.1.1.1:53，优先级高于原有的 address/port
   {
            "tag": "tunnel-src",
            "listen": "0.0.0.0",
          
            "port": "10830-10850,10851",
            "protocol": "tunnel", //与dokodemo-door互为别名
            "settings": {
                "network": "TCP", // default: TCP
              //  "address": "remote 127.0.0.1", // default: remote 127.0.0.1
               // "port": 0, // default: equals to local listening port
                "portMap": {
                    "10848": "1.1.1.1:53",  //转发端口到dns服务器

                    "10850": ":443", // overrides port only
                    "10851": "p4.juda.dpdns.org:443", // overrides address and port
                    "10845": "p2.juda.dpdns.org:10849",// 这个指向了远程的一份web服务器
                    "10846": ":10849" ,// overrides port only
                    "10847": "p4.juda.dpdns.org:80",// overrides address and port
                    "10844": ":8888", // 指向服务器xray 的api接口
                    "10843": ":3443" // 指向一个下行端口，完成骚操作
                    
                }
            }
        }

  
  
  ],

  // 出站设置
  "outbounds": [

    // 5默认出站direct
   
    {
      "tag": "direct",
       "settings": {
                "domainStrategy": "ForceIPv4"
            },
      "protocol": "freedom"
    },

    //服务器1 xray列表
     {
      "tag": "proxy_xhttp_reality",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "", // 替换成你的真实域名
            "port": 443,
            "users": [
             
         
              {
                "id": "",             
                "encryption": "none",
                "email": "vps@v4",
                "level": 0
              }
            ]
          }
        ]
      },
       "streamSettings": {
                 "network": "xhttp",
                  "xhttpSettings": {
                    "host": "",
                    "path": "/reality/xhttp",
                    "mode": "auto"//,
                    //  "extra": {
                    //   "headers": {
                    //       // "key": "value"
                    //   },
                    //   "xPaddingBytes": "100-1000",
                    //   "noGRPCHeader": false, // stream-up/one, client only
       
                    //   "scMaxEachPostBytes": 1000000, // packet-up only
                    //   "scMinPostsIntervalMs": 30, // packet-up, client only
                    //   "scStreamUpServerSecs": "20-80", // stream-up, server only
                    //   "xmux": { // h2/h3 mainly, client only
                    //       "maxConcurrency": "16-32",
                    //       "maxConnections": 0,
                    //       "cMaxReuseTimes": 0,
                    //       "hMaxRequestTimes": "600-900",
                    //       "hMaxReusableSecs": "1800-3000",
                    //       "hKeepAlivePeriod": 0
                    //   },
                    //   "downloadSettings": { // client only
                    //       "address": "", // another domain/IP
                    //       "port": 443,
                    //       "network": "xhttp",
                    //       "security": "tls",
                    //       "tlsSettings": {
                    //           ...
                    //       },
                    //       "xhttpSettings": {
                    //           "path": "/yourpath", // must be the same
                    //           ...
                    //       },
                    //       "sockopt": {} // will be replaced by upload's "sockopt" the latter's "penetrate" is true
                    //   }
                    //          }
                  },
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                    "fingerprint": "chrome", // 必填，使用 uTLS 库模拟客户端 TLS 指纹
                    "serverName": "", // 服务端 serverNames 之一
                    "publicKey": "", // 服务端私钥对应的公钥
                    "shortId": "50202bc2", // 服务端 shortIds 之一
                   // "mldsa65Verify":"", // 选填，服务端 mldsa65Seed 生成的公钥，对证书进行抗量子的额外验
                    "spiderX": "/spiderx.block" // 爬虫初始路径与参数，建议每个客户端不同
                }
            }
    },
     {
      "tag": "proxy_xhttp_trojan",
      "protocol": "trojan",
       "settings": {
        "servers": [
          {
            "address": "",
            "port": 443,
            "password": ""
          }
        ]
      },
       "streamSettings": {
                 "network": "xhttp",
                  "xhttpSettings": {
                    "host": "",
                    "path": "/reality/xhttp",
                    "mode": "auto"
                  },
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                    "fingerprint": "chrome", // 必填，使用 uTLS 库模拟客户端 TLS 指纹
                    "serverName": "", // 服务端 serverNames 之一
                    "publicKey": "", // 服务端私钥对应的公钥
                    "shortId": "", // 服务端 shortIds 之一
                    "spiderX": "/spiderx.block" // 爬虫初始路径与参数，建议每个客户端不同
                }
            }
    },
    {
      "tag": "proxy_vless_reality",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "", // 替换成你的真实域名
            "port": 443,
            "users": [
              {
                "id": "", 
               "flow": "xtls-rprx-vision", // Windows, macOS 同学保持这个不变
                "encryption": "none",
                "level": 0
              }
            ]
          }
        ]
      },
       "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                    "fingerprint": "chrome", // 必填，使用 uTLS 库模拟客户端 TLS 指纹
                    "serverName": "", // 服务端 serverNames 之一
                    "publicKey": "", // 服务端私钥对应的公钥
                    "shortId": "", // 服务端 shortIds 之一
                  //  "mldsa65Verify": ", // 选填，服务端 mldsa65Seed 生成的公钥，对证书进行抗量子的额外验
                    "spiderX": "/spiderx.block" // 爬虫初始路径与参数，建议每个客户端不同
                }
            }
    },
    
     {
      "tag": "proxy_vless_tls_tcp",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "", // 替换成你的真实域名
            "port": 443,
            "users": [
              {
                "id": "", // 和服务器端的一致
                "flow": "xtls-rprx-vision",      
                "encryption": "none",
                "level": 0
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "" , 
           "alpn": [
            "http/1.1",
            "h2"
          ],
          "fingerprint": "chrome",
          "allowInsecure": false, // 禁止不安全证书,这需要为true，不然浏览器不认
          "echConfigList": ""
        }
      }
    },
    {
      "tag": "proxy_trojan_tls_tcp",
      "protocol": "trojan",
       "settings": {
        "servers": [
          {
            "address": "",
            "port": 443,
            "password": "b"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "", // 替换成你的真实域名
          "fingerprint": "chrome",
          "allowInsecure": false // 禁止不安全证书
        }
      }
    },
    {   
            "tag": "proxy_vless_splithttp",
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "",
                        "port": 443,
                        "users": [
                            {
                                "id": "", // 与服务端一致
                                "encryption": "none"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "splithttp",
                "splithttpSettings": {
                    "path": "/vlesssplithttp", // 与服务端一致
                    "host": "" // 若 "address": "" 中填的是 VPS 的 IP，此处必须填 Nginx 配置中 server_name 的值，否则会因在 Nginx 配置中启用了 ssl_reject_handshake 而连接失败
                },
                "security": "tls",
                "tlsSettings": {
                    "serverName": "",
                     "alpn": [
                        "h3",
                        "h2",
                        "http/1.1"
                    ],
                    "fingerprint": "chrome" ,
                    "allowInsecure": false // 禁止不安全证书
                }
            }
           
        },
     {
          
           "tag": "proxy_vless_ws",
           "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "",
                        "port": 443,
                        "users": [
                            {
                                "id": "", // 与服务端一致
                                "encryption": "none"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vlessws?ed=2560", // 与服务端一致，建议增加 ?ed=2560 以启用 0-RTT 降低延迟
                    "host": ""
             
                  // 若 "address": "" 中填的是 VPS 的 IP，此处必须填 Nginx 配置中 server_name 的值，否则会因在 Nginx 配置中启用了 ssl_reject_handshake 而连接失败
              
              
                  },
                "security": "tls",
                "tlsSettings": {
                  "serverName": "",
                  "fingerprint": "chrome"
                }
            }
        },
     {
           "tag": "proxy_vless_httpupgrade",
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "",
                        "port": 443,
                        "users": [
                            {
                                "id": "", // 与服务端一致
                                "encryption": "none"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "httpupgrade",
                "httpupgradeSettings": {
                    "path": "/vlesshttpupgrade?ed=2560", // 与服务端一致，建议增加 ?ed=2560 以启用 0-RTT 降低延迟
                    "host": "" // 若 "address": "" 中填的是 VPS 的 IP，此处必须填 Nginx 配置中 server_name 的值，否则会因在 Nginx 配置中启用了 ssl_reject_handshake 而连接失败
                },
                "security": "tls",
                "tlsSettings": {
                    "serverName": "", //可以支持prox.juda.autos,proxy.juda.autos
                    "fingerprint": "chrome"
                }
            }
        },
     {
           "tag": "proxy_grpc_vless_tcp",
           "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "",
                        "port": 443,
                        "users": [
                            {
                                "id": "", // 与服务端一致
                                "encryption": "none"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "/reality/grpc/h2", // 与服务端一致
                    "multiMode": true,
                    "idle_timeout": 60,
                    "health_check_timeout": 20
                },
                "security": "tls",
                "tlsSettings": {
                    "serverName": "",
                    "fingerprint": "chrome"
                }
            }
            
        },

    {
      "tag": "proxy_udp_vless_mkcp",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "", // 服务器IP或域名
              "port": 4443,
            "users": [
              {
                "id": "", // 与服务器UUID一致
                "email": "vless@xtls.mkcp",
                "encryption": "none",
                "level": 0
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "kcp",
      //  "security": "none",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": true,
          "serverName": ""
        },
        "kcpSettings": {
          "mtu": 1350,
          "tti": 20,
          "uplinkCapacity": 12,
          "downlinkCapacity": 100,
          "congestion": false,
          "readBufferSize": 1,
          "writeBufferSize": 1,
          "header": {
           "type": "none"//,
        //   //        none"：默认值，不进行伪装，发送的数据是没有特征的数据包。
        //  //          "srtp"：伪装成 SRTP 数据包，会被识别为视频通话数据（如 FaceTime）。
        //  //        "utp"：伪装成 uTP 数据包，会被识别为 BT 下载数据。
        //  //       "wechat-video"：伪装成微信视频通话的数据包。
        //   //      "dtls"：伪装成 DTLS 1.2 数据包。
        //   //                "wireguard"：伪装成 WireGuard 数据包。（并不是真正的 WireGuard 协议）
        //   //           "dns"：某些校园网在未登录的情况下允许DNS查询，给KCP添加DNS头，把流量伪装成dns请求，可以绕过某些校园网登录。
        //   "domain": "apple.com"
        },
           "seed": "1yqE9B/cU2IiFSFNNRXzOw=="
        }
      }
    },
 //服务器1 singobox列表
     {
      "tag": "proxy_udp_shadowsocks",
      "protocol": "shadowsocks",
         "settings": {
     "servers": [
       {
      "email": "ss@udp",
      "address": "",
      "port": 10807,
      "method": "2022-blake3-aes-128-gcm",
      "password": "",
      "uot": false,
      "UoTVersion": 2,
      "level": 0
       }
               ]  
     }
    },

{
      "tag": "proxy_trojan_singbox",
      "protocol": "trojan",
       "settings": {
        "servers": [
          {
            "address": "",
            "port": 443,
            "password": ""
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "", // 替换成你的真实域名
          "fingerprint": "chrome",
          "allowInsecure": false // 禁止不安全证书
        }
      }
    },
{
      "tag": "proxy_shadowsocks_singbox",
      "protocol": "shadowsocks",
         "settings": {
     "servers": [
       {
      "email": "ss@udp",
      "address": "",
  // "port": 8084, //原始端口
      "port": 10804,  //通过服务器nginx 的stream进行中转
      
      "method": "2022-blake3-aes-128-gcm",
      "password": "",
      "uot": true,
      "UoTVersion": 2,
      "level": 0
       }
           ]  
     }
    },
   {
      "tag": "proxy_vless_reality_singbox",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "", // 替换成你的真实域名
          //  "port": 8089,
               "port": 10809,  //通过服务器nginx 的stream进行中转
            "users": [
              {
                "id": "", 
                "flow": "xtls-rprx-vision", // Windows, macOS 同学保持这个不变
                "encryption": "none",
                "level": 0
              }
            ]
          }
        ]
      },
       "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                    "fingerprint": "chrome", // 必填，使用 uTLS 库模拟客户端 TLS 指纹
                    "serverName": "", // 服务端 serverNames 之一
                    "publicKey": "", // 服务端私钥对应的公钥
                    "shortId": "", // 服务端 shortIds 之一
                    "spiderX": "/spiderx.block" // 爬虫初始路径与参数，建议每个客户端不同
                }
            }
    },
   {
      "tag": "proxy_vless_reality_grpc_singbox",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "", // 替换成你的真实域名
          //  "port": 8088,
               "port": 10808,  //通过服务器nginx 的stream进行中转
            "users": [
              {
                "id": "", 
               
                "encryption": "none",
                "level": 0
              }
            ]
          }
        ]
      },
       "streamSettings": {
                  "network": "grpc",
               
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                    "fingerprint": "chrome", // 必填，使用 uTLS 库模拟客户端 TLS 指纹
                    "serverName": "", // 服务端 serverNames 之一
                    "publicKey": "", // 服务端私钥对应的公钥
                    "shortId": "", // 服务端 shortIds 之一
                    "spiderX": "/spiderx.block" // 爬虫初始路径与参数，建议每个客户端不同
                },
                 "grpcSettings": {
                    "serviceName": "grpc", // 与服务端一致
                    "multiMode": false,
                    "idle_timeout": 60,
                    "health_check_timeout": 20
                }

            }
    },


    //服务器2列表
    //xhttp上下行分离，p2.juda.dpdns.org 通过reality上行，x1.juda.autos通过tls进入nginx反代下行
    //xhttp 不能有flow设置
    {
      "tag": "tunnel-dist-xray-xhttp-reality-1",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "p2.juda.dpdns.org", // 替换成你的真实域名
            "port": 443,
            "users": [
              {
                "id": "e25033eb-6080-4a50-bf50-1eaaca13dc51",             
                "encryption": "none",
                "email": "vps@v3",
                "level": 0
              }
            ]
          }
        ]
      },
       "streamSettings": {
                 "network": "xhttp",
                  "xhttpSettings": {
                  "headers": {
                        "Pragma": "no-cache",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
                      },
                    "host": "",
                    "path": "/reality/xhttp",
                    "mode": "auto",
                    "xPaddingBytes": "100-1000",
                    "noGRPCHeader": false, 
                    "scMaxEachPostBytes": 1000000, // packet-up only
                    "scMinPostsIntervalMs": 30, // packet-up, client only   
                    "xmux": { // h2/h3 mainly, client only
                          "maxConcurrency": "16-32",
                          "maxConnections": 0,
                          "cMaxReuseTimes": 0,
                          "hMaxRequestTimes": "600-900",
                          "hMaxReusableSecs": "1800-3000",
                          "hKeepAlivePeriod": 0
                      },
                      "downloadSettings": { // client only
                      "address": "107.148.54.116", 
                      "port": 443,
                      "network": "xhttp",
                       "xhttpSettings": {
                        "host": "",
                        "path": "/reality/xhttp",
                        "mode": "auto"
                      },
                      "security": "tls",
                      "tlsSettings": {
                        "serverName": "x1.juda.autos" , 
                        "alpn": [
                   //       "h3",
                          "h2",
                          "http/1.1"
                          
                        ],
                        "fingerprint": "chrome",
                        "allowInsecure": false // 禁止不安全证书,这需要为true，不然浏览器不认
                      }
              
       
                       }
                            
                  },
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                    "fingerprint": "chrome", // 必填，使用 uTLS 库模拟客户端 TLS 指纹
                    "serverName": "p2.juda.dpdns.org", // 服务端 serverNames 之一
                    "publicKey": "FeZkCok3ermqBaJ1WdAusSUBvN7lsaBLwlS3UzrSdj0", // 服务端私钥对应的公钥
                    "shortId": "64f1914d508165d5", // 服务端 shortIds 之一
                    "spiderX": "/spiderx.block" // 爬虫初始路径与参数，建议每个客户端不同
                }
            }
    },

   //xhttp上下行分离，通过x1.juda.autos 3443 端口 eality上行，x1.juda.autos通过p2.juda.dpdns.org eality下行
   {
		"tag": "tunnel-dist-xray-xhttp-reality-2",
    "protocol": "vless",
			"settings": {
				"address": "",
				"port": 3443,
				"encryption": "none",
				"id": "e25033eb-6080-4a50-bf50-1eaaca13dc51"
         
			
			},
      "streamSettings": {
                 "network": "xhttp",
                  "xhttpSettings": {
                  "headers": {
                        "Pragma": "no-cache",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
                      },
                    "host": "",
                    "path": "/reality/xhttp",
                    "mode": "auto",
                    "xPaddingBytes": "100-1000",
                    "noGRPCHeader": false, // stream-up/one, client only
                //  "noSSEHeader": false, // server only
                    "scMaxEachPostBytes": 1000000, // packet-up only
                    "scMinPostsIntervalMs": 30, // packet-up, client only
                   // "scMaxBufferedPosts": 30, // packet-up, server only
                    //"scStreamUpServerSecs": "20-80", // stream-up, server only
                    "xmux": { // h2/h3 mainly, client only
                          "maxConcurrency": "16-32",
                          "maxConnections": 0,
                          "cMaxReuseTimes": 0,
                          "hMaxRequestTimes": "600-900",
                          "hMaxReusableSecs": "1800-3000",
                          "hKeepAlivePeriod": 0
                      },
                      "downloadSettings": { // client only
                      "address": "107.148.54.116", 
                      "port": 443,
                      "network": "xhttp",
                       "xhttpSettings": {
                        "host": "",
                        "path": "/reality/xhttp",
                        "mode": "auto"
                      },
                     "security": "reality",
                    "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                   // "fingerprint": "randomizednoalpn", // 必填，使用 uTLS 库模拟客户端 TLS 指纹
                     "fingerprint": "chrome",
                    "serverName": "p2.juda.dpdns.org", // 服务端 serverNames 之一
                    "publicKey": "FeZkCok3ermqBaJ1WdAusSUBvN7lsaBLwlS3UzrSdj0", // 服务端私钥对应的公钥
                    "shortId": "64f1914d508165d5", // 服务端 shortIds 之一
                    "spiderX": "/spiderx.block" // 爬虫初始路径与参数，建议每个客户端不同
                }
       
                       }
                            
                  },
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                   // "fingerprint": "randomizednoalpn", // 必填，使用 uTLS 库模拟客户端 TLS 指纹
                      "fingerprint": "chrome",
                    "serverName": "x1.juda.autos", // 服务端 serverNames 之一
                    "publicKey": "tiapHof8aOr3vzcYINQMkql9AEKPqmo1jAL7zfpbyFQ", // 服务端私钥对应的公钥
                    "shortId": "4f10451af6044d56", // 服务端 shortIds 之一
                    "spiderX": "/spiderx.block" // 爬虫初始路径与参数，建议每个客户端不同
                }
            }
    
		},
   //xhttp上下行分离，通过x1.juda.autos 3443 端口 eality上行，x1.juda.autos通过p2.juda.dpdns.org tls下行
    {
		"tag": "tunnel-dist-xray-xhttp-reality-3",
    "protocol": "vless",
			"settings": {
				"address": "",
				"port": 3443,
				"encryption": "none",
				"id": "e25033eb-6080-4a50-bf50-1eaaca13dc51"	
			},
      "streamSettings": {
                 "network": "xhttp",
                  "xhttpSettings": {
                  "headers": {
                        "Pragma": "no-cache",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
                      },
                    "host": "",
                    "path": "/reality/xhttp",
                    "mode": "auto",
                    "xPaddingBytes": "100-1000",
                    "noGRPCHeader": false, // stream-up/one, client only
                    "scMaxEachPostBytes": 1000000, // packet-up only
                    "scMinPostsIntervalMs": 30, // packet-up, client only
                    "xmux": { // h2/h3 mainly, client only
                          "maxConcurrency": "16-32",
                          "maxConnections": 0,
                          "cMaxReuseTimes": 0,
                          "hMaxRequestTimes": "600-900",
                          "hMaxReusableSecs": "1800-3000",
                          "hKeepAlivePeriod": 0
                      },
                      "downloadSettings": { // client only
                      "address": "", 
                      "port": 443,
                      "network": "xhttp",
                       "xhttpSettings": {
                        "host": "",
                        "path": "/reality/xhttp",
                        "mode": "auto"
                      },
                      "security": "tls",
                      "tlsSettings": {
                        "serverName": "x1.juda.autos" , //或者prox.juda.autos
                        "alpn": [
                   //       "h3",
                          "h2",
                          "http/1.1"
                          
                        ],
                        "fingerprint": "chrome",
                        "allowInsecure": false // 禁止不安全证书,这需要为true，不然浏览器不认
                      }               
                }
                     
                            
                  },
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                   // "fingerprint": "randomizednoalpn", // 必填，使用 uTLS 库模拟客户端 TLS 指纹
                      "fingerprint": "chrome",
                    "serverName": "x1.juda.autos", // 服务端 serverNames 之一
                    "publicKey": "tiapHof8aOr3vzcYINQMkql9AEKPqmo1jAL7zfpbyFQ", // 服务端私钥对应的公钥
                    "shortId": "4f10451af6044d56", // 服务端 shortIds 之一
                    "spiderX": "/spiderx.block" // 爬虫初始路径与参数，建议每个客户端不同
                }
            }
    
		},
      //反向代理出站1（简单版）
  {
			"protocol": "vless",
			"settings": {
				"address": "",
				"port": 3444,
				"encryption": "mlkem768x25519plus.native.0rtt.2PcBa3Yz0zBdt4p8-PkJMzx9hIj2Ve-UmrnmZRPnpRk",
				"id": "ac04551d-6ebf-4685-86e2-17c12491f7f4",
				"flow": "xtls-rprx-vision",
				"reverse": {
					"tag": "reverse-in-vless-simple"
				}
			}
		},
     //反向代理出站2（复杂版）
    {
    "protocol": "vless",
			"settings": {
				"address": "",
				"port": 3445,
				"encryption": "mlkem768x25519plus.native.0rtt.2PcBa3Yz0zBdt4p8-PkJMzx9hIj2Ve-UmrnmZRPnpRk",
				"id": "ac04551d-6ebf-4685-86e2-17c12491f7f4",
        "reverse": {
					"tag": "reverse-in-vless-complex"
				}
			},
      "streamSettings": {
                 "network": "xhttp",
                  "xhttpSettings": {
                    "host": "",
                    "path": "/reality/xhttp",
                    "mode": "auto",
                    "xPaddingBytes": "100-1000",
                    "noGRPCHeader": false, 
                    "scMaxEachPostBytes": 1000000, 
                    "scMinPostsIntervalMs": 30, 
                    "xmux": { // h2/h3 mainly, client only
                          "maxConcurrency": "16-32",
                          "maxConnections": 0,
                          "cMaxReuseTimes": 0,
                          "hMaxRequestTimes": "600-900",
                          "hMaxReusableSecs": "1800-3000",
                          "hKeepAlivePeriod": 0
                      }                    
                  },
                "security": "reality",
                "realitySettings": {
                    "show": false, // 选填，若为 true，输出调试信息
                    "fingerprint": "chrome", // 必填，使用 uTLS 库模拟客户端 TLS 指纹
                    "serverName": "p2.juda.dpdns.org", // 服务端 serverNames 之一
                    "publicKey": "tiapHof8aOr3vzcYINQMkql9AEKPqmo1jAL7zfpbyFQ", // 服务端私钥对应的公钥
                    "shortId": "4f10451af6044d56", // 服务端 shortIds 之一
                  "mldsa65Verify": "8WVi6HQ01_4QeQXj3VnqTsCrLM30hIS9U7uwzrFohLnucc8yZM8t3gLfY0HHtnfqJH_Ua1eAiS0uAiU6ng3NMfEhLAFlqYFD_xbJf2rgLktiaX2ERZJSW722Psig1tjWMlsf4TCsNel0Fcft-8WKKRfzL4s2tXtTc-SX8GWR2yDrBwMyGxKFWPBDS6O9UOa_kNvdLUpu2y0CrNW7Qs5_NhDLlcJ_S6HAe-NuTpvZ6ISUbWgYsQAlGK_vnNNo5o9PdnV9YfbC_NLD4yELOYbR3oFxfXdU7h4t7cMkx_1LsW01jhpXhOsIMuVWfXSECr5R86WLOS7nolCeyk6V7ZzOVDWlj8Hxe_GaBOf6WVvG_bIboizC4_WrDM7g5niHCbNZlLzn-3u26BoA5P1LXKexRcWn_tkHjyMlIMOF8Xw4M_DRx36uHYEef619X8OhO5oHk7HT05FiU812uBj5oJysu9tRSZeK34gjLJebuYIN2zEHYNpC0ZSRWnys-AVoLA_kHEtc0dvRIswrRRvA2LxTxnU8VWiSnYRegMVFeczwXqr6IGxdMYCSN0n6BpcIaqiLcp5PPswr7D_gPuKSynCrpbpGbzVCdKvY1NioL5T8TD6YFWwPe3N_eC29NeccA4UQcg35x4QUnSspKItuWSCxubr0yVjOV1OeAS0PAShQbLcfeLWCsMZdvEcJaKcxBGIXScxF1C55pD-tYl2g2MeHckQevEtDLRPnE4_IOC3FCcI6kZi74QTdpbXPTMSIAXlbJJeKX4_5iR-l_QzH3cxEY2VhzCFgym29iwbrEiNfKmkMP0XFVxuZN04veULv0EVJXJZIYDtsFd4CzmhVWkhLgFsCfCEDGSByDuxQZ1-Rj78geMCqYOI3esk1ydkGaPmL1gtn46BI1pWenRRN83ShZdj8PtPb0YjlD-Wwj6WKksab4-Dc-O1HnzEob0n8mBBH1BoiuRh2irWepMfvStKCCOXt8s7g5S3fynkEN2ZYiC8uPvbXhG0_JKxJ8zhDpQUnyaydGFhBRAH43jkPTR7BHmDeVyfEEOZ5W43vsRWJcTfi7dU2alGbw2oWgLookTnOgMhtRS4Kd3wg5I5SMK_2f5EuUQ5ZUKGwgv4q_ewp7UDYnizGqswIfFDgH1a5CN5RdrZLGaEPRM9GNjR6xUc97EXiIW7EjD7ULoa8XuxAehjdlv7QdoF-XfMurccWtJqOfSDCYt-KfVIkXOcv7t7bn6g4sjC2T9tc_OzE4TC2J-wSzalhvDMNRR3zDxPXeeaTlOybk-0Wk8-8Ib2p4bLOGv-EgHWkuWyQLlZgMdKB27ye1hmiXw0JthI6m1NWaMj4dJpSrwDimjVIMNKyGFXt9rlgtSXODSqFA7rbTSYgU8gaFBGIfD31mIbpBKloXpxckDKq_6vTDTMGTqArDzAbIOFKWHO08I8PApWf--B_FTwDWbthKllvNH9wv1AxUNu8zFNYN93s1KFBX2wROvhgafmooxTfR1RpcKnST1ry-SQTuiSuXCxs0AyPIAYiNdomziZ2DJ86TYgIwRUS2RibEmURsRNkwwsL_LGv-CGUXMloLA8x91ocdu41g2Ft92wqPgFILA-8GzpGS1c5LtO-CJ6sM52V0_8b6DhJJpEo4vySYwtP9Rs8SUusr9ldGpDG_ySFk75XstXAw4BxpGhJOmDA0t_d2uJm0ABwSniSP57FI0lodzW0Z0UYAqINtUM4S1NlC2QD8EyAy5oD036QGdvdob9I42fpyHRmkdQ_HMLRQCKrfrB_Zc4W4NHGtskdz-9gyOaIbvTKGrcaDylME8UwoKp2TjrC4XdnlinOipL4Vlq6zUry_lx2PBKhYgTcLgY_vAPZvZ247xRRjP2s21mZiU04ZjRZlmbZWO3Ie9TcBhSyikQNmNxkTEtj_mFkjDV9vG8VKGVHbT50FvN9JgFnfqmMZdYVr0aCLkgjWnNnaHGeZfRrO5qCyI_KgMsCVRVxr97C0CJUKdT1r3nVFzxdDObyDM149i3KOB2AlLPyr7VloX6kPqHh6Cwr2htY2SDmWeUviXYHNr26jJKGGyeEuTXVmrSMRQgGfNDpYsQSjX5kkoliBhDkdJM_60VfUz6HXoq9qrzrUhnAEbveGTY58q1y0gJ_4_cE75gwQ0ZhYONg8cS770fjsI4euDvmyzf0h8TqZ3CRPuB-MC9ORxMxl71-dHcW3e0yUOKYJiTMCx_yoLizMQxqlw3xX4PWOHeZK2Mm7a_FRKGWwjutOFDxInDqfb_1P_OcMrCUHVx1vQUvhwEc9WJY3c3TIyf5OtuBtSqT5RIwZZH7Paf37hfg8rM_1BbbzMDQ82yjWSi8abIMBKlBJaViLWIYxIj5FdgwfHUCqBCRY1cNY5aCzIUcKM8NTP96FAS5fViw7Sdhvresq11nVmkEzbUFqzqJ7MxAuObj2YUGBziypY83__cRiyODGPk-ZfY4PuPS-1b0vFbiSSIu85AzuL8rTtosjXfGXOK8r2fw28_Sf3-PgNoHp_FMrLRiB7OdoI0VCEcSKZOm8WzX4oYCmwhPmaFRAgUWfCReRTH3gDVI5zRwhQa0_TQqqnxInmSQAQD3cQo",
                    "spiderX": "/spiderx.block" // 爬虫初始路径与参数，建议每个客户端不同
                }
            }
    
		},

    //dns出站
    {
      "tag": "dns-out",  
      "protocol": "dns",
      "settings": {
        "nonIPQuery": "drop" // 若不写此字段，将使用默认值 "drop"，阻止非 A 和 AAAA 记录查询，若设置为 "skip"，则允许非 A 和 AAAA 记录查询
            },
      "proxySettings": {
          "tag": "direct" // 当 "nonIPQuery" 设置为 "skip" 时，若不写此字段，将使用本地网络出站；若设置此字段，将使用对应 "tag" 出站，目的地址对应 "dns-in" 中的 "settings" 字段的内容
      }
           
        },
    // 用`blackhole`协议屏蔽流量，即当routing中指定'block'时，调用这个协议做处理
    {
      "tag": "block",
      "protocol": "blackhole"
    },

    //反向代理服务器（这里为了简单，采用了重定向功能到内部服务器（注意这个10845端口实际上在tag 为tunnel-src 的位置和服务器进行映射
    {
      "tag": "reverse-out-redirect",
       "protocol": "direct",
        "settings": {
                "redirect": "127.0.0.1:10845"
            }
    }
  ]
}
 ```


## 客户端配置（OneXray）
![客户端](png/client%201.jpg)
![客户端](png/client%202.jpg)


