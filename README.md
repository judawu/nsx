# NSX 安装管理脚本说明文档

## 介绍

NSX 安装管理脚本是一个用于部署和管理集成 Nginx、Sing-box 和 Xray 的代理环境的 Bash 脚本。该脚本支持 Docker 和本地安装模式，提供证书管理、配置修改、订阅生成、日志管理和卸载功能。

- **作者**：JudaWu
- **版本**：v0.0.3
- **网站**：[https://github.com/judawu/nsx](https://p4.juda.dpdns.org/)
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
  1. **配置 NSX 服务**：更新脚本和配置文件，重启服务。
  2. **修改 nginx.conf**：使用 nano 编辑，替换域名等，重载 Nginx。
  3. **修改 xray config.json**：
     - 替换域名、生成新 UUID/密码、Reality 密钥（x25519/ML-DSA65）。
     - 生成订阅链接和二维码。
     - 支持协议：VLESS, VMess, Trojan, Shadowsocks。
     - 重启 Xray。
  4. **修改 sing-box config.json**：
     - 类似 Xray，生成新 UUID/密码、Reality 密钥。
     - 支持协议：VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, Naive。
     - 重启 Sing-box。
  5. **退出**。
- **订阅文件**：`/usr/local/nsx/www/subscribe/{xray_sub.txt,singbox_sub.txt}`
- **注意**：配置更新会备份原文件（.bak）。Reality 设置仅在 JSON 中存在相应字段时更新。

## 订阅生成

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
 **手动修改订阅**。
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

  
  *例1*：
  ```
  vless://41a83310-1a69-4031-88b8-c21a7eba0e2a@p1.juda.dpdns.org:443?type=xhttp&host=&path=%2Freality%2Fxhttp&security=reality&pbk=dWrPthWzzXjYkzgbK40T-R51uI56vulNt0sXLMgdLWg&fp=chrome&sni=p1.juda.dpdns.org&sid=af3dd995&flow=#VLESS-XHTTP-REALITY
  ```
  其中sni=p1.juda.dpdns.org表示为你的分流域名，在nginx。conf的stream模块中，定义了不同域名分流到不同的sock进行代理服务，p1.juda.dpdns.org可能表示我的xray_tls_proxy代理，而p1.juda.dpdns.org表示xray_reality_proxy代理，上面的vless分享链接启用了reality，所以需要手动更改sni指向p2.juda.dpdns.org
  
  也就是：
  ```
vless://41a83310-1a69-4031-88b8-c21a7eba0e2a@p1.juda.dpdns.org:443?type=xhttp&host=&path=%2Freality%2Fxhttp&security=reality&pbk=dWrPthWzzXjYkzgbK40T-R51uI56vulNt0sXLMgdLWg&fp=chrome&sni=p2.juda.dpdns.org&sid=af3dd995&flow=#VLESS-XHTTP-REALITY
  ```
  *例2*：
  ```
  trojan://FLmu1Q9yx59XtENJnmR6yw==@p1.juda.dpdns.org:443?type=tcp&security=tls&fp=chrome&sni=p1.juda.dpdns.org#TROJAN-XHTTP-REALITY
  ```
  这条链接采用trojan协议，但是因为室通过fallback访问，所以分享链接需要改成和上面的vless类似，也就是：
  ```
   trojan://FLmu1Q9yx59XtENJnmR6yw==@p1.juda.dpdns.org:443?type=xhttp&host=&path=%2Freality%2Fxhttp&security=reality&pbk=dWrPthWzzXjYkzgbK40T-R51uI56vulNt0sXLMgdLWg&fp=chrome&sni=p2.juda.dpdns.org&sid=af3dd995&flow=#TROJAN-XHTTP-REALITY
```
 *例3*：
 
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
 vless://e5eef0e4-6a06-4281-aeba-63d8cc31869b@p1.juda.dpdns.org:443?type=grpc&serviceName=%2Freality%2Fgrpc%2Fh1%7Ch2&security=tls&fp=chrome&sni=p1.juda.dpdns.org&flow=#Vless_grpc
```
 需要改成
 ```
  vless://e5eef0e4-6a06-4281-aeba-63d8cc31869b@p1.juda.dpdns.org:443?type=grpc&serviceName=%2Freality%2Fgrpc%2Fh1&security=tls&fp=chrome&sni=p3.juda.dpdns.org&flow=#Vless_grpc
 ```
## 日志管理

查看或清除日志文件。

- **菜单选项**：6
- **子选项**：
  1. 查看 Nginx 访问日志（`tail -f /usr/local/nsx/log/nginx_access.log`）。
  2. 查看 Nginx 错误日志。
  3. 查看 Xray 访问日志。
  4. 查看 Sing-box 日志。
  5. 查看证书日志（最后 100 行）。
  6. 清除所有日志。
  7. 退出。
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

## 使用菜单

运行 `nsx` 或 `sudo bash install.sh` 进入主菜单：
- 1: 阅读说明
- 2: Docker 安装
- 3: 本地安装
- 4: 证书管理
- 5: 配置管理
- 6: 日志管理
- 7: 更新脚本
- 8: 停止 Docker
- 9: 生成订阅
- 10: 卸载
- 11: 退出


