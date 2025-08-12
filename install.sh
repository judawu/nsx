#!/usr/bin/env bash

# NSX 安装管理加博爱
# Project directory: /usr/local/nsx
# Supports Docker and local installation, certificate management, and configuration management

# Set language
export LANG=en_US.UTF-8

# 输出颜色
echoContent() {
    case $1 in
        "red") echo -e "\033[31m${2}\033[0m" ;;
        "green") echo -e "\033[32m${2}\033[0m" ;;
        "yellow") echo -e "\033[33m${2}\033[0m" ;;
        "skyblue") echo -e "\033[1;36m${2}\033[0m" ;;
    esac
}

# 定义变量
BASE_DIR="/usr/local/nsx"
CERT_DIR="${BASE_DIR}/certs"
NGINX_DIR="${BASE_DIR}/nginx"
XRAY_DIR="${BASE_DIR}/xray"
LOG_DIR="${BASE_DIR}/log"
SINGBOX_DIR="${BASE_DIR}/sing-box"
WWW_DIR="${BASE_DIR}/www"
SUBSCRIBE_DIR="${BASE_DIR}/www/subscribe"
COMPOSE_FILE="${BASE_DIR}/docker/docker-compose.yml"
NGINX_CONF="${NGINX_DIR}/nginx.conf"
XRAY_CONF="${XRAY_DIR}/config.json"
SINGBOX_CONF="${SINGBOX_DIR}/config.json"
SHM_DIR="/dev/shm/nsx"
NGINX_CACHE_DIR="${NGINX_DIR}/cache"
NGINX_RUN_DIR="${NGINX_DIR}/run"
NGINX_CONF_DIR="${NGINX_DIR}/conf.d"
ACME_DIR="${BASE_DIR}/acme"
ACME_LOG="${LOG_DIR}/acme.log"


# 检查系统信息
checkSystem() {
    echoContent skyblue "检查系统..."
    if [[ -n $(find /etc -name "redhat-release") ]] || grep -q -i "centos" /etc/os-release || grep -q -i "rocky" /etc/os-release; then
        release="centos"
        installCmd='yum -y install'
        upgradeCmd='yum -y update'
        updateCmd='yum -y update'
        uninstallCmd='yum -y remove'
    elif grep -q -i "ubuntu" /etc/os-release; then
        release="ubuntu"
        installCmd='apt -y install'
        upgradeCmd='apt -y upgrade'
        updateCmde='apt update'
        uninstallCmd='apt -y remove'
        
    elif grep -q -i "debian" /etc/os-release; then
        release="debian"
        installCmd='apt -y install'
        upgradeCmd='apt -y upgrade'
        updateCmd='apt update'
        uninstallCmd='apt -y remove'
    else
        echoContent red "不支持的操作系统，脚本仅支持 CentOS、Rocky Linux、Ubuntu 或 Debian."
        exit 1
    fi
    
    if [[ -n $(which uname) ]]; then
        if [[ "$(uname)" == "Linux" ]]; then
            case "$(uname -m)" in
            'amd64' | 'x86_64')
                xrayCoreCPUVendor="Xray-linux-64"
                v2rayCoreCPUVendor="v2ray-linux-64"
                warpRegCoreCPUVendor="main-linux-amd64"
                singBoxCoreCPUVendor="-linux-amd64"
                ;;
            'armv8' | 'aarch64')
                cpuVendor="arm"
                xrayCoreCPUVendor="Xray-linux-arm64-v8a"
                v2rayCoreCPUVendor="v2ray-linux-arm64-v8a"
                warpRegCoreCPUVendor="main-linux-arm64"
                singBoxCoreCPUVendor="-linux-arm64"
                ;;
            *)
                echo "  不支持此CPU架构--->"
                exit 1
                ;;
            esac
        fi
    else
        echoContent red "  无法识别此CPU架构，默认amd64、x86_64--->"
        xrayCoreCPUVendor="Xray-linux-64"
        v2rayCoreCPUVendor="v2ray-linux-64"
    fi


    LOCAL_IP=$(ip addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1)
    echoContent green "系统: $release"
    echoContent green "系统cpu: $(uname -m)"
    echoContent green "本地 IP: $LOCAL_IP"
}

# 检查 SELinux
checkCentosSELinux() {
    if [[ "$release" == "centos" ]] && [[ -f "/etc/selinux/config" ]] && ! grep -q "SELINUX=disabled" /etc/selinux/config; then
        echoContent yellow "禁用 SELinux 以确保兼容性..."
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

# 安装工具
installTools() {
    echoContent skyblue "\n安装工具..."
    echoContent green "\n安装以下依赖curl wget git sudo lsof unzip ufw socat jq iputils-ping dnsutils qrencode.."
    ${installCmd} curl wget git sudo lsof unzip ufw socat jq iputils-ping dnsutils qrencode -y
  
    if [[ "$release" != "centos" ]]; then
        echoContent green "\n执行系统更新..."
        ${upgradeCmd}
        ${updateCmd}

    fi
}

# 安装 Docker 和 Docker Compose
installDocker() {
    echoContent skyblue "Docker 安装..."
    if ! command -v docker &> /dev/null; then
        echoContent yellow "安装 Docker..."
        curl -fsSL https://get.docker.com | bash
        if [ $? -ne 0 ]; then
            echoContent red "安装 Docker 失败，请参考 https://docs.docker.com/engine/install/."
            exit 1
        fi
        systemctl enable docker
        systemctl start docker
    else
        echoContent green "Docker 已安装."
    fi

    # 检查 Docker Compose 插件
    if ! docker compose version &> /dev/null; then
        echoContent yellow "安装 Docker Compose 插件..."
        if [[ "$release" == "ubuntu" || "$release" == "debian" ]]; then
            ${updateCmd}
            ${upgradeCmd}
            ${installCmd} docker-compose-plugin
            if [ $? -ne 0 ]; then
                echoContent red "通过 apt 安装 Docker Compose 插件失败."
                exit 1
            fi
        elif [[ "$release" == "centos" ]]; then
            # 为 CentOS/Rocky Linux 安装 Docker Compose 插件二进制文件
            mkdir -p /usr/libexec/docker/cli-plugins
            curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/libexec/docker/cli-plugins/docker-compose
            chmod +x /usr/libexec/docker/cli-plugins/docker-compose
            if [ $? -ne 0 ]; then
                echoContent red "安装 Docker Compose 插件二进制文件失败."
                exit 1
            fi
        else
            echoContent red "不支持的操作系统，无法安装 Docker Compose 插件."
            exit 1
        fi
    else
        echoContent green "Docker Compose 插件已安装."
    fi

    # 验证 Docker Compose 版本
    docker compose version
    if [ $? -eq 0 ]; then
        echoContent green "Docker Compose 插件验证成功: $(docker compose version --short)"
    else
        echoContent red "Docker Compose 插件验证失败，请手动安装."
        exit 1
    fi
}

# 创建目录
createDirectories() {
    echoContent skyblue "\n创建目录..."
    for DIR in "$CERT_DIR" "$NGINX_DIR" "$LOG_DIR" "$NGINX_CACHE_DIR" "$NGINX_RUN_DIR" "$NGINX_CONF_DIR" "$XRAY_DIR"  "$SINGBOX_DIR" "$WWW_DIR"  "$SUBSCRIBE_DIR" "$WWW_DIR/wwwroot/blog" "$WWW_DIR/wwwroot/video" "$SHM_DIR" "$ACME_DIR"; do
        if [ ! -d "$DIR" ]; then
            echoContent yellow "创建目录 $DIR..."
            mkdir -p "$DIR"
        else
            echoContent green "目录 $DIR 已存在."
        fi
    done

    echoContent yellow "设置权限..."
    chown -R nobody:nogroup "$SHM_DIR" "$LOG_DIR" "$CERT_DIR" "$NGINX_CACHE_DIR" "$NGINX_RUN_DIR" "$NGINX_CONF_DIR" "$ACME_DIR"
    chmod -R 700  "$CERT_DIR" "$NGINX_CACHE_DIR" "$NGINX_RUN_DIR" "$NGINX_CONF_DIR" "$ACME_DIR"
    chmod -R 766  "$SHM_DIR" "$LOG_DIR"
}

# 安装 acme.sh
installAcme() {
    if [[ ! -d "$HOME/.acme.sh" ]] || [[ -d "$HOME/.acme.sh" && -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
        echoContent skyblue "\n进度 4/${TOTAL_PROGRESS} : 安装证书程序 acme.sh..."
        curl https://get.acme.sh | sh
        if [[ $? -ne 0 ]]; then
            echoContent red "安装 acme.sh 失败，请参考 https://github.com/acmesh-official/acme.sh."
            exit 1
        fi
    else
        echoContent green "acme.sh 已安装."
    fi
}
# 管理证书
manageCertificates() {
    # Define defaults
    ACME_LOG="${ACME_LOG:-/var/log/acme.log}"
    CERT_DIR="${CERT_DIR:-/etc/ssl/private}"
    CREDENTIALS_FILE="${HOME}/.acme.sh/credentials.conf"
    mkdir -p "$CERT_DIR" || { echoContent red "无法创建 $CERT_DIR"; exit 1; }
    touch "$CREDENTIALS_FILE" && chmod 600 "$CREDENTIALS_FILE" || { echoContent red "无法创建 $CREDENTIALS_FILE"; exit 1; }

    echoContent skyblue "\n证书管理菜单"
    echoContent yellow "1. 申请证书"
    echoContent yellow "2. 更新证书"
    echoContent yellow "3. 安装自签证书"
    echoContent yellow "4. 退出"
    read -r -p "请选择一个选项 [1-4]: " cert_option

    case $cert_option in
        1|2)
            local action="--issue"
            [[ "$cert_option" == "2" ]] && action="--renew"
            echoContent skyblue "${action##--}证书..."
            read -r -p "确认 SSL 类型为 letsencrypt 还是 zerossl (y=letsencrypt, n=zerossl): " selectSSLType
            if [[ -n "$selectSSLType" && "$selectSSLType" == "n" ]]; then
                sslType="zerossl"
                read -r -p "请输入你的邮箱注册zerossl(要和你的DNS邮箱一致)回车默认已注册zerossl: " regZeroSSLEmail
                if [[ -n "$regZeroSSLEmail" ]]; then
                 sudo "$HOME/.acme.sh/acme.sh" --register-account -m "$regZeroSSLEmail" --server zerossl
                fi
            else
                sslType="letsencrypt"
            fi
            echoContent skyblue " SSL 类型为 $sslType."
            read -r -p "请输入证书域名 (例如: yourdomain.com 或 *.yourdomain.com，多个域名用逗号隔开): " DOMAIN
            if [[ -z "$DOMAIN" ]]; then
                echoContent red "请输入域名"
                return 1
            fi
            # 提取第一个域名用于证书命名
            FIRST_DOMAIN=$(echo "$DOMAIN" | cut -d',' -f1 | xargs)
            echoContent skyblue " 证书域名为 $DOMAIN (使用 $FIRST_DOMAIN 作为证书文件名)."
            read -r -p "请输入DNS提供商: 0.Cloudflare, 1.阿里云, 2.手动DNS, 3.独立: " DNS_VENDOR

            if [[ "$cert_option" == "1" ]]; then
                # 清除此域名的先前凭据
                grep -v "^${FIRST_DOMAIN}:" "$CREDENTIALS_FILE" > "${CREDENTIALS_FILE}.tmp" && mv "${CREDENTIALS_FILE}.tmp" "$CREDENTIALS_FILE"
            fi
            echoContent skyblue " DNS提供商选择 $DNS_VENDOR."
            if [[ "$DNS_VENDOR" == "0" ]]; then
 
                if [[ "$cert_option" == "2" && -s "$CREDENTIALS_FILE" ]] && grep -q "^${FIRST_DOMAIN}:Cloudflare:" "$CREDENTIALS_FILE"; then
                    # 为续订加载保存的 Cloudflare 凭据
                    IFS=':' read -r _ _ cf_type cf_value1 cf_value2 < <(grep "^${FIRST_DOMAIN}:Cloudflare:" "$CREDENTIALS_FILE")
                    if [[ "$cf_type" == "token" ]]; then
                        cfAPIToken="$cf_value1"
                    else
                        cfAPIEmail="$cf_value1"
                        cfAPIKey="$cf_value2"
                    fi
                    echoContent green "使用保存的 Cloudflare 凭据进行续订"
                else
                    read -r -p "请输入 Cloudflare API Token (推荐) 或按回车使用邮箱和API Key: " cfAPIToken
                    if [[ -n "$cfAPIToken" ]]; then
                        echoContent green "保存 Cloudflare API Token $cfAPIToken"
                        echo "${FIRST_DOMAIN}:Cloudflare:token:${cfAPIToken}" >> "$CREDENTIALS_FILE"
                    else
                        read -r -p "请输入 Cloudflare Email: " cfAPIEmail
                        read -r -p "请输入 Cloudflare Global API Key: " cfAPIKey
                        if [[ -z "${cfAPIEmail}" || -z "${cfAPIKey}" ]]; then
                            echoContent red "输入为空，请重试"
                            return 1
                        fi
                        echoContent green " 保存 Cloudflare Email $cfAPIEmail 和 Global API Key $cfAPIKey"
                        echo "${FIRST_DOMAIN}:Cloudflare:key:${cfAPIEmail}:${cfAPIKey}" >> "$CREDENTIALS_FILE"
                    fi
                fi
                echoContent green " Cloudflare DNS API ${action##--}证书中"
                if [[ -n "$cfAPIToken" ]]; then
                    if ! sudo CF_Token="${cfAPIToken}" "$HOME/.acme.sh/acme.sh" $action -d "${DOMAIN}" --dns dns_cf -k ec-256 --server "${sslType}" 2>&1 | tee -a "$ACME_LOG"; then
                       sudo rm -rf "$HOME/.acme.sh/${FIRST_DOMAIN}_ecc"
                       echoContent red "请检查 $ACME_LOG 日志以获取详细信息"
                       exit 1
                    fi
                    unset CF_Token
                else
                    if ! sudo CF_Email="${cfAPIEmail}" CF_Key="${cfAPIKey}" "$HOME/.acme.sh/acme.sh" $action -d "${DOMAIN}" --dns dns_cf -k ec-256 --server "${sslType}" 2>&1 | tee -a "$ACME_LOG"; then
                        sudo rm -rf "$HOME/.acme.sh/${FIRST_DOMAIN}_ecc"
                        echoContent red "请检查 $ACME_LOG 日志以获取详细信息"
                        exit 1
                    fi
                    unset CF_Email CF_Key
                fi
            elif [[ "$DNS_VENDOR" == "1" ]]; then
                if [[ "$cert_option" == "2" && -s "$CREDENTIALS_FILE" ]] && grep -q "^${FIRST_DOMAIN}:Alibaba:" "$CREDENTIALS_FILE"; then
                    # 为续订加载保存的 Alibaba 凭据
                    IFS=':' read -r _ _ aliKey aliSecret < <(grep "^${FIRST_DOMAIN}:Alibaba:" "$CREDENTIALS_FILE")
                    echoContent green " 使用保存的阿里云凭据进行续订"
                else
                    read -r -p "请输入阿里云 Key: " aliKey
                    read -r -p "请输入阿里云 Secret: " aliSecret
                    if [[ -z "${aliKey}" || -z "${aliSecret}" ]]; then
                        echoContent red " 输入为空，请重试"
                        return 1
                    fi
                    echoContent green "保存阿里云 Key 和 Secret"
                    echo "${FIRST_DOMAIN}:Alibaba:${aliKey}:${aliSecret}" >> "$CREDENTIALS_FILE"
                fi
                echoContent green " 阿里云 DNS API ${action##--}证书中"
                if ! sudo Ali_Key="${aliKey}" Ali_Secret="${aliSecret}" "$HOME/.acme.sh/acme.sh" $action -d "${DOMAIN}" --dns dns_ali -k ec-256 --server "${sslType}" 2>&1 | tee -a "$ACME_LOG"; then
                    echoContent red "证书签发失败，清理残留数据并退出"
                    sudo rm -rf "$HOME/.acme.sh/${FIRST_DOMAIN}_ecc"
                    echoContent red "请检查 $ACME_LOG 日志以获取详细信息"
                    exit 1
                fi
                unset Ali_Key Ali_Secret
            elif [[ "$DNS_VENDOR" == "2" ]]; then
                echoContent yellow "手动 DNS 模式，请添加 TXT 记录:（例如在cloudware中在DNS下手动建立TXT文件，将下面的字符串输入）"
                if ! sudo "$HOME/.acme.sh/acme.sh" $action -d "${DOMAIN}" --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please -k ec-256 --server "${sslType}" 2>&1 | tee -a "$ACME_LOG"; then
                    echoContent red "证书签发失败，清理残留数据并退出"
                    sudo rm -rf "$HOME/.acme.sh/${FIRST_DOMAIN}_ecc"
                    echoContent red "请检查 $ACME_LOG 日志以获取详细信息"
                fi
                txtValue=$(tail -n 10 "$ACME_LOG" | grep "TXT value" | awk -F "'" '{print $2}' | head -1)
                if [[ -n "$txtValue" ]]; then
                    echoContent green "  名称: _acme-challenge"
                    echoContent green " 值: ${txtValue}"
                    echoContent yellow " 请添加 TXT 记录（例如在cloudware中在DNS下手动建立TXT文件，将下面的字符串${txtValue}输入）并等待 1-2 分钟"
                    read -r -p "是否已添加 TXT 记录? [y/n]: " addDNSTXTRecordStatus
                    if [[ "$addDNSTXTRecordStatus" == "y" ]]; then
                        txtAnswer=$(dig @1.1.1.1 +nocmd "_acme-challenge.${FIRST_DOMAIN}" txt +noall +answer | awk -F "[\"]" '{print $2}' | head -1)
                        if echo "$txtAnswer" | grep -q "^${txtValue}"; then
                            echoContent green "TXT 记录验证通过"
                            if ! sudo "$HOME/.acme.sh/acme.sh" $action -d "${DOMAIN}" --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please -k ec-256 --server "${sslType}" 2>&1 | tee -a "$ACME_LOG"; then
                                   echoContent red "证书签发失败，清理残留数据并退出"
                                   sudo rm -rf "$HOME/.acme.sh/${FIRST_DOMAIN}_ecc"
                                   echoContent red "请检查 $ACME_LOG 日志以获取详细信息"
                            fi
                        else
                            echoContent red "TXT 记录验证失败"
                            exit 1
                        fi
                    fi
                fi
            elif [[ "$DNS_VENDOR" == "3" ]]; then
                echoContent green " ---> 独立模式 ${action##--}证书中"
                if ! sudo "$HOME/.acme.sh/acme.sh" $action -d "${DOMAIN}" --standalone -k ec-256 --server "${sslType}" 2>&1 | tee -a "$ACME_LOG"; then
                    echoContent red "命令失败，请检查 $ACME_LOG 日志"
                    exit 1
                fi
            else
                echoContent red "无效 DNS 提供商"
                return 1
            fi

            echoContent yellow "安装证书..."
            if [[ ! -f "$HOME/.acme.sh/${FIRST_DOMAIN}_ecc/fullchain.cer" ]]; then
                echoContent red "证书文件未生成，清理残留数据并退出"
                sudo rm -rf "$HOME/.acme.sh/${FIRST_DOMAIN}_ecc"
                echoContent red "请检查 $ACME_LOG 日志以获取详细信息"
                exit 1
            fi
            if ! sudo "$HOME/.acme.sh/acme.sh" --install-cert -d "${FIRST_DOMAIN}" --ecc \
                --fullchain-file "${CERT_DIR}/${FIRST_DOMAIN}.pem" \
                --key-file "${CERT_DIR}/${FIRST_DOMAIN}.key" 2>&1 | tee -a "$ACME_LOG"; then
                echoContent red "证书安装失败，请检查 $ACME_LOG 日志"
                exit 1
            fi
            chmod 644 "${CERT_DIR}/${FIRST_DOMAIN}.pem"
            chmod 644 "${CERT_DIR}/${FIRST_DOMAIN}.key"
            echoContent green "证书${action##--}并安装成功"
            ;;
        3)
            echoContent skyblue "安装自签证书..."
            if ! command -v openssl &>/dev/null; then
                echoContent yellow "安装 openssl..."
                ${installCmd:-apt install -y} openssl
                if [[ $? -ne 0 ]]; then
                    echoContent red "安装 openssl 失败，请手动安装"
                    exit 1
                fi
            fi
            read -r -p "请输入自签证书域名 (例如: sub.yourdomain.com): " DOMAIN
            if [[ -z "$DOMAIN" ]]; then
                echoContent red "请输入域名"
                return 1
            fi
            echoContent skyblue "为 ${DOMAIN} 生成自签证书..."
            touch /tmp/openssl-san.cnf || { echoContent red "无法写入 /tmp"; exit 1; }
            cat > /tmp/openssl-san.cnf << EOF
[req]
default_bits = 256
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = ${DOMAIN}

[req_ext]
subjectAltName = DNS:${DOMAIN}
EOF
            if ! openssl ecparam -name secp256r1 -genkey -out "${CERT_DIR}/${DOMAIN}.key" 2>>"$ACME_LOG"; then
                echoContent red "生成私钥失败，请检查 $ACME_LOG 日志"
                exit 1
            fi
            if ! openssl req -x509 -new -key "${CERT_DIR}/${DOMAIN}.key" -days 365 -out "${CERT_DIR}/${DOMAIN}.pem" \
                -config /tmp/openssl-san.cnf -extensions req_ext 2>>"$ACME_LOG"; then
                echoContent red "生成自签证书失败，请检查 $ACME_LOG 日志"
                exit 1
            fi
            rm -f /tmp/openssl-san.cnf
            chmod 644 "${CERT_DIR}/${DOMAIN}.pem"
            chmod 644 "${CERT_DIR}/${DOMAIN}.key"
            echoContent green "自签证书生成并安装成功，位于 ${CERT_DIR}/${DOMAIN}.pem"
            ;;
        4)
            return
            ;;
        *)
            echoContent red "无效选项，请重试"
            return 1
            ;;
    esac
    if [[ "$cert_option" == "1" || "$cert_option" == "2" ]]; then
        echoContent yellow "清除 TXT 记录..."
        if ! sudo "$HOME/.acme.sh/acme.sh" --remove -d "${FIRST_DOMAIN}" --dns 2>&1 | tee -a "$ACME_LOG"; then
            echoContent red "清除 TXT 记录失败，请检查 $ACME_LOG 日志"
        else
            echoContent green "TXT 记录已清除"
        fi
    fi
    # Schedule renewal for Cloudflare or Alibaba DNS if credentials were saved
    if [[ "$cert_option" == "1" && ("$DNS_VENDOR" == "0" || "$DNS_VENDOR" == "1") ]]; then
        echoContent yellow "设置每3个月自动续订证书..."
        local cron_cmd
        if [[ "$DNS_VENDOR" == "0" ]]; then
            if [[ -n "$cfAPIToken" ]]; then
                cron_cmd="CF_Token=\"\$(grep '^${FIRST_DOMAIN}:Cloudflare:token:' \"${CREDENTIALS_FILE}\" | cut -d':' -f4)\" \"$HOME/.acme.sh/acme.sh\" --renew -d "${DOMAIN}" --dns dns_cf -k ec-256 --server ${sslType} --install-cert -d \"${FIRST_DOMAIN}\" --ecc --fullchain-file \"${CERT_DIR}/${FIRST_DOMAIN}.pem\" --key-file \"${CERT_DIR}/${FIRST_DOMAIN}.key\" 2>&1 | tee -a \"$ACME_LOG\""
            else
                cron_cmd="CF_Email=\"\$(grep '^${FIRST_DOMAIN}:Cloudflare:key:' \"${CREDENTIALS_FILE}\" | cut -d':' -f4)\" CF_Key=\"\$(grep '^${FIRST_DOMAIN}:Cloudflare:key:' \"${CREDENTIALS_FILE}\" | cut -d':' -f5)\" \"$HOME/.acme.sh/acme.sh\" --renew -d "${DOMAIN}" --dns dns_cf -k ec-256 --server ${sslType} --install-cert -d \"${FIRST_DOMAIN}\" --ecc --fullchain-file \"${CERT_DIR}/${FIRST_DOMAIN}.pem\" --key-file \"${CERT_DIR}/${FIRST_DOMAIN}.key\" 2>&1 | tee -a \"$ACME_LOG\""
            fi
        elif [[ "$DNS_VENDOR" == "1" ]]; then
            cron_cmd="Ali_Key=\"\$(grep '^${FIRST_DOMAIN}:Alibaba:' \"${CREDENTIALS_FILE}\" | cut -d':' -f3)\" Ali_Secret=\"\$(grep '^${FIRST_DOMAIN}:Alibaba:' \"${CREDENTIALS_FILE}\" | cut -d':' -f4)\" \"$HOME/.acme.sh/acme.sh\" --renew -d "${DOMAIN}" --dns dns_ali -k ec-256 --server ${sslType} --install-cert -d \"${FIRST_DOMAIN}\" --ecc --fullchain-file \"${CERT_DIR}/${FIRST_DOMAIN}.pem\" --key-file \"${CERT_DIR}/${FIRST_DOMAIN}.key\" 2>&1 | tee -a \"$ACME_LOG\""
        fi
        (crontab -l 2>/dev/null | grep -v "${FIRST_DOMAIN}.*acme.sh --renew"; echo "0 3 1 */3 * $cron_cmd") | crontab -
        echoContent green "已为 ${FIRST_DOMAIN} 设置每3个月自动续订"
    fi
}

url_encode() {
    local input="$1"
    if ! command -v jq &> /dev/null; then
        echo "Error: jq is not installed" >&2
        return 1
    fi
    local encoded
    encoded=$(printf '%s' "$input" | jq -nr --arg v "$input" '$v | @uri' | sed 's/%23/#/' 2>/dev/null) || {
        echo "Error: URL encoding failed" >&2
        return 1
    }
    printf '%s' "$encoded"
}
xray_config(){
        echoContent skyblue "\nxray配置文件修改"
   
        # 检查 jq 和 xray 是否已安装
        if ! command -v jq &> /dev/null; then
            echoContent red "jq 没有安装，请先安装jq" 
            exit 1
        fi

        if ! command -v xray &> /dev/null; then
            echoContent red "xray 没有安装或者没有进行软链接，请先安装xray或者使用 ln -sf /usr/local/nsx/xray/xray /usr/bin/xray生产软连接" 
            exit 1
        fi

        # JSON 文件路径

        TEMP_FILE="/tmp/xray_config_temp.json"
        echoContent green "临时文件位置$TEMP_FILE"
        # 检查 config.json 是否存在
        if [[ ! -f "$XRAY_CONF" ]]; then
            echoContent red "$XRAY_CONF 不存在"
            exit 1
        fi
        # Create subscription directory if not exists
        if [ ! -d "$SUBSCRIBE_DIR" ]; then
                mkdir -p "$SUBSCRIBE_DIR"
                chown nobody:nogroup "$SUBSCRIBE_DIR"
                chmod 755 "$SUBSCRIBE_DIR"
        fi

        # Generate Xray subscription
        if [ -f "$XRAY_CONF" ]; then
                echoContent yellow "生成 Xray 订阅..."
                XRAY_SUB_FILE="${SUBSCRIBE_DIR}/xray_sub.txt"
                > "$XRAY_SUB_FILE"
        fi
        # 获取用户输入的域名
        echoContent skyblue "请手动输入域名\n"
        read -p "请输入域名替换文件中 'yourdomain' (e.g., example.com): " YOURDOMAIN
        if [[ -z "$YOURDOMAIN" ]]; then
            echoContent red "Error: 域名不能为空."
            exit 1
        fi

        # 备份原始文件
        cp "$XRAY_CONF" "${XRAY_CONF}.bak" || {
        echoContent red "Error: Failed to create backup ${XRAY_CONF}.bak"
        exit 1
        }
        echoContent green "创建备份: ${XRAY_CONF}.bak"

       generate_short_ids() {
            short_id1=$(openssl rand -hex 4)  # 8 字节
            short_id2=$(openssl rand -hex 8)  # 16 字节
            echo "[\"$short_id1\", \"$short_id2\"]"
        }

        echoContent green "\n创建一个临时 JSON 文件$TEMP_FILE，复制原始内容$XRAY_CONF"
        cp "$XRAY_CONF" "$TEMP_FILE" || {
        echoContent red "Error: Failed to create temporary file $TEMP_FILE"
        exit 1
        }
        # 替换 yourdomain 为用户输入的域名
        jq --arg domain "$YOURDOMAIN" \
        'walk(if type == "string" then gsub("yourdomain"; $domain) else . end)' \
        "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE" || {
        echoContent red "Error: Failed to update domain."
        exit 1
        }



        echoContent green  "提取所有 inbounds\n"
        # 提取所有 inbounds
        inbounds=$(jq -c '.inbounds[] | select(.settings.clients)' "$TEMP_FILE")
        #echoContent green "$inbounds"


        # 遍历每个 inbound
        jq -c '.inbounds[] | select(.settings.clients)' "$TEMP_FILE" | while IFS= read -r inbound; do
            declare -g url=""
            tag=$(echo "$inbound" | jq -r '.tag')
            protocol=$(echo "$inbound" | jq -r '.protocol')
            port=$(echo "$inbound" | jq -r '.port')
            if [[ "$port" == "null" || -z "$port" ]]; then
            port="443"
            fi
            echoContent skyblue "\n处理 inbound tag: $tag, protocol: $protocol"
            network=$(echo "$inbound" | jq -r '.streamSettings.network // "tcp"')
            url="$url?type=$network"
            case "$network" in
                        "grpc") 
                        serviceName=$(echo "$inbound" | jq -r '.streamSettings.grpcSettings.serviceName') 
                        serviceName=$(url_encode "$serviceName")
                        url="$url&serviceName=$serviceName"
                        ;;
                        "ws") 
                        path=$(echo "$inbound" | jq -r '.streamSettings.wsSettings.path') 
                        path=$(url_encode "$path")
                        url="$url&path=$path"
                        ;;
                        "xhttp") 
                        xhttpSettings=$(echo "$inbound" | jq -r '.streamSettings.xhttpSettings')
                        host=$(echo "$xhttpSettings" | jq -r '.host')
                        path=$(echo "$xhttpSettings" | jq -r '.path')
                        host=$(url_encode "$host")
                        path=$(url_encode "$path")
                        url="$url&host=$host&path=$path"
                        ;;
                        "splithttp") 
                        path=$(echo "$inbound" | jq -r '.streamSettings.splithttpSettings.path')
                        path=$(url_encode "$path")
                        url="$url&path=$path"
                        ;;
                        "httpupgrade")
                        path=$(echo "$inbound" | jq -r '.streamSettings.httpupgradeSettings.path') 
                        path=$(url_encode "$path")
                        url="$url&path=$path"
                        ;;
                        "kcp")
                        seed=$(echo "$inbound" | jq -r '.streamSettings.kcpSettings.seed')
                        seed=$(url_encode "$seed")
                        url="$url&seed=$seed"
                        ;;
                        *) 
                        ;;
            esac
            # 检查 streamSettings.security 是否为 reality
            security=$(echo "$inbound" | jq -r '.streamSettings.security // "none"')
            if [[ "$security" == "reality" ]]; then
                echoContent green "\n检查 streamSettings:  reality security for $tag, updating keys and settings..."

                # 生成公私密钥对
                echoContent green "\n用xray x25519 生成公私匙\n用openssl rand -hex 4生成随机的 shortIds\n用xray mldsa65生成mldsa65 seed和verfify"
                key_pair=$(xray x25519)
                private_key=$(echo "$key_pair" | grep "Private key" | awk '{print $3}')
                public_key=$(echo "$key_pair" | grep "Public key" | awk '{print $3}')
                new_short_ids=$(generate_short_ids)
                new_mldsa65_key_pair=$(xray mldsa65) || {
                    echoContent red "Error: Failed to generate mldsa65 key pair."
                    exit 1
                    }
                mldsa65_seed=$(echo "$new_mldsa65_key_pair" | grep "Seed" | awk '{print $2}')
                mldsa65_verify=$(echo "$new_mldsa65_key_pair" | grep "Verify" | awk '{print $2}')

                echoContent yellow "\nGenerated new privateKey: $private_key"
                echoContent yellow "\nGenerated new publicKey: $public_key"
                echoContent yellow "\nGenerated new shortIds: $new_short_ids"
                echoContent yellow "\nGenerated new mldsa65Seed: $mldsa65_seed"
                echoContent yellow "\nGenerated new mldsa65Verify: $mldsa65_verify"

                # 更新 privateKey, publicKey, shortIds, mldsa65Seed
                jq --arg tag "$tag" --arg private_key "$private_key" --arg public_key "$public_key" --argjson short_ids "$new_short_ids" --arg mldsa65_seed "$mldsa65_seed"  --arg mldsa65_verify "$mldsa65_verify" \
                '(.inbounds[] | select(.tag == $tag) | .streamSettings.realitySettings) |=
                    (.privateKey = $private_key | .password = $public_key | .shortIds = $short_ids | .mldsa65Seed = $mldsa65_seed | .mldsa65Verify = $mldsa65_verify)' \
                "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE" || {
                    echoContent red "Error: Failed to update reality settings."
                    exit 1
                    }
                short_id=$(echo "$new_short_ids" | jq -r '.[0]') # 取第一个 short_id
                url="$url&security=reality&pbk=$public_key&fp=chrome&sni=$YOURDOMAIN&sid=$short_id&pqv=$mldsa65_verify#$tag"
            
            elif [[ "$security" == "tls" ]]; then
                        tlsSettings=$(echo "$inbound" | jq -r '.streamSettings.tlsSettings')
                        fp=$(echo "$tlsSettings" | jq -r '.fingerprint // "chrome"')
                        sni=$(echo "$tlsSettings" | jq -r '.serverName // "$YOURDOMAIN"')
                        alpn=$(echo "$inbound" | jq -r '.tls.alpn // "h2,http/1.1"')

                        # 如果 alpn 是数组，则将其转换为逗号分隔的字符串
                        if [[ "$alpn" == \[*\] ]]; then
                            alpn=$(echo "$alpn" | jq -r 'join(",")')
                        fi
                      
                        url="$url&security=tls&fp=$fp&sni=$YOURDOMAIN&alpn=$alpn#$tag"
            else
                url="$url#$tag"
            
            fi

            # 处理 vless 和 vmess 的 id 替换
            if [[ "$protocol" == "vless" || "$protocol" == "vmess" ]]; then
                echoContent green "\n处理 vless 和 vmess 的 id 替换,用 xray uuid 生成新的uuid替换"
                clients=$(echo "$inbound" | jq -c '.settings.clients[]')
                client_index=0
                echo "$clients" | while IFS= read -r client; do
                    old_id=$(echo "$client" | jq -r '.id')
                    new_id=$(xray uuid) || {
                    echoContent red "Error: Failed to generate UUID."
                    exit 1
                    }
                url="$protocol://$new_id@$YOURDOMAIN:$port$url"
                echoContent yellow "\n替换 $client_index UUID, $tag: $old_id -> $new_id \n"
                # 更新 id
                jq --arg tag "$tag" --arg old_id "$old_id" --arg new_id "$new_id" \
                '(.inbounds[] | select(.tag == $tag) | .settings.clients[] | select(.id == $old_id)).id = $new_id' \
                "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE" || {
                        echoContent red "Error: Failed to update UUID."
                        exit 1
                        }
                echo "$url" >> "$XRAY_SUB_FILE"
                echoContent skyblue "\n生成 $protocol 订阅链接: $url" 
                qrencode -t ANSIUTF8 "$url"
                qrencode -o "${SUBSCRIBE_DIR}/$protocol_${tag//[@\/]/_}.png" "$url" 2>/dev/null || echoContent red "生成二维码失败: $url"
                
                ((client_index++))
                done
                
            fi

            # 处理 trojan 和 shadowsocks 的 password 替换
            if [[ "$protocol" == "trojan" || "$protocol" == "shadowsocks" ]]; then
                echoContent green "\n处理 trojan 和 shadowsocks 的 password 替换,用openssl rand -base64 16 生成新密码"
                clients=$(echo "$inbound" | jq -c '.settings.clients[]')
                client_index=0
                echo "$clients" | while IFS= read -r client; do
                    old_password=$(echo "$client" | jq -r '.password')
                    new_password=$(openssl rand -base64 16)  # 生成 16 字节的 base64 密码
                    url="$protocol://$new_password@$YOURDOMAIN:$port$url"
                    echoContent yellow "\n替换 $client_index password $tag: $old_password -> $new_password \n"

                    # 更新 password
                    jq --arg tag "$tag" --arg old_password "$old_password" --arg new_password "$new_password" \
                    '(.inbounds[] | select(.tag == $tag) | .settings.clients[] | select(.password == $old_password)).password = $new_password' \
                    "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE" || {
                        echoContent red "Error: Failed to update password."
                        exit 1
                        }
                    echo "$url" >> "$XRAY_SUB_FILE"
                    echoContent skyblue "\n生成 $protocol 订阅链接: $url" 
                    qrencode -t ANSIUTF8 "$url"
                    qrencode -o "${SUBSCRIBE_DIR}/$protocol_${tag//[@\/]/_}.png" "$url" 2>/dev/null || echoContent red "生成二维码失败: $url"
                 
                    ((client_index++))        
                done
            fi
           
           
        
            # 在构造 URL 时使用：
           
           

        done

        # 替换原始文件
            mv "$TEMP_FILE" "$XRAY_CONF" || {
                echoContent red "Error: Failed to replace $XRAY_CONF"
                exit 1
                }
        echoContent skyblue "已为 $XRAY_CONF更新了新的 UUIDs, passwords, reality settings设置，并更新了域名$YOURDOMAIN."

        # 验证 JSON 文件是否有效
        if jq empty "$XRAY_CONF" &> /dev/null; then
            echoContent skyblue "JSON 有效.可以进行服务重启了。"
        
        else
            echoContent red "Error: 更新 JSON file 无效. 恢复备份."
            mv "${XRAY_CONF}.bak" "$XRAY_CONF"
            exit 1
        fi
}
singbox_config() {
    echoContent skyblue "\nsingbox配置文件修改"

    # 定义默认变量
    TEMP_FILE="/tmp/singbox_config_temp.json"

    # 清理临时文件
    trap 'rm -f "$TEMP_FILE" "${TEMP_FILE}.tmp" 2>/dev/null' EXIT

    # 检查变量
    if [[ -z "$SINGBOX_CONF" || -z "$SUBSCRIBE_DIR" ]]; then
        echoContent red "Error: SINGBOX_CONF or SUBSCRIBE_DIR is not set."
        exit 1
    fi

    # 检查文件权限
    if [[ ! -r "$SINGBOX_CONF" || ! -w "$SINGBOX_CONF" ]]; then
        echoContent red "Error: $SINGBOX_CONF is not readable or writable."
        exit 1
    fi

    # 检查 jq 和 sing-box
    if ! command -v jq &> /dev/null; then
        echoContent red "Error: jq 没有安装. 请先安装."
        exit 1
    fi
    if ! command -v sing-box &> /dev/null; then
        echoContent red "Error: sing-box 没有安装. 请先安装."
        exit 1
    fi

    # 检查 qrencode 依赖（用于生成二维码）
    if ! command -v qrencode &> /dev/null; then
        echoContent yellow "Warning: qrencode is not installed, skipping QR code generation."
        QRENCODE_AVAILABLE=false
    else
        QRENCODE_AVAILABLE=true
    fi

    # 检查 config.json
    if [[ ! -f "$SINGBOX_CONF" ]]; then
        echoContent red "Error: $SINGBOX_CONF不存在"
        exit 1
    fi

    # 创建订阅目录
    if [ ! -d "$SUBSCRIBE_DIR" ]; then
        mkdir -p "$SUBSCRIBE_DIR" || {
            echoContent red "Error: Failed to create directory $SUBSCRIBE_DIR"
            exit 1
        }
        chown nobody:nogroup "$SUBSCRIBE_DIR"
        chmod 755 "$SUBSCRIBE_DIR"
    fi

    # 生成订阅文件
    echoContent yellow "生成 Sing-box 订阅..."
    SINGBOX_SUB_FILE="${SUBSCRIBE_DIR}/singbox_sub.txt"
    > "$SINGBOX_SUB_FILE"

    # 获取用户输入的域名
    echoContent skyblue "请手动输入域名\n"
    read -p "请输入域名替换文件中 'yourdomain' (e.g., example.com): " SINGBOXDOMAIN
    if [[ -z "$SINGBOXDOMAIN" ]]; then
        echoContent red "Error: Domain cannot be empty."
        exit 1
    fi

    # 备份原始文件
    cp "$SINGBOX_CONF" "${SINGBOX_CONF}.bak" || {
        echoContent red "Error: Failed to create backup ${SINGBOX_CONF}.bak"
        exit 1
    }
    echoContent green "Backup created: ${SINGBOX_CONF}.bak"

   generate_short_ids() {
    short_id=$(openssl rand -hex 8)  # 16 字节
    echo "[\"\", \"$short_id\"]"
}

    # 创建临时 JSON 文件
    cp "$SINGBOX_CONF" "$TEMP_FILE" || {
        echoContent red "Error: Failed to create temporary file $TEMP_FILE"
        exit 1
    }

    # 替换 yourdomain 为用户输入的域名
    jq --arg domain "$SINGBOXDOMAIN" \
       'walk(if type == "string" then gsub("yourdomain"; $domain) else . end)' \
       "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE" || {
        echoContent red "Error: Failed to update domain."
        exit 1
    }

    # 提取所有 inbounds
    echoContent skyblue "\n提取所有 inbounds里的users\n"
    jq -c '.inbounds[] | select(.users)' "$TEMP_FILE" | while IFS= read -r inbound; do
        # 初始化 URL
        url=""

        tag=$(echo "$inbound" | jq -r '.tag')
        type=$(echo "$inbound" | jq -r '.type')
        port=$(echo "$inbound" | jq -r '.listen_port // "443"')
        echoContent skyblue "\nProcessing inbound with tag: $tag, type: $type, port: $port"
         # 添加传输协议参数
        transport=$(echo "$inbound" | jq -r '.transport.type // "tcp"')
        url="?type=$transport"
        case "$transport" in
            "grpc")
                serviceName=$(echo "$inbound" | jq -r '.transport.service_name // empty')
                if [[ -n "$serviceName" ]]; then
                    serviceName=$(url_encode "$serviceName")
                    url="$url&serviceName=$serviceName"
                fi
                ;;
            "ws")
                path=$(echo "$inbound" | jq -r '.transport.path // empty')
                if [[ -n "$path" ]]; then
                    path=$(url_encode "$path")
                    url="$url&path=$path"
                fi
                ;;
            "http")
                path=$(echo "$inbound" | jq -r '.transport.path // empty')
                host=$(echo "$inbound" | jq -r '.transport.header.host // empty')
                if [[ -n "$path" ]]; then
                    path=$(url_encode "$path")
                    url="$url&path=$path"
                fi
                if [[ -n "$host" ]]; then
                    host=$(url_encode "$host")
                    url="$url&host=$host"
                fi
                ;;
            "httpupgrade")
                path=$(echo "$inbound" | jq -r '.transport.path // empty')
                if [[ -n "$path" ]]; then
                    path=$(url_encode "$path")
                    url="$url&path=$path"
                fi
                ;;
            *)
                ;;
        esac

        # 检查 TLS 设置
        tls_enabled=$(echo "$inbound" | jq -r '.tls.enabled // false')
        if [[ "$tls_enabled" == "true" ]]; then
            reality_enabled=$(echo "$inbound" | jq -r '.tls.reality.enabled // false')
            if [[ "$reality_enabled" == "true" ]]; then
                echoContent green "\nDetected reality TLS for $tag, updating keys and settings..."
                key_pair=$(sing-box generate reality-keypair) || {
                    echoContent red "Error: Failed to generate reality key pair."
                    exit 1
                }
                private_key=$(echo "$key_pair" | grep "PrivateKey" | awk '{print $2}')
                public_key=$(echo "$key_pair" | grep "PublicKey" | awk '{print $2}')
                new_short_ids=$(generate_short_ids)
                short_id=$(echo "$new_short_ids" | jq -r '.[1]') # 取第二个 short_id

                echoContent yellow "\nGenerated new private_key: $private_key"
                echoContent yellow "\nGenerated new public_key: $public_key"
                echoContent yellow "\nGenerated new short_id: $new_short_ids"

                # 更新 private_key, short_id
                jq --arg tag "$tag" --arg private_key "$private_key" --argjson short_ids "$new_short_ids" \
                   '(.inbounds[] | select(.tag == $tag) | .tls.reality) |=
                    (.private_key = $private_key | .short_id = $short_ids)' \
                   "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE" || {
                    echoContent red "Error: Failed to update reality settings."
                    exit 1
                }

                url="$url&security=reality&pbk=$public_key&fp=chrome&sni=$SINGBOXDOMAIN&sid=$short_id#$tag"
            else
                fp=$(echo "$inbound" | jq -r '.tls.fingerprint // "chrome"')
                sni=$(echo "$inbound" | jq -r '.tls.server_name // "'"$SINGBOXDOMAIN"'"')
                alpn=$(echo "$inbound" | jq -r '.tls.alpn // "http/1.1"')

                # 如果 alpn 是数组，则将其转换为逗号分隔的字符串
                if [[ "$alpn" == \[*\] ]]; then
                    alpn=$(echo "$alpn" | jq -r 'join(",")')
                fi
                url="$url&security=tls&fp=$fp&sni=$sni&alpn=$alpn#$tag"
            fi
        else
            url="$url#$tag"
        fi

     
        # 处理 vmess、vless 和 tuic 的 uuid 替换
        if [[ "$type" == "vmess" || "$type" == "vless" || "$type" == "tuic" ]]; then
            echoContent green "\n处理 vmess、vless 和 tuic 的 uuid 替换,用sing-box generate uuid 生成uuid\n"
            user_index=0
            echo "$inbound" | jq -c '.users[]' | while IFS= read -r user; do
                old_uuid=$(echo "$user" | jq -r '.uuid')
                new_uuid=$(sing-box generate uuid) || {
                    echoContent red "Error: Failed to generate UUID."
                    exit 1
                }
                echoContent yellow "\nReplacing UUID for user $user_index in $tag: $old_uuid -> $new_uuid"

                # 更新 uuid
                jq --arg tag "$tag" --arg old_uuid "$old_uuid" --arg new_uuid "$new_uuid" \
                   '(.inbounds[] | select(.tag == $tag) | .users[] | select(.uuid == $old_uuid)).uuid = $new_uuid' \
                   "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE" || {
                    echoContent red "Error: Failed to update UUID."
                    exit 1
                }

                # 构造 URL
                url="$type://$new_uuid@$SINGBOXDOMAIN:$port$url"
                echo "$url" >> "$SINGBOX_SUB_FILE"
                echoContent skyblue "\n生成 $type 订阅链接: $url"
                qrencode -t ANSIUTF8 "$url" 2>/dev/null
                qrencode -o "${SUBSCRIBE_DIR}/${type}_${tag//[@\/]/_}.png" "$url" 2>/dev/null || {
                echoContent red "生成二维码失败: $url"
                }
                ((user_index++))
            done
        fi

        # 处理 trojan、shadowsocks、shadowtls 和 hysteria2 的 password 替换
        if [[ "$type" == "trojan" || "$type" == "shadowsocks" || "$type" == "shadowtls" || "$type" == "hysteria2" || "$type" == "naive" ]]; then
            echoContent green "\n处理 trojan、shadowsocks、shadowtls、naive 和 hysteria2 的 password 替换\n"
            user_index=0
            echo "$inbound" | jq -c '.users[]' | while IFS= read -r user; do
                old_password=$(echo "$user" | jq -r '.password')
                if [[ "$type" == "shadowsocks" || "$type" == "shadowtls" ]]; then
                    new_password=$(openssl rand -base64 16)
                else
                    new_password=$(sing-box generate uuid)
                fi
                echoContent yellow "\nReplacing password for user $user_index in $tag: $old_password -> $new_password"

                # 更新 password
                jq --arg tag "$tag" --arg old_password "$old_password" --arg new_password "$new_password" \
                   '(.inbounds[] | select(.tag == $tag) | .users[] | select(.password == $old_password)).password = $new_password' \
                   "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE" || {
                    echoContent red "Error: Failed to update password."
                    exit 1
                }

                # 构造 URL
                url="$type://$new_password@$SINGBOXDOMAIN:$port$url"
                  echo "$url" >> "$SINGBOX_SUB_FILE"
                 echoContent skyblue "\n生成 $type 订阅链接: $url"
                 qrencode -t ANSIUTF8 "$url" 2>/dev/null
                qrencode -o "${SUBSCRIBE_DIR}/${type}_${tag//[@\/]/_}.png" "$url" 2>/dev/null || {
                    echoContent red "生成二维码失败: $url"
                }
                ((user_index++))
            done

            # 更新 shadowsocks 或 shadowtls 的顶层 password
            if [[ "$type" == "shadowsocks" || "$type" == "shadowtls" ]]; then
                echoContent green "\n shadowsocks 或 shadowtls，更新顶层的 password 字段"
                top_password=$(echo "$inbound" | jq -r '.password // empty')
                if [[ -n "$top_password" ]]; then
                    new_top_password=$(openssl rand -base64 16)
                    echoContent yellow "Replacing top-level password in $tag: $top_password -> $new_top_password"
                    jq --arg tag "$tag" --arg new_password "$new_top_password" \
                       '(.inbounds[] | select(.tag == $tag)).password = $new_password' \
                       "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE" || {
                        echoContent red "Error: Failed to update top-level password."
                        exit 1
                    }
                fi
            fi
        fi

       
        
           
          
      \
    done

    # 替换原始文件
    mv "$TEMP_FILE" "$SINGBOX_CONF" || {
        echoContent red "Error: Failed to replace $SINGBOX_CONF"
        exit 1
    }
    echoContent skyblue "Updated $SINGBOX_CONF with new UUIDs, passwords, reality settings, and domain as $SINGBOXDOMAIN."

    # 验证 JSON 文件是否有效
    if jq empty "$SINGBOX_CONF" &> /dev/null; then
        echoContent skyblue "JSON file is valid. Restarting sing-box service..."
        systemctl restart sing-box || {
            echoContent red "Error: Failed to restart sing-box service."
            exit 1
        }
    else
        echoContent red "Error: Updated JSON file is invalid. Restoring backup."
        mv "${SINGBOX_CONF}.bak" "$SINGBOX_CONF"
        exit 1
    fi
}
configNginx() {
    echoContent green "nginx.conf 采用stream模块分流\n 包括tls,reality,pre,sing等前缀域名进行分流 ."
            read -r -p "请输入 nginx.conf 配置中替换tls.yourdomain的新域名 (后端xray tls解密): " TLS_YOURDOMAIN
            read -r -p "请输入 nginx.conf 配置中替换reality.yourdomain的新域名 (后端xray reality解密): " REALITY_YOURDOMAIN
            read -r -p "请输入 nginx.conf 配置中替换pre.yourdomain的新域名 (前端nginx解密): " PRE_YOURDOMAIN
            read -r -p "请输入 nginx.conf 配置中替换sing.yourdomain的新域名 (后端singbox解密): " SING_YOURDOMAIN
            read -r -p "请输入 nginx.conf 配置中替换www.yourdomain的新域名 (前端nginx正常网站): " WWW_YOURDOMAIN
            read -r -p "请输入 nginx.conf 配置中替换yourdomain的新域名 (用于通配符或者综合证书)，如果对上面的域名都有证书，请手动修改nginx.conf: " YOURDOMAIN
            read -r -p "请输入 nginx.conf 的新 IP 地址 (例如: $LOCAL_IP): " NEW_IP
            if [[ -z "$NEW_IP" ]]; then
                NEW_IP="$LOCAL_IP"
            fi
            read -r -p "请输入 nginx.conf 的新端口 (默认 443): " NEW_PORT
            if [[ -z "$NEW_PORT" ]]; then
                NEW_PORT="443"
            fi
            sed -i "s/tls\.yourdomain/$TLS_YOURDOMAIN/g" "$NGINX_CONF"
            sed -i "s/reality\.yourdomain/$REALITY_YOURDOMAIN/g" "$NGINX_CONF"
            sed -i "s/pre\.yourdomain/$PRE_YOURDOMAIN/g" "$NGINX_CONF"
            sed -i "s/sing\.yourdomain/$SING_YOURDOMAIN/g" "$NGINX_CONF"
            sed -i "s/www\.yourdomain/$WWW_YOURDOMAIN/g" "$NGINX_CONF"
            sed -i "s/yourdomain/$YOURDOMAIN/g" "$NGINX_CONF"
            sed -i "s/yourdomain/$YOURDOMAIN/g" "$XRAY_CONF"
            sed -i "s/yourdomain/$YOURDOMAIN/g" "$SINGBOX_CONF"
            sed -i "s/yourIP/$NEW_IP/g" "$NGINX_CONF"
            sed -i "s/listen 443/listen $NEW_PORT/g" "$NGINX_CONF"
            echoContent skyblue "nginx.conf 更新成功."        
}
# Manage configurations
manageConfigurations() {
    echoContent skyblue "\n配置管理菜单"
    echoContent yellow "1. 配置nsx服务"
    echoContent yellow "2. 修改 nginx.conf"
    echoContent yellow "3. 修改 xray config.json"
    echoContent yellow "4. 修改 sing-box config.json"
    echoContent yellow "5. 退出"
    read -r -p "请选择一个选项 [1-4]: " config_option

    case $config_option in
       1)
            
            configNSX
            ;;
       2)
            configNginx
            # Reload Nginx if running
            if pgrep nginx > /dev/null; then
                nginx -s reload
                echoContent green "Nginx 已重载以应用新配置."
            elif docker ps | grep -q nginx; then
                docker compose -f "$COMPOSE_FILE" restart
                echoContent green "Docker Compose 已重启以应用新配置."
            fi
            ;;
        3)
            xray_config
            echoContent green "xray config.json 更新成功."
            # Restart Xray if running
            if systemctl is-active --quiet xray; then
                systemctl restart xray
                echoContent green "Xray 已重启以应用新配置."
            elif docker ps | grep -q xray; then
                docker compose -f "$COMPOSE_FILE" restart
                echoContent green "Docker Compose 已重启以应用新配置."
            fi
            ;;
        4)
            singbox_config
            echoContent green "sing-box config.json 更新成功."
            # Restart Sing-box if running
            if systemctl is-active --quiet sing-box; then
                systemctl restart sing-box
                echoContent green "Sing-box 已重启以应用新配置."
            elif docker ps | grep -q sing-box; then
                docker compose -f "$COMPOSE_FILE" restart
                echoContent green "Docker Compose 已重启以应用新配置."
            fi
            ;;
        5)
            return
            ;;
        *)
            echoContent red "无效选项."
            manageConfigurations
            ;;
    esac
}
generateSubscriptions() {
    echoContent skyblue "\n生成订阅..."



    # 检查变量
    if [[ -z "$XRAY_CONF" || -z "$SINGBOX_CONF" || -z "$SUBSCRIBE_DIR" || -z "$COMPOSE_FILE" ]]; then
        echoContent red "Error: XRAY_CONF, SINGBOX_CONF, SUBSCRIBE_DIR, or COMPOSE_FILE is not set."
        return 1
    fi

    # 检查依赖
    if ! command -v jq &> /dev/null; then
        echoContent red "Error: jq is not installed."
        return 1
    fi
    if ! command -v qrencode &> /dev/null; then
        echoContent yellow "Warning: qrencode is not installed, skipping QR code generation."
        QRENCODE_AVAILABLE=false
    else
        QRENCODE_AVAILABLE=true
    fi

    # 创建订阅目录
    if [ ! -d "$SUBSCRIBE_DIR" ]; then
        mkdir -p "$SUBSCRIBE_DIR" || {
            echoContent red "Error: Failed to create directory $SUBSCRIBE_DIR"
            return 1
        }
        chown nobody:nogroup "$SUBSCRIBE_DIR"
        chmod 755 "$SUBSCRIBE_DIR"
    fi

    # 获取用户输入的域名
    read -r -p "请输入订阅域名 (例如: sing.yourdomain): " SUB_DOMAIN
    if [[ -z "$SUB_DOMAIN" ]]; then
        echoContent red "域名不能为空."
        return 1
    fi

    # Generate Xray subscription
    if [ -f "$XRAY_CONF" ]; then
        echoContent yellow "生成 Xray 订阅..."
        XRAY_SUB_FILE="${SUBSCRIBE_DIR}/xray_sub.txt"
        > "$XRAY_SUB_FILE"

        # 提取所有 inbounds
        jq -c '.inbounds[] | select(.settings.clients)' "$XRAY_CONF" | while IFS= read -r inbound; do
            tag=$(echo "$inbound" | jq -r '.tag')
            protocol=$(echo "$inbound" | jq -r '.protocol')
            port=$(echo "$inbound" | jq -r '.port // "443"')
            encryption=$(echo "$inbound" | jq -r '.settings.decryption // "none"')
            network=$(echo "$inbound" | jq -r '.streamSettings.network // "tcp"')
            security=$(echo "$inbound" | jq -r '.streamSettings.security // "none"')

            # 构造传输参数
            params="type=$network"
            case "$network" in
                "grpc")
                    serviceName=$(echo "$inbound" | jq -r '.streamSettings.grpcSettings.serviceName // empty')
                    if [[ -n "$serviceName" ]]; then
                        serviceName=$(url_encode "$serviceName")
                        params="$params&serviceName=$serviceName"
                    fi
                    ;;
                "ws")
                    path=$(echo "$inbound" | jq -r '.streamSettings.wsSettings.path // empty')
                    if [[ -n "$path" ]]; then
                        path=$(url_encode "$path")
                        params="$params&path=$path"
                    fi
                    ;;
                "xhttp")
                    xhttpSettings=$(echo "$inbound" | jq -r '.streamSettings.xhttpSettings')
                    host=$(echo "$xhttpSettings" | jq -r '.host // empty')
                    path=$(echo "$xhttpSettings" | jq -r '.path // empty')
                    if [[ -n "$host" ]]; then
                        host=$(url_encode "$host")
                        params="$params&host=$host"
                    fi
                    if [[ -n "$path" ]]; then
                        path=$(url_encode "$path")
                        params="$params&path=$path"
                    fi
                    ;;
                "splithttp")
                    path=$(echo "$inbound" | jq -r '.streamSettings.splithttpSettings.path // empty')
                    if [[ -n "$path" ]]; then
                        path=$(url_encode "$path")
                        params="$params&path=$path"
                    fi
                    ;;
                "httpupgrade")
                    path=$(echo "$inbound" | jq -r '.streamSettings.httpupgradeSettings.path // empty')
                    if [[ -n "$path" ]]; then
                        path=$(url_encode "$path")
                        params="$params&path=$path"
                    fi
                    ;;
                "kcp")
                    seed=$(echo "$inbound" | jq -r '.streamSettings.kcpSettings.seed // empty')
                    if [[ -n "$seed" ]]; then
                        seed=$(url_encode "$seed")
                        params="$params&seed=$seed"
                    fi
                    ;;
                *)
                    ;;
            esac

            # 处理安全设置
            if [[ "$security" == "reality" ]]; then
                realitySettings=$(echo "$inbound" | jq -r '.streamSettings.realitySettings')
                pbk=$(echo "$realitySettings" | jq -r '.password // empty')
                sid=$(echo "$realitySettings" | jq -r '.shortIds[0] // empty')
                pqv=$(echo "$realitySettings" | jq -r '.mldsa65Verify // empty')
                params="$params&security=reality&pbk=$pbk&sid=$sid&pqv=$pqv&fp=chrome&sni=$SUB_DOMAIN"
            elif [[ "$security" == "tls" ]]; then
                tlsSettings=$(echo "$inbound" | jq -r '.streamSettings.tlsSettings')
                fp=$(echo "$tlsSettings" | jq -r '.fingerprint // "chrome"')
                sni=$(echo "$tlsSettings" | jq -r '.serverName // "'"$SUB_DOMAIN"'"')
                alpn=$(echo "$tlsSettings" | jq -r '.alpn | join(",") // "http/1.1"')
                params="$params&security=tls&fp=$fp&sni=$sni&alpn=$alpn"
            fi

            # 处理 clients
            clients=$(echo "$inbound" | jq -c '.settings.clients[]')
            echo "$clients" | while IFS= read -r client; do
                email=$(echo "$client" | jq -r '.email // "unknown"')
                SUB_LINK=""
                case "$protocol" in
                    "vmess")
                        id=$(echo "$client" | jq -r '.id')
                        vmess_json=$(jq -n --arg id "$id" --arg add "$SUB_DOMAIN" --arg port "$port" --arg ps "$email" --arg enc "$encryption" \
                            '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:0,net:(.network // "tcp"),type:"none",tls:(.security // "none"),enc:$enc}')
                        SUB_LINK="vmess://$(echo -n "$vmess_json" | base64 -w 0)?$params#$tag"
                        ;;
                    "vless")
                        id=$(echo "$client" | jq -r '.id')
                        flow=$(echo "$client" | jq -r '.flow // empty')
                        if [[ -n "$flow" ]]; then
                            params="$params&flow=$flow"
                        fi
                        SUB_LINK="vless://$id@$SUB_DOMAIN:$port?$params#$tag"
                        ;;
                    "trojan")
                        password=$(echo "$client" | jq -r '.password')
                        SUB_LINK="trojan://$password@$SUB_DOMAIN:$port?$params#$tag"
                        ;;
                    "shadowsocks")
                        password=$(echo "$client" | jq -r '.password')
                        method=$(echo "$inbound" | jq -r '.settings.method // "aes-256-gcm"')
                        SUB_LINK="ss://$(echo -n "$method:$password" | base64 -w 0)@$SUB_DOMAIN:$port#$tag"
                        ;;
                    *)
                        echoContent yellow "Unsupported protocol: $protocol for tag: $tag, skipping."
                        continue
                        ;;
                esac

                if [[ -n "$SUB_LINK" ]]; then
                  
                    echo "$SUB_LINK" >> "$XRAY_SUB_FILE"
                    echoContent green "\n生成 Xray $protocol 订阅链接: $SUB_LINK"
                    if [[ "$QRENCODE_AVAILABLE" == "true" ]]; then
                        qrencode -t ANSIUTF8 "$SUB_LINK" 2>/dev/null
                        qrencode -o "${SUBSCRIBE_DIR}/${protocol}_${email//[@\/]/_}_${tag//[@\/]/_}.png" "$SUB_LINK" 2>/dev/null || {
                            echoContent red "生成二维码失败: $SUB_LINK"
                        }
                    fi
                fi
            done
        done

        if [ -s "$XRAY_SUB_FILE" ]; then
            echo "$(cat "$XRAY_SUB_FILE" | base64 -w 0)" > "$XRAY_SUB_FILE"
            chown nobody:nogroup "$XRAY_SUB_FILE" "${SUBSCRIBE_DIR}"/*.png 2>/dev/null
            chmod 644 "$XRAY_SUB_FILE" "${SUBSCRIBE_DIR}"/*.png 2>/dev/null
            echoContent green "Xray 订阅已保存至 ${XRAY_SUB_FILE}，二维码已生成."
        else
            echoContent red "未生成任何 Xray 订阅链接."
        fi
    else
        echoContent red "Xray 配置文件 ${XRAY_CONF} 不存在."
    fi

    # Generate Sing-box subscription
    if [ -f "$SINGBOX_CONF" ]; then
        echoContent yellow "生成 Sing-box 订阅..."
        SINGBOX_SUB_FILE="${SUBSCRIBE_DIR}/singbox_sub.txt"
        > "$SINGBOX_SUB_FILE"

        # 提取所有 inbounds
        jq -c '.inbounds[] | select(.users)' "$SINGBOX_CONF" | while IFS= read -r inbound; do
            tag=$(echo "$inbound" | jq -r '.tag')
            type=$(echo "$inbound" | jq -r '.type')
            port=$(echo "$inbound" | jq -r '.listen_port // "443"')
            transport=$(echo "$inbound" | jq -r '.transport.type // "tcp"')
            tls_enabled=$(echo "$inbound" | jq -r '.tls.enabled // false')

            # 构造传输参数
            params="type=$transport"
            case "$transport" in
                "grpc")
                    serviceName=$(echo "$inbound" | jq -r '.transport.service_name // empty')
                    if [[ -n "$serviceName" ]]; then
                        serviceName=$(url_encode "$serviceName")
                        params="$params&serviceName=$serviceName"
                    fi
                    ;;
                "ws")
                    path=$(echo "$inbound" | jq -r '.transport.path // empty')
                    if [[ -n "$path" ]]; then
                        path=$(url_encode "$path")
                        params="$params&path=$path"
                    fi
                    ;;
                "http")
                    path=$(echo "$inbound" | jq -r '.transport.path // empty')
                    host=$(echo "$inbound" | jq -r '.transport.header.host // empty')
                    if [[ -n "$path" ]]; then
                        path=$(url_encode "$path")
                        params="$params&path=$path"
                    fi
                    if [[ -n "$host" ]]; then
                        host=$(url_encode "$host")
                        params="$params&host=$host"
                    fi
                    ;;
                "httpupgrade")
                    path=$(echo "$inbound" | jq -r '.transport.path // empty')
                    if [[ -n "$path" ]]; then
                        path=$(url_encode "$path")
                        params="$params&path=$path"
                    fi
                    ;;
                *)
                    ;;
            esac

            # 处理 TLS 设置
            if [[ "$tls_enabled" == "true" ]]; then
                reality_enabled=$(echo "$inbound" | jq -r '.tls.reality.enabled // false')
                if [[ "$reality_enabled" == "true" ]]; then
                    short_id=$(echo "$inbound" | jq -r '.tls.reality.short_id[0] // empty')
                    public_key=$(echo "$inbound" | jq -r '.tls.reality.public_key // empty')
                    params="$params&security=reality&pbk=$public_key&sid=$short_id&fp=chrome&sni=$SUB_DOMAIN"
                else
                    fp=$(echo "$inbound" | jq -r '.tls.fingerprint // "chrome"')
                    sni=$(echo "$inbound" | jq -r '.tls.server_name // "'"$SUB_DOMAIN"'"')
                    alpn=$(echo "$inbound" | jq -r '.tls.alpn | join(",") // "http/1.1"')
                    params="$params&security=tls&fp=$fp&sni=$sni&alpn=$alpn"
                fi
            fi

            # 处理 users
            users=$(echo "$inbound" | jq -c '.users[]')
            echo "$users" | while IFS= read -r user; do
                name=$(echo "$user" | jq -r '.name // "unknown"')
                SUB_LINK=""
                case "$type" in
                    "vless")
                        uuid=$(echo "$user" | jq -r '.uuid')
                        if [[ -z "$uuid" || -z "$name" ]]; then
                            echoContent red "跳过无效 VLESS 配置: UUID 或 name 为空 (tag: $tag)"
                            continue
                        fi
                        SUB_LINK="vless://$uuid@$SUB_DOMAIN:$port?$params#$name"
                        ;;
                    "vmess")
                        uuid=$(echo "$user" | jq -r '.uuid')
                        if [[ -z "$uuid" || -z "$name" ]]; then
                            echoContent red "跳过无效 VMess 配置: UUID 或 name 为空 (tag: $tag)"
                            continue
                        fi
                        vmess_json=$(jq -n --arg id "$uuid" --arg add "$SUB_DOMAIN" --arg port "$port" --arg ps "$name" \
                            '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:0,net:"'$transport'",type:"none",tls:(.security // "none")}')
                        SUB_LINK="vmess://$(echo -n "$vmess_json" | base64 -w 0)?$params#$name"
                        ;;
                    "trojan")
                        password=$(echo "$user" | jq -r '.password')
                        if [[ -z "$password" || -z "$name" ]]; then
                            echoContent red "跳过无效 Trojan 配置: password 或 name 为空 (tag: $tag)"
                            continue
                        fi
                        SUB_LINK="trojan://$password@$SUB_DOMAIN:$port?$params#$name"
                        ;;
                    "shadowsocks")
                        password=$(echo "$user" | jq -r '.password')
                        method=$(echo "$user" | jq -r '.method // "aes-256-gcm"')
                        if [[ -z "$password" || -z "$name" ]]; then
                            echoContent red "跳过无效 Shadowsocks 配置: password 或 name 为空 (tag: $tag)"
                            continue
                        fi
                        SUB_LINK="ss://$(echo -n "$method:$password" | base64 -w 0)@$SUB_DOMAIN:$port#$name"
                        ;;
                    "hysteria2")
                        password=$(echo "$user" | jq -r '.password')
                        if [[ -z "$password" || -z "$name" ]]; then
                            echoContent red "跳过无效 Hysteria2 配置: password 或 name 为空 (tag: $tag)"
                            continue
                        fi
                        SUB_LINK="hysteria2://$password@$SUB_DOMAIN:$port?insecure=0&$params#$name"
                        ;;
                    "tuic")
                        uuid=$(echo "$user" | jq -r '.uuid')
                        password=$(echo "$user" | jq -r '.password')
                        if [[ -z "$uuid" || -z "$password" || -z "$name" ]]; then
                            echoContent red "跳过无效 TUIC 配置: UUID, password 或 name 为空 (tag: $tag)"
                            continue
                        fi
                        SUB_LINK="tuic://$uuid:$password@$SUB_DOMAIN:$port?alpn=h3&congestion_control=bbr&$params#$name"
                        ;;
                    "naive")
                        username=$(echo "$user" | jq -r '.username')
                        password=$(echo "$user" | jq -r '.password')
                        if [[ -z "$username" || -z "$password" || -z "$name" ]]; then
                            echoContent red "跳过无效 Naive 配置: username, password 或 name 为空 (tag: $tag)"
                            continue
                        fi
                        SUB_LINK="naive+https://$username:$password@$SUB_DOMAIN:$port?insecure=0&$params#$name"
                        ;;
                    *)
                        echoContent yellow "Unsupported protocol: $type for tag: $tag, skipping."
                        continue
                        ;;
                esac

                if [[ -n "$SUB_LINK" ]]; then
                   
                    echo "$SUB_LINK" >> "$SINGBOX_SUB_FILE"
                    echoContent green "\n生成 Sing-box $type 订阅链接: $SUB_LINK"
                    if [[ "$QRENCODE_AVAILABLE" == "true" ]]; then
                        qrencode -t ANSIUTF8 "$SUB_LINK" 2>/dev/null
                        qrencode -o "${SUBSCRIBE_DIR}/${type}_${name//[@\/]/_}_${tag//[@\/]/_}.png" "$SUB_LINK" 2>/dev/null || {
                            echoContent red "生成二维码失败: $SUB_LINK"
                        }
                    fi
                fi
            done
        done

        if [ -s "$SINGBOX_SUB_FILE" ]; then
            echo "$(cat "$SINGBOX_SUB_FILE" | base64 -w 0)" > "$SINGBOX_SUB_FILE"
            chown nobody:nogroup "$SINGBOX_SUB_FILE" "${SUBSCRIBE_DIR}"/*.png 2>/dev/null
            chmod 644 "$SINGBOX_SUB_FILE" "${SUBSCRIBE_DIR}"/*.png 2>/dev/null
            echoContent green "Sing-box 订阅已保存至 ${SINGBOX_SUB_FILE}，二维码已生成."
        else
            echoContent red "未生成任何 Sing-box 订阅链接."
        fi
    else
        echoContent red "Sing-box 配置文件 ${SINGBOX_CONF} 不存在."
    fi

    # 重启服务
    if [ -s "$XRAY_SUB_FILE" ] && command -v xray &> /dev/null; then
        echoContent skyblue "正在重启 Xray 服务..."
        systemctl restart xray || {
            echoContent red "Error: Failed to restart Xray service."
            return 1
        }
    fi
    if [ -s "$SINGBOX_SUB_FILE" ] && command -v sing-box &> /dev/null; then
        echoContent skyblue "正在重启 Sing-box 服务..."
        systemctl restart sing-box || {
            echoContent red "Error: Failed to restart Sing-box service."
            return 1
        }
    fi

    # Reload Nginx if running in Docker
    if docker ps | grep -q nginx && [ -f "$COMPOSE_FILE" ]; then
        docker compose -f "$COMPOSE_FILE" restart nginx || {
            echoContent red "Error: Failed to restart Nginx."
            return 1
        }
        echoContent green "Nginx 已重启以应用订阅文件."
    fi

    echoContent green "订阅生成完成，可通过 http://${SUB_DOMAIN}/subscribe/ 访问."
}
# Manage logs
manageLogs() {
    echoContent skyblue "\n日志管理菜单"
    echoContent yellow "1. 查看 Nginx 访问日志"
    echoContent yellow "2. 查看 Nginx 错误日志"
    echoContent yellow "3. 查看 Xray 访问日志"
    echoContent yellow "4. 查看 Sing-box 日志"
    echoContent yellow "5. 查看证书日志"
    echoContent yellow "6. 清除所有日志"
    echoContent yellow "7. 退出"
    read -r -p "请选择一个选项 [1-7]: " log_option

    case $log_option in
        1) tail -f "${LOG_DIR}/nginx_access.log" ;;
        2) tail -f "${LOG_DIR}/nginx_error.log" ;;
        3) tail -f "${LOG_DIR}/xray_access.log" ;;
        4) tail -f "${LOG_DIR}/singbox.log" ;;
        5) tail -n 100 "${ACME_LOG}" ;;
        6)
            echo > "${LOG_DIR}/nginx_access.log"
            echo > "${LOG_DIR}/nginx_error.log"
            echo > "${LOG_DIR}/xray_access.log"
            echo > "${LOG_DIR}/xray_error.log"
            echo > "${LOG_DIR}/singbox.log"
            echoContent green "所有日志已清除."
            ;;
        7) return ;;
        *) echoContent red "无效选项." ; manageLogs ;;
    esac
}

# Install alias
aliasInstall() {
    if [[ -f "$BASE_DIR/install.sh" ]] && [[ -d "$BASE_DIR" ]]; then
        ln -sf "$BASE_DIR/install.sh" /usr/bin/nsx  
        chmod 700 "$BASE_DIR/install.sh"
        echoContent green "已创建别名 'nsx'，运行 'nsx' 以执行脚本."
    fi
      
}


# Update script
updateConfig() {
   echoContent yellow "更新配置文件..."
        # Backup existing configuration files if they exist
        for file in "$COMPOSE_FILE" "$NGINX_CONF" "$XRAY_CONF" "$SINGBOX_CONF"; do
            if [[ -f "$file" ]]; then
                mv "$file" "$file.bak" || {
                    echoContent red "无法备份 $file."
                    exit 1
                }
            fi
        done

        # Ensure source configuration files exist in the repository
        for src in "$TEMP_DIR/docker/docker-compose.yml" "$TEMP_DIR/nginx/nginx.conf" \
                   "$TEMP_DIR/xray/config.json" "$TEMP_DIR/sing-box/config.json"; do
            if [[ ! -f "$src" ]]; then
                echoContent red "仓库中缺少配置文件: $src."
                exit 1
            fi
        done

        # Ensure destination directories exist
        for dest in "$COMPOSE_FILE" "$NGINX_CONF" "$XRAY_CONF" "$SINGBOX_CONF"; do
            mkdir -p "$(dirname "$dest")" || {
                echoContent red "无法创建目录 $(dirname "$dest")."
                exit 1
            }
        done


   # Copy configuration files
        if ! cp "$TEMP_DIR/docker/docker-compose.yml" "$COMPOSE_FILE"; then
            echoContent red "无法复制 docker-compose.yml 到 $COMPOSE_FILE."
            exit 1
        fi
        if ! cp "$TEMP_DIR/nginx/nginx.conf" "$NGINX_CONF"; then
            echoContent red "无法复制 nginx.conf 到 $NGINX_CONF."
            exit 1
        fi
        if ! cp "$TEMP_DIR/xray/config.json" "$XRAY_CONF"; then
            echoContent red "无法复制 xray/config.json 到 $XRAY_CONF."
            exit 1
        fi
        if ! cp "$TEMP_DIR/sing-box/config.json" "$SINGBOX_CONF"; then
            echoContent red "无法复制 sing-box/config.json 到 $SINGBOX_CONF."
            exit 1
        fi

        # Set permissions
        chmod 644 "$COMPOSE_FILE" || {
            echoContent red "无法设置 $COMPOSE_FILE 权限."
            exit 1
        }
        chmod 644 "$NGINX_CONF" || {
            echoContent red "无法设置 $NGINX_CONF 权限."
            exit 1
        }
        chmod 644 "$XRAY_CONF" || {
            echoContent red "无法设置 $XRAY_CONF 权限."
            exit 1
        }
        chmod 644 "$SINGBOX_CONF" || {
            echoContent red "无法设置 $SINGBOX_CONF 权限."
            exit 1
        }

        echoContent green "配置文件更新成功."

}

updateNSX() {
    echoContent skyblue "\n进度 5/${TOTAL_PROGRESS} : 更新 NSX 脚本..."
    # Check if git is installed
    if ! command -v git &> /dev/null; then
        echoContent yellow "安装 git..."
        ${installCmd} git
        if [ $? -ne 0 ]; then
            echoContent red "安装 git 失败，请手动安装."
            exit 1
        fi
    fi

    # Create a temporary directory for cloning
    TEMP_DIR=$(mktemp -d)
    if [ $? -ne 0 ]; then
        echoContent red "创建临时目录失败."
        exit 1
    fi
    # Ensure temporary directory is cleaned up on exit
    trap 'rm -rf "$TEMP_DIR"' EXIT
    # Clone the repository
    # Clone the repository
    if ! git clone https://github.com/judawu/nsx.git "$TEMP_DIR"; then
        echoContent red "克隆 Git 仓库失败，请检查网络或仓库地址 https://github.com/judawu/nsx."
        exit 1
    fi

    # Remove old install.sh
    rm -f "$BASE_DIR/install.sh"

    # Copy install.sh from cloned repository
    if [ -f "$TEMP_DIR/install.sh" ]; then
        cp "$TEMP_DIR/install.sh" "$BASE_DIR/install.sh"
        chmod 700 "$BASE_DIR/install.sh"
        echoContent green "脚本更新成功."
    else
        echoContent red "克隆的仓库中未找到 install.sh 文件."
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    read -r -p "是否用 GitHub 仓库替换当前配置文件？(y/n): " keep_config
    if [[ "$keep_config" == "n" ]]; then
        echoContent green "保留现有配置文件，不进行更新."
    elif [[ "$keep_config" == "y" ]]; then
       updateConfig
    else
        echoContent green "保留现有配置文件，不进行更新."
    fi

    # Call aliasInstall (assuming it's defined elsewhere)
    if type aliasInstall >/dev/null 2>&1; then
        aliasInstall || {
            echoContent red "执行 aliasInstall 失败."
            exit 1
        }
    else
        echoContent yellow "警告: aliasInstall 函数未定义，跳过."
    fi


}

# Docker installation
dockerInstall() {
    installTools
    echoContent skyblue "\n进度 4/${TOTAL_PROGRESS} : Docker 安装..."
    installDocker
    createDirectories
    installAcme

    # Copy configuration files (assuming files are in the script's directory)
    if [[ $(pwd) != $BASE_DIR ]]; then 
        if [[  -f "$COMPOSE_FILE" ]]; then 
         cp ./docker/docker-compose.yml "$COMPOSE_FILE"
        chmod 644 "$COMPOSE_FILE"
        fi
        if [[  -f "$COMPOSE_FILE" ]]; then
         cp ./nginx/nginx.conf "$NGINX_CONF"
         chmod 644 "$NGINX_CONF"
        fi
        if [[  -f "$COMPOSE_FILE" ]]; then
          cp ./xray/config.json "$XRAY_CONF"
          chmod 644 "$XRAY_CONF"
        fi
        if [[  -f "$COMPOSE_FILE" ]]; then
           cp ./sing-box/config.json "$SINGBOX_CONF"
           chmod 644 "$SINGBOX_CONF"
        fi       
    fi

    # Check certificates
    if [ ! -d "${CERT_DIR}" ] || [ -z "$(ls -A "${CERT_DIR}"/*.pem 2>/dev/null)" ]; then
        echoContent yellow "未找到证书，运行证书管理..."
        manageCertificates
    fi
    configNginx
    # Check Nginx configuration
    echoContent yellow "检查 Nginx 配置语法..."
    docker run --rm -v "${NGINX_CONF}:/etc/nginx/nginx.conf:ro" -v "${CERT_DIR}:/etc/nginx/certs:ro" -v "${SHM_DIR}:/dev/shm/nsx" nginx:alpine nginx -t
    if [ $? -ne 0 ]; then
        echoContent red "错误：Nginx 配置语法检查失败！"
        exit 1
    fi

    # Start Docker Compose
    echoContent yellow "启动 Docker 容器..."
    docker compose -f "$COMPOSE_FILE" up -d
    if [ $? -ne 0 ]; then
        echoContent red "启动 Docker Compose 失败，请检查配置或日志."
        exit 1
    fi

    # Set permissions for log files
    find "$SHM_DIR"  -name "*.sock" -exec chown nobody:nogroup {} \; -exec chmod 666 {} \;
    find "$LOG_DIR"  -type f -name "*.log" -exec chown nobody:nogroup {} \; -exec chmod 644 {} \;

    echoContent green "Docker 容器启动成功."

    # Check container status
    echoContent yellow "检查容器状态..."
    docker ps -f name=nginx-stream -f name=xray -f name=sing-box

    echoContent green "请使用systemctl enable ufw 和systemctl start ufw开启防火墙，用ufw allow port 开启端口访问..."
    aliasInstall
}
createSystemdServices() {
    echoContent skyblue "\n配置 systemd 服务..."

    # Nginx 服务文件
    if [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        echoContent green "创建 Nginx systemd 服务..."
        cat <<EOF >/etc/systemd/system/nginx.service
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
ExecStart=/usr/sbin/nginx -c /usr/local/nsx/nginx/nginx.conf -g "daemon on; master_process on;"
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s quit
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    elif [[ "${release}" == "centos" ]]; then
        echoContent green "创建 Nginx systemd 服务..."
        cat <<EOF >/etc/systemd/system/nginx.service
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
ExecStart=/usr/sbin/nginx -c /usr/local/nsx/nginx/nginx.conf -g "daemon on; master_process on;"
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s quit
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    fi

    # Xray 服务文件
    echoContent green "创建 Xray systemd 服务..."
    cat <<EOF >/etc/systemd/system/xray.service
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/nsx/xray/xray -c /usr/local/nsx/xray/config.json
ExecStop=/bin/kill -s QUIT \$MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Sing-box 服务文件
    echoContent green "创建 Sing-box systemd 服务..."
    cat <<EOF >/etc/systemd/system/sing-box.service
[Unit]
Description=Sing-box Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/nsx/sing-box/sing-box run -c /usr/local/nsx/sing-box/config.json
ExecStop=/bin/kill -s QUIT \$MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载 systemd 配置
    echoContent green "重新加载 systemd 配置..."
    systemctl daemon-reload

    # 设置文件权限
    chmod 644 /etc/systemd/system/nginx.service
    chmod 644 /etc/systemd/system/xray.service
    chmod 644 /etc/systemd/system/sing-box.service
}

# 修改后的服务启动部分
startServices() {

    echoContent skyblue "\n启动服务..."

    # 启用并启动服务
    sudo systemctl enable nginx
    sudo systemctl start nginx
     # 检查服务状态
    if sudo systemctl is-active --quiet nginx; then
        echoContent green "Nginx启动成功！"
    else
        echoContent red "Nginx服务启动失败，请检查日志："
        echoContent red "Nginx: journalctl -u nginx.service"
   
    fi
    sudo systemctl enable xray 
    sudo systemctl start  xray 
    if sudo systemctl is-active --quiet xray; then
        echoContent green "xray启动成功！"
    else
        echoContent red "xray服务启动失败，请检查日志："
        echoContent red "Xray: journalctl -u xray.service"
    fi

    sudo systemctl enable sing-box
    sudo systemctl start sing-box

    # 检查服务状态
    if sudo systemctl is-active --quiet sing-box; then
        echoContent green  "Sing-box启动成功！"
    else
        echoContent red "Sing-box服务启动失败，请检查日志："     
        echoContent red "Sing-box: journalctl -u sing-box.service"

    fi
    echoContent green  "设置$SHM_DIR 下的socks文件权限！"
    find "$SHM_DIR" -name "*.*" -exec chown nobody:nogroup {} \; -exec chmod 666 {} \;
    find "$LOG_DIR"  -type f -name "*.log" -exec chown nobody:nogroup {} \; -exec chmod 644 {} \;
    # Check if the find command was successful
    if [ $? -eq 0 ]; then
        echo "Successfully changed permissions to 666 for all socket files in $SHM_DIR"
    else
        echo "Error: Failed to change permissions for some or all socket files."
        exit 1
    fi
}

restartServices() {
    echoContent skyblue "\重启服务..."

    # 启用并启动服务
    echoContent yellow "停止服务."
    sudo systemctl stop nginx xray sing-box
    echoContent yellow "清理$SHM_DIR/."
    sudo rm -rf "$SHM_DIR"/*
    echoContent yellow "启动服务."
    sudo systemctl start nginx xray sing-box

    echoContent green  "设置$SHM_DIR 下的socks文件权限！"
    find "$SHM_DIR"  -name "*.*" -exec chown nobody:nogroup {} \; -exec chmod 666 {} \;
    find "$LOG_DIR"  -type f -name "*.log" -exec chown nobody:nogroup {} \; -exec chmod 644 {} \;
    # Check if the find command was successful
    if [ $? -eq 0 ]; then
        echo "Successfully changed permissions to 666 for all socket files in $SHM_DIR"
    else
        echo "Error: Failed to change permissions for some or all socket files."
        exit 1
    fi
    # 检查服务状态
    if sudo systemctl is-active --quiet nginx && sudo systemctl is-active --quiet xray && sudo systemctl is-active --quiet sing-box; then
        echoContent green "所有服务（Nginx, Xray, Sing-box）启动成功！"
    else
        echoContent red "部分或全部服务启动失败，请检查日志："
        echoContent red "Nginx: journalctl -u nginx.service"
        echoContent red "Xray: journalctl -u xray.service"
        echoContent red "Sing-box: journalctl -u sing-box.service"
        exit 1
    fi
}
# Local installation
localInstall() {
   
    echoContent skyblue "\n进度 4/${TOTAL_PROGRESS} : 本地安装..."
    installTools
    checkCentosSELinux
    
    createDirectories
    installAcme

    # Check certificates
    if [ ! -d "${CERT_DIR}" ] || [ -z "$(ls -A "${CERT_DIR}"/*.pem 2>/dev/null)" ]; then
        echoContent yellow "未找到证书，运行证书管理..."
        manageCertificates
    fi
   
    # Install Nginx

    echoContent skyblue "\n 安装nginx..."
    if [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        echoContent green "\n 安装nginx依赖..."
        sudo apt update
        sudo apt install -y gnupg2 ca-certificates lsb-release
        echo "deb http://nginx.org/packages/mainline/${release} $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
        if ! curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/nginx_signing.gpg; then
            echoContent red "\n 错误: 无法下载Nginx签名密钥!"
            exit 1
        fi
        sudo apt update
        sudo apt install -y nginx
        if [ $? -eq 0 ]; then
            echoContent skyblue "\n nginx安装完成..."
         
        else
            echoContent red "\n nginx安装失败!"
            exit 1
        fi
    elif [[ "${release}" == "centos" ]]; then
        echoContent green "\n 安装nginx依赖..."
        sudo yum install -y yum-utils
        cat <<EOF | sudo tee /etc/yum.repos.d/nginx.repo
[nginx-mainline]
name=nginx mainline repo
baseurl=http://nginx.org/packages/mainline/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
        sudo yum install -y nginx
        if [ $? -eq 0 ]; then
            echoContent skyblue "\n nginx安装完成..."
           
            
        else
            echoContent red "\n nginx安装失败!"
            exit 1
        fi
    else
        echoContent red "\n 错误: 不支持的操作系统: ${release}"
        exit 1
    fi
    
  

    # Install Xray and Sing-box
    echoContent skyblue "\n 安装xray..."
   
    version=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=5" | jq -r ".[]|select (.prerelease==false)|.tag_name" | head -1)
    echoContent green " Xray-core版本:${version}"
    if [[ "${release}" == "alpine" ]]; then
        wget -c -q -P /usr/local/nsx/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
    else
        wget -c -q  -P /usr/local/nsx/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
    fi

    if [[ ! -f "/usr/local/nsx/xray/${xrayCoreCPUVendor}.zip" ]]; then
        read -r -p "核心下载失败，请重新尝试安装" 
        exit 1
    else
        echoContent skyblue "开始安装xray..."
        unzip -o "/usr/local/nsx/xray/${xrayCoreCPUVendor}.zip" -d /usr/local/nsx/xray >/dev/null
        rm -rf "/usr/local/nsx/xray/${xrayCoreCPUVendor}.zip"
        chmod 655 /usr/local/nsx/xray/xray
        ln -sf /usr/local/nsx/xray/xray /usr/bin/xray
        echoContent skyblue "安装xray成功..."
    fi
   
    
    echoContent skyblue "安装singbox..."
    version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=20" | jq -r ".[]|select (.prerelease==false)|.tag_name" | head -1)

    echoContent green " sing-box版本:${version}"

    if [[ "${release}" == "alpine" ]]; then
        wget -c -q -P /usr/local/nsx/sing-box/ "https://github.com/SagerNet/sing-box/releases/download/${version}/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz"
    else
        wget -c -q -P /usr/local/nsx/sing-box/ "https://github.com/SagerNet/sing-box/releases/download/${version}/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz"
    fi

    if [[ ! -f "/usr/local/nsx/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz" ]]; then
        echoContent red "核心下载失败，请重新尝试安装" 
        exit 1
    else
        echoContent skyblue "开始安装singbox..."
        tar zxvf "/usr/local/nsx/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz" -C "/usr/local/nsx/sing-box/" >/dev/null 2>&1
        mv "/usr/local/nsx/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}/sing-box" /usr/local/nsx/sing-box
        rm -rf /usr/local/nsx/sing-box/sing-box-*
        chmod 655 /usr/local/nsx/sing-box/sing-box
        ln -sf /usr/local/nsx/sing-box/sing-box /usr/bin/sing-box
        echoContent green "singbox安装成功"
    fi
    read -r -p "本地安装已经完成，是否继续配置？(y/n): " config_nsx
      if [[ "$config_nsx"=="y" ]]; then
        configNSX
      else 
        echoContent green "nginx，xray singbox安装完成，请手动配置"
      fi
   
}
configNSX() {
    updateNSX
    echoContent skyblue "进行nginx的配置修改..."
    configNginx
    echoContent skyblue "\n 删除安装的nginx配置文件，拷贝/usr/local/nsx/nginx/nginx.conf配置文件到/etc/nginx..."
    sudo rm /etc/nginx/conf.d/default.conf
    sudo rm /etc/nginx/nginx.conf
    sudo cp /usr/local/nsx/nginx/nginx.conf /etc/nginx/nginx.conf
    sudo chmod 644 /etc/nginx/nginx.conf
    
    echoContent skyblue "开始创建服务..."
    # Start services
    createSystemdServices

    echoContent skyblue "开始启动服务..."
    echoContent yellow "清理/dev/shm/nsx/."
    sudo rm -rf "$SHM_DIR"/*
    startServices

    echoContent skyblue "进行xray的配置修改..."
    xray_config

    echoContent skyblue "进行singbox的配置修改..."
    singbox_config

    restartServices
    echoContent yellpw "请使用systemctl enable ufw 和systemctl start ufw开启防火墙，用ufw allow port 开启端口访问..."
    aliasInstall


}
# Stop NSX
stopNSX() {
    echoContent skyblue "停止 NSX 容器并清理..."
    # Check if Docker and docker-compose.yml exist
    if ! command -v docker &> /dev/null || [ ! -f "$COMPOSE_FILE" ]; then
        echoContent red "未找到 Docker 或 docker-compose.yml 文件，如果是本地安装，请手动停止服务."
        exit 1
    fi
    # Check if Docker service is running
    if ! systemctl is-active --quiet docker; then
        echoContent red "Docker 服务未运行"
        exit 1
    fi
    # Stop and remove containers
    echoContent yellow "运行 docker compose down..."
    docker compose -f "$COMPOSE_FILE" down
    if [ $? -ne 0 ]; then
        echoContent red "停止 Docker Compose 失败，请检查配置或日志."
        exit 1
    fi

    # Clean up /dev/shm/nsx if empty
    if [ -d "$SHM_DIR" ] && [ -z "$(ls -A "$SHM_DIR")" ]; then
        echoContent yellow "目录 $SHM_DIR 为空，删除..."
        if ! rm -rf "$SHM_DIR"; then
                echoContent red "无法删除 $SHM_DIR，请检查权限."
                exit 1
         fi
    elif [ -d "$SHM_DIR" ]; then
        echoContent yellow "清理 $SHM_DIR 中的文件..."
        if ! rm -rf "$SHM_DIR"/*; then
                echoContent red "无法清理 $SHM_DIR 中的文件，请检查权限."
                exit 1
        fi
    fi

    echoContent green "NSX 容器已停止并清理完成."
}

uninstallNSX() {
    # Define defaults
 

    echoContent skyblue "卸载 NSX 服务..."

    # Stop NSX containers
    if command -v docker &>/dev/null && [[ -f "$COMPOSE_FILE" ]]; then
        stopNSX
    fi

    # Uninstall Xray
   
        read -r -p "确认卸载 Xray？(y/n): " uninstallXray
        if [[ "$uninstallXray" == "y" ]]; then
            echoContent yellow "停止并卸载 Xray..."
            
            if [[ -f "/etc/systemd/system/xray.service" ]]; then
                systemctl stop xray 2>/dev/null
                systemctl disable xray 2>/dev/null
                rm -f /etc/systemd/system/xray.service || {
                    echoContent red "无法删除 xray.service，请检查权限."
                    exit 1
                }
            fi
               if [[ -f "/usr/bin/xray" ]]; then
                rm -rf /usr/bin/xray* || {
                    echoContent red "无法清理 /usr/bin/xray，请检查权限."
                    exit 1
                }
              
            fi
            if [[ -d "/usr/local/nsx/xray" ]]; then
                rm -rf /usr/local/bin/xray/* || {
                    echoContent red "无法清理 /usr/local/bin/xray，请检查权限."
                    exit 1
                }
              
            fi
         
            
            if ! command -v xray &>/dev/null; then
                echoContent green "Xray 卸载完成."
            else
                echoContent red "Xray 卸载失败，xray 命令仍存在."
                exit 1
            fi
        fi
    

    # Uninstall Sing-box
  
        read -r -p "确认卸载 Sing-box？(y/n): " uninstallSingbox
        if [[ "$uninstallSingbox" == "y" ]]; then
            echoContent yellow "停止并卸载 Sing-box..."
          
            if [[ -f "/etc/systemd/system/sing-box.service" ]]; then
                systemctl stop sing-box 2>/dev/null
                systemctl disable sing-box 2>/dev/null
                rm -f /etc/systemd/system/sing-box.service || {
                    echoContent red "无法删除 sing-box.service，请检查权限."
                    exit 1
                }
            fi
               if [[ -f "/usr/bin/sing-box" ]]; then
                rm -rf /usr/bin/sing-box* || {
                    echoContent red "无法清理 /usr/bin/sing-box，请检查权限."
                    exit 1
                }
              
            fi
            if [[ -d "/usr/local/nsx/sing-box" ]]; then
                rm -rf /usr/local/nsx/sing-box/* || {
                    echoContent red "无法清理 /usr/local/nsx/sing-box，请检查权限."
                    exit 1
                }
                rmdir /usr/local/nsx/sing-box 2>/dev/null || true
            fi
        
            if ! command -v sing-box &>/dev/null; then
                echoContent green " Sing-box 卸载完成."
            else
                echoContent red "Sing-box 卸载失败，sing-box 命令仍存在."
                exit 1
            fi
        fi
   

    # Uninstall Nginx
   
        read -r -p "确认卸载 Nginx？(y/n): " uninstallNginx
        if [[ "$uninstallNginx" == "y" ]]; then
            echoContent yellow "停止并卸载 Nginx..."
          
            if [[ -f "/etc/systemd/system/nginx.service" ]]; then
                systemctl stop nginx 2>/dev/null
                systemctl disable nginx 2>/dev/null
                rm -f /etc/systemd/system/nginx.service || {
                    echoContent red "无法删除 nginx.service，请检查权限."
                    exit 1
                }
            fi
            # 卸载 Nginx 软件包
             $uninstallCmd --purge nginx nginx-common nginx-full -y
    
                # 删除残留的配置文件和日志
            rm -rf /etc/nginx /var/log/nginx /var/cache/nginx
            if ! command -v nginx &>/dev/null; then
                echoContent green " Nginx 卸载完成."
            else
                echoContent red "Nginx 卸载失败，nginx 命令仍存在."
                exit 1
            fi
        fi
    

    # Uninstall Docker
    if command -v docker &>/dev/null; then
        read -r -p "确认清理 Docker 容器？(y/n): " uninstallDocker
        if [[ "$uninstallDocker" == "y" ]]; then
            echoContent yellow "停止并卸载 Docker..."
           
            if [[ -f "/etc/systemd/system/docker.service" ]]; then
                systemctl stop docker 2>/dev/null
                systemctl disable docker 2>/dev/null
                rm -f /etc/systemd/system/docker.service || {
                    echoContent red "无法删除 docker.service，请检查权限."
                    exit 1
                }
            fi
          
            # Clean up Docker data (images, containers, volumes)
            if docker system prune -a -f --volumes; then
                echoContent green "Docker 数据清理完成."
            else
                echoContent yellow "警告: Docker 数据清理失败，部分数据可能仍存在."
            fi
            if ! command -v docker &>/dev/null; then
                echoContent green "  Docker 卸载完成."
            else
                echoContent yellow "Docker 数据清理完成，docker 命令仍存在系统中，如果需要卸载，请手动卸载."
                exit 1
            fi
        fi
    fi
    echoContent yellow "清理/dev/shm/nsx/."
    sudo rm -rf "$SHM_DIR"/*
    # Clean up NSX configuration and certificate files
    read -r -p "是否删除 NSX 配置文件和证书？(y/n): " removeConfigs
    if [[ "$removeConfigs" == "y" ]]; then
        echoContent yellow "清理 NSX 配置文件和证书..."
        for file in "$COMPOSE_FILE" "$NGINX_CONF" "$XRAY_CONF" "$SINGBOX_CONF" "$CERT_DIR"/* "$CREDENTIALS_FILE"; do
            if [[ -f "$file" || -d "$file" ]]; then
                rm -rf "$file" || {
                    echoContent red "无法删除 $file，请检查权限."
                    exit 1
                }
            fi
        done
        if [[ -d "/usr/local/nsx" ]]; then
            rmdir /usr/local/nsx 2>/dev/null || true
        fi
        echoContent green "NSX 配置文件和证书清理完成."
    else
        echoContent yellow "保留 NSX 配置文件和证书."
    fi

    # Reload systemd daemon
    if ! systemctl daemon-reload; then
        echoContent red "无法重新加载 systemd 配置，请检查."
        exit 1
    fi

    echoContent green "NSX 卸载完成."
}
# Main menu
menu() {
    clear
    echoContent red "\n=============================================================="
    echoContent green "NSX 安装管理脚本"
    echoContent green "作者: JudaWu"
    echoContent green "版本: v0.0.2"
    echoContent green "Github: https://github.com/judawu/nsx"
    echoContent green "描述: 一个集成 Nginx、Sing-box 和 Xray 的代理环境"
    echoContent red "\n=============================================================="
   
    echoContent yellow "1. 阅读说明"   
    echoContent yellow "2. 使用 Docker 安装 NSX"
    echoContent yellow "3. 本地安装 NSX"
    echoContent yellow "4. 证书管理"
    echoContent yellow "5. 配置管理"
    echoContent yellow "6. 日志管理"
    echoContent yellow "7. 更新脚本"
    echoContent yellow "8. 停止 Docker"
    echoContent yellow "9. 生成订阅"
    echoContent yellow "10. 卸载nsx"
    echoContent yellow "11. 退出"
    read -r -p "请选择一个选项 [1-9]: " option

    case $option in
        1)
        echoContent green "输入nsx启动脚本\n选择2 安装Docker版服务用docker启动\n选择3安装XRAY,SINGBOX,NINGX到本机\n选择4进行证书申请\n选择5进行配置文件修改"
        exit 1;;
        2)dockerInstall ;;
        3) localInstall ;;
        4) manageCertificates ;;
        5) manageConfigurations ;;
        6) manageLogs ;;
        7) updateNSX ;;
        8) stopNSX ;;
        9) generateSubscriptions ;;
        10)uninstallNSX ;;
        11) exit 0 ;;
        *) echoContent red "无效选项." ; menu ;;
    esac
}

# Start script
checkSystem
menu