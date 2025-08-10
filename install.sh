#!/usr/bin/env bash

# NSX Installation and Management Script
# Project directory: /usr/local/nsx
# Supports Docker and local installation, certificate management, and configuration management

# Set language
export LANG=en_US.UTF-8

# Colors for output
echoContent() {
    case $1 in
        "red") echo -e "\033[31m${2}\033[0m" ;;
        "green") echo -e "\033[32m${2}\033[0m" ;;
        "yellow") echo -e "\033[33m${2}\033[0m" ;;
        "skyBlue") echo -e "\033[1;36m${2}\033[0m" ;;
    esac
}

# Define variables
BASE_DIR="/usr/local/nsx"
CERT_DIR="${BASE_DIR}/certs"
NGINX_DIR="${BASE_DIR}/nginx"
XRAY_DIR="${BASE_DIR}/xray"
SINGBOX_DIR="${BASE_DIR}/sing-box"
WWW_DIR="${BASE_DIR}/www"
SUBSCRIBE_DIR="${BASE_DIR}/www/subscribe"
COMPOSE_FILE="${BASE_DIR}/docker/docker-compose.yml"
NGINX_CONF="${NGINX_DIR}/nginx.conf"
XRAY_CONF="${XRAY_DIR}/config.json"
SINGBOX_CONF="${SINGBOX_DIR}/config.json"
NGINX_SHM_DIR="/dev/shm/nsx"
NGINX_LOG_DIR="${NGINX_DIR}/log"
NGINX_CACHE_DIR="${NGINX_DIR}/cache"
NGINX_RUN_DIR="${NGINX_DIR}/run"
NGINX_CONF_DIR="${NGINX_DIR}/conf.d"
XRAY_LOG_DIR="${XRAY_DIR}/log"
SINGBOX_LOG_DIR="${SINGBOX_DIR}/log"
ACME_DIR="${BASE_DIR}/acme"
ACME_LOG="${ACME_DIR}/acme.log"
TOTAL_PROGRESS=5

# Check system information
checkSystem() {
    echoContent skyBlue "检查系统..."
    if [[ -n $(find /etc -name "redhat-release") ]] || grep -q -i "centos" /etc/os-release || grep -q -i "rocky" /etc/os-release; then
        release="centos"
        installCmd='yum -y install'
        upgradeCmd='yum -y update'
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

# Check SELinux
checkCentosSELinux() {
    if [[ "$release" == "centos" ]] && [[ -f "/etc/selinux/config" ]] && ! grep -q "SELINUX=disabled" /etc/selinux/config; then
        echoContent yellow "禁用 SELinux 以确保兼容性..."
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

# Install tools
installTools() {
    echoContent skyBlue "\n进度 1/${TOTAL_PROGRESS} : 安装工具..."
    echoContent Green "\n安装以下依赖curl wget git sudo lsof unzip ufw socat jq iputils-ping dnsutils qrencode.."
    ${installCmd} curl wget git sudo lsof unzip ufw socat jq iputils-ping dnsutils qrencode -y
  
    if [[ "$release" != "centos" ]]; then
        echoContent Green "\n执行系统更新..."
        ${upgradeCmd}
        ${updateCmd}

    fi
}

# Install Docker and Docker Compose
installDocker() {
    echoContent skyBlue "\n进度 2/${TOTAL_PROGRESS} : 检查 Docker 安装..."
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

    # Check for Docker Compose plugin
    if ! docker compose version &> /dev/null; then
        echoContent yellow "安装 Docker Compose 插件..."
        if [[ "$release" == "ubuntu" || "$release" == "debian" ]]; then
            ${upgradeCmd}
            ${installCmd} docker-compose-plugin
            if [ $? -ne 0 ]; then
                echoContent red "通过 apt 安装 Docker Compose 插件失败."
                exit 1
            fi
        elif [[ "$release" == "centos" ]]; then
            # Install Docker Compose plugin binary for CentOS/Rocky Linux
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

    # Verify Docker Compose version
    docker compose version
    if [ $? -eq 0 ]; then
        echoContent green "Docker Compose 插件验证成功: $(docker compose version --short)"
    else
        echoContent red "Docker Compose 插件验证失败，请手动安装."
        exit 1
    fi
}

# Create directories
createDirectories() {
    echoContent skyBlue "\n进度 3/${TOTAL_PROGRESS} : 创建目录..."
    for DIR in "$CERT_DIR" "$NGINX_DIR" "$NGINX_LOG_DIR" "$NGINX_CACHE_DIR" "$NGINX_RUN_DIR" "$NGINX_CONF_DIR" "$XRAY_DIR" "$XRAY_LOG_DIR" "$SINGBOX_DIR" "$SINGBOX_LOG_DIR" "$WWW_DIR"  "$SUBSCRIBE_DIR" "$WWW_DIR/wwwroot/blog" "$WWW_DIR/wwwroot/video" "$NGINX_SHM_DIR" "$ACME_DIR"; do
        if [ ! -d "$DIR" ]; then
            echoContent yellow "创建目录 $DIR..."
            mkdir -p "$DIR"
        else
            echoContent green "目录 $DIR 已存在."
        fi
    done

    echoContent yellow "设置权限..."
    chown -R nobody:nogroup "$NGINX_SHM_DIR" "$NGINX_LOG_DIR" "$XRAY_LOG_DIR" "$SINGBOX_LOG_DIR" "$CERT_DIR" "$NGINX_CACHE_DIR" "$NGINX_RUN_DIR" "$NGINX_CONF_DIR" "$ACME_DIR"
    chmod -R 700 "$NGINX_SHM_DIR" "$NGINX_LOG_DIR" "$XRAY_LOG_DIR" "$SINGBOX_LOG_DIR" "$CERT_DIR" "$NGINX_CACHE_DIR" "$NGINX_RUN_DIR" "$NGINX_CONF_DIR" "$ACME_DIR"
}

# Install acme.sh
installAcme() {
    if [[ ! -d "$HOME/.acme.sh" ]] || [[ -d "$HOME/.acme.sh" && -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
        echoContent skyBlue "\n进度 4/${TOTAL_PROGRESS} : 安装证书程序 acme.sh..."
        curl https://get.acme.sh | sh
        if [[ $? -ne 0 ]]; then
            echoContent red "安装 acme.sh 失败，请参考 https://github.com/acmesh-official/acme.sh."
            exit 1
        fi
    else
        echoContent green "acme.sh 已安装."
    fi
}
# Manage certificates
manageCertificates() {
    # Define defaults
    ACME_LOG="${ACME_LOG:-/var/log/acme.log}"
    CERT_DIR="${CERT_DIR:-/etc/ssl/private}"
    CREDENTIALS_FILE="${HOME}/.acme.sh/credentials.conf"
    mkdir -p "$CERT_DIR" || { echoContent red "无法创建 $CERT_DIR"; exit 1; }
    touch "$CREDENTIALS_FILE" && chmod 600 "$CREDENTIALS_FILE" || { echoContent red "无法创建 $CREDENTIALS_FILE"; exit 1; }

    echoContent skyBlue "\n证书管理菜单"
    echoContent yellow "1. 申请证书"
    echoContent yellow "2. 更新证书"
    echoContent yellow "3. 安装自签证书"
    echoContent yellow "4. 退出"
    read -r -p "请选择一个选项 [1-4]: " cert_option

    case $cert_option in
        1|2)
            local action="--issue"
            [[ "$cert_option" == "2" ]] && action="--renew"
            echoContent skyBlue "${action##--}证书..."
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
            echoContent skyBlue " SSL 类型为 $sslType."
            read -r -p "请输入证书域名 (例如: yourdomain.com 或 *.yourdomain.com，多个域名用逗号隔开): " DOMAIN
            if [[ -z "$DOMAIN" ]]; then
                echoContent red "请输入域名"
                return 1
            fi
            # Extract the first domain for certificate naming
            FIRST_DOMAIN=$(echo "$DOMAIN" | cut -d',' -f1 | xargs)
            echoContent skyBlue " 证书域名为 $DOMAIN (使用 $FIRST_DOMAIN 作为证书文件名)."
            read -r -p "请输入DNS提供商: 0.Cloudflare, 1.阿里云, 2.手动DNS, 3.独立: " DNS_VENDOR

            if [[ "$cert_option" == "1" ]]; then
                # Clear previous credentials for this domain
                grep -v "^${FIRST_DOMAIN}:" "$CREDENTIALS_FILE" > "${CREDENTIALS_FILE}.tmp" && mv "${CREDENTIALS_FILE}.tmp" "$CREDENTIALS_FILE"
            fi
            echoContent skyBlue " DNS提供商选择 $DNS_VENDOR."
            if [[ "$DNS_VENDOR" == "0" ]]; then
                if [[ "$cert_option" == "2" && -s "$CREDENTIALS_FILE" && $(grep "^${FIRST_DOMAIN}:Cloudflare:" "$CREDENTIALS_FILE") ]]; then
                    # Load saved Cloudflare credentials for renewal
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
                if [[ "$cert_option" == "2" && -s "$CREDENTIALS_FILE" && $(grep "^${FIRST_DOMAIN}:Alibaba:" "$CREDENTIALS_FILE") ]]; then
                    # Load saved Alibaba credentials for renewal
                    IFS=':' read -r _ _ aliKey aliSecret < <(grep "^${FIRST_DOMAIN}:Alibaba:" "$CREDENTIALS_FILE")
                    echoContent green " ---> 使用保存的阿里云凭据进行续订"
                else
                    read -r -p "请输入阿里云 Key: " aliKey
                    read -r -p "请输入阿里云 Secret: " aliSecret
                    if [[ -z "${aliKey}" || -z "${aliSecret}" ]]; then
                        echoContent red " ---> 输入为空，请重试"
                        return 1
                    fi
                    echoContent green " ---> 保存阿里云 Key 和 Secret"
                    echo "${FIRST_DOMAIN}:Alibaba:${aliKey}:${aliSecret}" >> "$CREDENTIALS_FILE"
                fi
                echoContent green " ---> 阿里云 DNS API ${action##--}证书中"
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
                    echoContent green " ---> 名称: _acme-challenge"
                    echoContent green " ---> 值: ${txtValue}"
                    echoContent yellow " ---> 请添加 TXT 记录（例如在cloudware中在DNS下手动建立TXT文件，将下面的字符串${txtValue}输入）并等待 1-2 分钟"
                    read -r -p "是否已添加 TXT 记录? [y/n]: " addDNSTXTRecordStatus
                    if [[ "$addDNSTXTRecordStatus" == "y" ]]; then
                        txtAnswer=$(dig @1.1.1.1 +nocmd "_acme-challenge.${FIRST_DOMAIN}" txt +noall +answer | awk -F "[\"]" '{print $2}' | head -1)
                        if echo "$txtAnswer" | grep -q "^${txtValue}"; then
                            echoContent green " ---> TXT 记录验证通过"
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
            echoContent skyBlue "安装自签证书..."
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
            echoContent skyBlue "为 ${DOMAIN} 生成自签证书..."
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
xray_config(){
    echoContent skyBlue "\nxray配置文件修改"
   
# 检查 jq 和 xray 是否已安装
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install jq first."
    exit 1
fi

if ! command -v xray &> /dev/null; then
    echo "Error: xray is not installed. Please install xray first."
    exit 1
fi

# JSON 文件路径
TEMP_FILE="config_temp.json"

# 检查 config.json 是否存在
if [[ ! -f "$XRAY_CONF" ]]; then
    echo "Error: $XRAY_CONF does not exist."
    exit 1
fi

# 获取用户输入的域名
read -p "请输入域名替换文件中 'yourdomain' (e.g., example.com): " YOURDOMAIN
if [[ -z "$YOURDOMAIN" ]]; then
    echo "Error: 域名不能为空."
    exit 1
fi

# 备份原始文件
cp "$XRAY_CONF" "${XRAY_CONF}.bak"
echo "创建备份: ${XRAY_CONF}.bak"

# 生成随机的 shortIds（8 字节和 16 字节的十六进制字符串）
generate_short_ids() {
    short_id1=$(openssl rand -hex 4)  # 8 字节
    short_id2=$(openssl rand -hex 8)  # 16 字节
    echo "[\"$short_id1\", \"$short_id2\"]"
}



# 提取所有 inbounds
inbounds=$(jq -c '.inbounds[] | select(.settings.clients)' "$XRAY_CONF")

# 创建一个临时 JSON 文件，复制原始内容
cp "$XRAY_CONF" "$TEMP_FILE"

# 遍历每个 inbound
echo "$inbounds" | while IFS= read -r inbound; do
    tag=$(echo "$inbound" | jq -r '.tag')
    protocol=$(echo "$inbound" | jq -r '.protocol')
    echo "Processing inbound with tag: $tag, protocol: $protocol"

    # 处理 vless 和 vmess 的 id 替换
    if [[ "$protocol" == "vless" || "$protocol" == "vmess" ]]; then
        clients=$(echo "$inbound" | jq -c '.settings.clients[]')
        client_index=0
        echo "$clients" | while IFS= read -r client; do
            old_id=$(echo "$client" | jq -r '.id')
            new_id=$(xray uuid)
            echo "Replacing ID for client $client_index in $tag: $old_id -> $new_id"

            # 更新 id
            jq --arg tag "$tag" --arg old_id "$old_id" --arg new_id "$new_id" \
               '(.inbounds[] | select(.tag == $tag) | .settings.clients[] | select(.id == $old_id)).id = $new_id' \
               "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE"
            ((client_index++))
        done
    fi

    # 处理 trojan 和 shadowsocks 的 password 替换
    if [[ "$protocol" == "trojan" || "$protocol" == "shadowsocks" ]]; then
        clients=$(echo "$inbound" | jq -c '.settings.clients[]')
        client_index=0
        echo "$clients" | while IFS= read -r client; do
            old_password=$(echo "$client" | jq -r '.password')
            new_password=$(openssl rand -base64 16)  # 生成 16 字节的 base64 密码
            echo "Replacing password for client $client_index in $tag: $old_password -> $new_password"

            # 更新 password
            jq --arg tag "$tag" --arg old_password "$old_password" --arg new_password "$new_password" \
               '(.inbounds[] | select(.tag == $tag) | .settings.clients[] | select(.password == $old_password)).password = $new_password' \
               "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE"
            ((client_index++))
        done
    fi

    # 检查 streamSettings.security 是否为 reality
    security=$(echo "$inbound" | jq -r '.streamSettings.security // "none"')
    if [[ "$security" == "reality" ]]; then
        echo "Detected reality security for $tag, updating keys and settings..."

        # 生成公私密钥对
        key_pair=$(xray x25519)
        private_key=$(echo "$key_pair" | grep "Private key" | awk '{print $3}')
        public_key=$(echo "$key_pair" | grep "Public key" | awk '{print $3}')
        new_short_ids=$(generate_short_ids)
        new_mldsa65_key_pair=$(xray mldsa65)
        mldsa65_seed=$(echo "$new_mldsa65_key_pair" | grep "Seed" | awk '{print $2}')
        mldsa65_verfify=$(echo "$new_mldsa65_key_pair" | grep "Verify" | awk '{print $2}')

        echo "Generated new privateKey: $private_key"
        echo "Generated new publicKey: $public_key"
        echo "Generated new shortIds: $new_short_ids"
        echo "Generated new mldsa65Seed: $new_mldsa65_key_pair"

        # 更新 privateKey, publicKey, shortIds, mldsa65Seed
        jq --arg tag "$tag" --arg private_key "$private_key" --arg public_key "$public_key" --argjson short_ids "$new_short_ids" --arg mldsa65_seed "$new_mldsa65_seed" \
           '(.inbounds[] | select(.tag == $tag) | .streamSettings.realitySettings) |=
            (.privateKey = $private_key | .password = $public_key | .shortIds = $short_ids | .mldsa65Seed = $mldsa65_seed | .mldsa65Verify = $mldsa65Verify)' \
           "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE"
    fi
done

# 替换 yourdomain 为用户输入的域名
jq --arg domain "$YOURDOMAIN" \
   'walk(if type == "string" then gsub("yourdomain"; $domain) else . end)' \
   "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE"

# 替换原始文件
mv "$TEMP_FILE" "$XRAY_CONF"
echo "Updated $XRAY_CONF with new UUIDs, passwords, reality settings, and domain."

# 验证 JSON 文件是否有效
if jq empty "$XRAY_CONF" &> /dev/null; then
    echo "JSON file is valid."
else
    echo "Error: Updated JSON file is invalid. Restoring backup."
    mv "${CONFIG_FILE}.bak" "$XRAY_CONF"
    exit 1
fi

}
singbox_config(){
    echoContent skyBlue "\nsingbox配置文件修改"
  #!/bin/bash

# 检查 jq 和 sing-box 是否已安装
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install jq first."
    exit 1
fi

if ! command -v sing-box &> /dev/null; then
    echo "Error: sing-box is not installed. Please install sing-box first."
    exit 1
fi


TEMP_FILE="config_temp.json"

# 检查 config.json 是否存在
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: $CONFIG_FILE does not exist."
    exit 1
fi

# 获取用户输入的域名
read -p "Please enter the domain to replace 'yourdomain' (e.g., example.com): " SINGGOBXDOMAIN
if [[ -z "$SINGGOBXDOMAIN" ]]; then
    echo "Error: Domain cannot be empty."
    exit 1
fi

# 备份原始文件
cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
echo "Backup created: ${CONFIG_FILE}.bak"

# 生成随机的 short_id（16 字节的十六进制字符串）
generate_short_ids() {
    short_id=$(openssl rand -hex 8)  # 16 字节
    echo "[\"\", \"$short_id\"]"
}

# 提取所有 inbounds
inbounds=$(jq -c '.inbounds[] | select(.users)' "$CONFIG_FILE")

# 创建一个临时 JSON 文件，复制原始内容
cp "$CONFIG_FILE" "$TEMP_FILE"

# 遍历每个 inbound
echo "$inbounds" | while IFS= read -r inbound; do
    tag=$(echo "$inbound" | jq -r '.tag')
    type=$(echo "$inbound" | jq -r '.type')
    echo "Processing inbound with tag: $tag, type: $type"

    # 处理 vmess、vless 和 tuic 的 uuid 替换
    if [[ "$type" == "vmess" || "$type" == "vless" || "$type" == "tuic" ]]; then
        users=$(echo "$inbound" | jq -c '.users[]')
        user_index=0
        echo "$users" | while IFS= read -r user; do
            old_uuid=$(echo "$user" | jq -r '.uuid')
            new_uuid=$(sing-box generate uuid)
            echo "Replacing UUID for user $user_index in $tag: $old_uuid -> $new_uuid"

            # 更新 uuid
            jq --arg tag "$tag" --arg old_uuid "$old_uuid" --arg new_uuid "$new_uuid" \
               '(.inbounds[] | select(.tag == $tag) | .users[] | select(.uuid == $old_uuid)).uuid = $new_uuid' \
               "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE"
            ((user_index++))
        done
    fi

    # 处理 trojan、shadowsocks、shadowtls 和 hysteria2 的 password 替换
    if [[ "$type" == "trojan" || "$type" == "shadowsocks" || "$type" == "shadowtls" || "$type" == "hysteria2" ]]; then
        users=$(echo "$inbound" | jq -c '.users[]')
        user_index=0
        echo "$users" | while IFS= read -r user; do
            old_password=$(echo "$user" | jq -r '.password')
            # 为 shadowsocks 和 shadowtls 生成 2022-blake3-aes-128-gcm 兼容的 16 字节密码
            if [[ "$type" == "shadowsocks" || "$type" == "shadowtls" ]]; then
                new_password=$(openssl rand -base64 16)
            else
                new_password=$(sing-box generate uuid)  # trojan 和 hysteria2 使用 UUID 格式密码
            fi
            echo "Replacing password for user $user_index in $tag: $old_password -> $new_password"

            # 更新 password
            jq --arg tag "$tag" --arg old_password "$old_password" --arg new_password "$new_password" \
               '(.inbounds[] | select(.tag == $tag) | .users[] | select(.password == $old_password)).password = $new_password' \
               "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE"
            ((user_index++))
        done

        # 如果是 shadowsocks 或 shadowtls，更新顶层的 password 字段（如果存在）
        if [[ "$type" == "shadowsocks" || "$type" == "shadowtls" ]]; then
            top_password=$(echo "$inbound" | jq -r '.password // empty')
            if [[ -n "$top_password" ]]; then
                new_top_password=$(openssl rand -base64 16)
                echo "Replacing top-level password in $tag: $top_password -> $new_top_password"
                jq --arg tag "$tag" --arg new_password "$new_top_password" \
                   '(.inbounds[] | select(.tag == $tag)).password = $new_password' \
                   "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE"
            fi
        fi
    fi

    # 检查 tls.reality.enabled 是否为 true
    reality_enabled=$(echo "$inbound" | jq -r '.tls.reality.enabled // false')
    if [[ "$reality_enabled" == "true" ]]; then
        echo "Detected reality TLS for $tag, updating keys and settings..."

        # 生成公私密钥对
        key_pair=$(sing-box generate reality-keypair)
        private_key=$(echo "$key_pair" | grep "PrivateKey" | awk '{print $2}')
        public_key=$(echo "$key_pair" | grep "PublicKey" | awk '{print $2}')
        new_short_ids=$(generate_short_ids)

        echo "Generated new private_key: $private_key"
        echo "Generated new public_key: $public_key"
        echo "Generated new short_id: $new_short_ids"

        # 更新 private_key, public_key, short_id
        jq --arg tag "$tag" --arg private_key "$private_key" --arg public_key "$public_key" --argjson short_ids "$new_short_ids" \
           '(.inbounds[] | select(.tag == $tag) | .tls.reality) |=
            (.private_key = $private_key | .public_key = $public_key | .short_id = $short_ids)' \
           "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE"
    fi
done

# 替换 yourdomain 为用户输入的域名
jq --arg domain "$SINGGOBXDOMAIN" \
   'walk(if type == "string" then gsub("yourdomain"; $domain) else . end)' \
   "$TEMP_FILE" > "${TEMP_FILE}.tmp" && mv "${TEMP_FILE}.tmp" "$TEMP_FILE"

# 替换原始文件
mv "$TEMP_FILE" "$CONFIG_FILE"
echo "Updated $CONFIG_FILE with new UUIDs, passwords, reality settings, and domain."

# 验证 JSON 文件是否有效
if jq empty "$CONFIG_FILE" &> /dev/null; then
    echo "JSON file is valid."
else
    echo "Error: Updated JSON file is invalid. Restoring backup."
    mv "${CONFIG_FILE}.bak" "$CONFIG_FILE"
    exit 1
fi
}

# Manage configurations
manageConfigurations() {
    echoContent skyBlue "\n配置管理菜单"
    echoContent yellow "1. 修改 nginx.conf"
    echoContent yellow "2. 修改 xray config.json"
    echoContent yellow "3. 修改 sing-box config.json"
    echoContent yellow "4. 退出"
    read -r -p "请选择一个选项 [1-4]: " config_option

    case $config_option in
        1)
            echoContent green "nginx.conf 采用stream模块分流\n 包括tls,reality,pre,sing等前缀域名进行分流 ."
            read -r -p "请输入 nginx.conf 配置中替换tls.yourdomain的新域名 (后端xray tls解密): " TLS_YOURDOMAIN
            read -r -p "请输入 nginx.conf 配置中替换reality.yourdomain的新域名 (后端xray reality解密): " REALITY_YOURDOMAIN
            read -r -p "请输入 nginx.conf 配置中替换pre.yourdomain的新域名 (前端nignx解密): " PRE_YOURDOMAIN
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
            sed -i "s/yourIP/$NEW_IP/g" "$NGINX_CONF"
            sed -i "s/listen 443/listen $NEW_PORT/g" "$NGINX_CONF"
            echoContent green "nginx.conf 更新成功."
            # Reload Nginx if running
            if pgrep nginx > /dev/null; then
                nginx -s reload
                echoContent green "Nginx 已重载以应用新配置."
            elif docker ps | grep -q nginx; then
                docker compose -f "$COMPOSE_FILE" restart
                echoContent green "Docker Compose 已重启以应用新配置."
            fi
            ;;
        2)
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
        3)
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
        4)
            return
            ;;
        *)
            echoContent red "无效选项."
            manageConfigurations
            ;;
    esac
}
# Generate subscriptions
generateSubscriptions() {
    echoContent skyBlue "\n生成订阅..."
    read -r -p "请输入订阅域名 (例如: sing.yourdomain): " SUB_DOMAIN
    if [[ -z "$SUB_DOMAIN" ]]; then
        echoContent red "域名不能为空."
        return 1
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

        # VLESS subscriptions
        XRAY_VLESS=$(jq -r '.inbounds[] | select(.protocol=="vless") | .tag as $tag | .settings.clients[] | . as $client | .streamSettings // {network:"tcp",security:"none"} | "\($tag)#\(.id)#\(.email)#\(input_filename)#\(.streamSettings.network // "tcp")#\(.streamSettings.security // "none")#\(.streamSettings.realitySettings.shortIds[0] // "")#\(.streamSettings.grpcSettings.serviceName // "")#\(.streamSettings.wsSettings.path // "")#\(.streamSettings.splithttpSettings.path // "")#\(.streamSettings.httpupgradeSettings.path // "")#\(.streamSettings.kcpSettings.seed // "")"' "$XRAY_CONF")
        while IFS='#' read -r tag uuid email filename network security short_id grpc_path ws_path splithttp_path httpupgrade_path kcp_seed; do
            port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag==$tag) | .port // (.listen | split(":")[-1])' "$XRAY_CONF")
            if [[ "$port" == "null" || -z "$port" ]]; then
                port="443"
            fi
            if [[ "$port" == "null" || -z "$port" ]]; then
                continue
            fi
            params=""
            case "$network" in
                "grpc") params="type=grpc&serviceName=${grpc_path}" ;;
                "ws") params="type=ws&path=${ws_path}" ;;
                "splithttp") params="type=http&path=${splithttp_path}" ;;
                "httpupgrade") params="type=httpupgrade&path=${httpupgrade_path}" ;;
                "kcp") params="type=kcp&seed=${kcp_seed}" ;;
                *) params="type=tcp" ;;
            esac
            if [[ "$security" == "reality" ]]; then
                params="${params}&security=reality&sid=${short_id}"
            elif [[ "$security" == "tls" ]]; then
                params="${params}&security=tls"
            fi
            SUB_LINK="vless://${uuid}@${SUB_DOMAIN}:${port}?${params}#${email}"
            echo "$SUB_LINK" >> "$XRAY_SUB_FILE"
            qrencode -o "${SUBSCRIBE_DIR}/vless_${email//[@\/]/_}.png" "$SUB_LINK"
            echoContent green "生成 Xray VLESS 订阅链接: $SUB_LINK"
        done <<< "$XRAY_VLESS"

        # VMess subscriptions
        XRAY_VMESS=$(jq -r '.inbounds[] | select(.protocol=="vmess") | .tag as $tag | .settings.clients[] | . as $client | .streamSettings // {network:"tcp"} | "\($tag)#\(.id)#\(.email)#\(input_filename)#\(.streamSettings.network // "tcp")#\(.streamSettings.wsSettings.path // "")"' "$XRAY_CONF")
        while IFS='#' read -r tag uuid email filename network ws_path; do
            port="443"
            if [[ "$port" == "null" || -z "$port" ]]; then
                continue
            fi
            vmess_json=$(jq -n --arg id "$uuid" --arg add "$SUB_DOMAIN" --arg port "$port" --arg ps "$email" --arg path "$ws_path" \
                '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:0,net:($ws_path != "" | if . then "ws" else "tcp" end),type:"none",tls:"tls",path:$path}')
            SUB_LINK="vmess://$(echo -n "$vmess_json" | base64 -w 0)"
            echo "$SUB_LINK" >> "$XRAY_SUB_FILE"
            qrencode -o "${SUBSCRIBE_DIR}/vmess_${email//[@\/]/_}.png" "$SUB_LINK"
            echoContent green "生成 Xray VMess 订阅链接: $SUB_LINK"
        done <<< "$XRAY_VMESS"

        # Trojan subscriptions
        XRAY_TROJAN=$(jq -r '.inbounds[] | select(.protocol=="trojan") | .tag as $tag | .settings.clients[] | "\($tag)#\(.password)#\(.email)#\(input_filename)"' "$XRAY_CONF")
        while IFS='#' read -r tag password email filename; do
            port=443
            if [[ "$port" == "null" || -z "$port" ]]; then
                continue
            fi
            SUB_LINK="trojan://${password}@${SUB_DOMAIN}:${port}?security=tls#${email}"
            echo "$SUB_LINK" >> "$XRAY_SUB_FILE"
            qrencode -o "${SUBSCRIBE_DIR}/trojan_${email//[@\/]/_}.png" "$SUB_LINK"
            echoContent green "生成 Xray Trojan 订阅链接: $SUB_LINK"
        done <<< "$XRAY_TROJAN"

        # Shadowsocks subscriptions
        XRAY_SS=$(jq -r '.inbounds[] | select(.protocol=="shadowsocks") | .tag as $tag | .settings.clients[] | "\($tag)#\(.password)#\(.email)#\(input_filename)#\(.settings.method)"' "$XRAY_CONF")
        while IFS='#' read -r tag password email filename method; do
            port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag==$tag) | .port' "$XRAY_CONF")
            if [[ "$port" == "null" || -z "$port" ]]; then
                continue
            fi
            SUB_LINK="ss://$(echo -n "${method}:${password}" | base64 -w 0)@${SUB_DOMAIN}:${port}#${email}"
            echo "$SUB_LINK" >> "$XRAY_SUB_FILE"
            qrencode -o "${SUBSCRIBE_DIR}/ss_${email//[@\/]/_}.png" "$SUB_LINK"
            echoContent green "生成 Xray Shadowsocks 订阅链接: $SUB_LINK"
        done <<< "$XRAY_SS"

        if [ -s "$XRAY_SUB_FILE" ]; then
            echo "$(cat "$XRAY_SUB_FILE" | base64 -w 0)" > "$XRAY_SUB_FILE"
            chown nobody:nogroup "$XRAY_SUB_FILE" "${SUBSCRIBE_DIR}/vless_*.png" "${SUBSCRIBE_DIR}/vmess_*.png" "${SUBSCRIBE_DIR}/trojan_*.png" "${SUBSCRIBE_DIR}/ss_*.png"
            chmod 644 "$XRAY_SUB_FILE" "${SUBSCRIBE_DIR}/vless_*.png" "${SUBSCRIBE_DIR}/vmess_*.png" "${SUBSCRIBE_DIR}/trojan_*.png" "${SUBSCRIBE_DIR}/ss_*.png"
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

        # VLESS subscriptions
        SINGBOX_VLESS=$(jq -r '.inbounds[] | select(.type=="vless") | .tag as $tag | .users[] | . as $user | .tls // {enabled:false} | "\($tag)#\(.uuid)#\(.name)#\(input_filename)#\(.tls.enabled)#\(.tls.reality.enabled // false)#\(.tls.reality.short_id[0] // "")#\(.transport.type // "tcp")#\(.transport.service_name // "")#\(.transport.path // "")"' "$SINGBOX_CONF")
        while IFS='#' read -r tag uuid name filename tls_enabled reality_enabled short_id transport service_name path; do
            port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag==$tag) | .listen_port' "$SINGBOX_CONF")
            if [[ "$port" == "null" || -z "$port" ]]; then
                continue
            fi
            params=""
            case "$transport" in
                "grpc") params="type=grpc&serviceName=${service_name}" ;;
                "http") params="type=http&path=${path}" ;;
                *) params="type=tcp" ;;
            esac
            if [[ "$reality_enabled" == "true" ]]; then
                params="${params}&security=reality&sid=${short_id}"
            elif [[ "$tls_enabled" == "true" ]]; then
                params="${params}&security=tls"
            fi
            SUB_LINK="vless://${uuid}@${SUB_DOMAIN}:${port}?${params}#${name}"
            echo "$SUB_LINK" >> "$SINGBOX_SUB_FILE"
            qrencode -o "${SUBSCRIBE_DIR}/vless_${name//[@\/]/_}.png" "$SUB_LINK"
            echoContent green "生成 Sing-box VLESS 订阅链接: $SUB_LINK"
        done <<< "$SINGBOX_VLESS"

        # VMess subscriptions
        SINGBOX_VMESS=$(jq -r '.inbounds[] | select(.type=="vmess") | .tag as $tag | .users[] | "\($tag)#\(.uuid)#\(.name)#\(input_filename)"' "$SINGBOX_CONF")
        while IFS='#' read -r tag uuid name filename; do
            port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag==$tag) | .listen_port' "$SINGBOX_CONF")
            if [[ "$port" == "null" || -z "$port" ]]; then
                continue
            fi
            vmess_json=$(jq -n --arg id "$uuid" --arg add "$SUB_DOMAIN" --arg port "$port" --arg ps "$name" \
                '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:0,net:"tcp",type:"none",tls:"none"}')
            SUB_LINK="vmess://$(echo -n "$vmess_json" | base64 -w 0)"
            echo "$SUB_LINK" >> "$SINGBOX_SUB_FILE"
            qrencode -o "${SUBSCRIBE_DIR}/vmess_${name//[@\/]/_}.png" "$SUB_LINK"
            echoContent green "生成 Sing-box VMess 订阅链接: $SUB_LINK"
        done <<< "$SINGBOX_VMESS"

        # Trojan subscriptions
        SINGBOX_TROJAN=$(jq -r '.inbounds[] | select(.type=="trojan") | .tag as $tag | .users[] | "\($tag)#\(.password)#\(.name)#\(input_filename)"' "$SINGBOX_CONF")
        while IFS='#' read -r tag password name filename; do
            port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag==$tag) | .listen_port' "$SINGBOX_CONF")
            if [[ "$port" == "null" || -z "$port" ]]; then
                continue
            fi
            SUB_LINK="trojan://${password}@${SUB_DOMAIN}:${port}?security=tls#${name}"
            echo "$SUB_LINK" >> "$SINGBOX_SUB_FILE"
            qrencode -o "${SUBSCRIBE_DIR}/trojan_${name//[@\/]/_}.png" "$SUB_LINK"
            echoContent green "生成 Sing-box Trojan 订阅链接: $SUB_LINK"
        done <<< "$SINGBOX_TROJAN"

        # Shadowsocks subscriptions
        SINGBOX_SS=$(jq -r '.inbounds[] | select(.type=="shadowsocks") | .tag as $tag | .users[] | "\($tag)#\(.password)#\(.name)#\(input_filename)#\(.method)"' "$SINGBOX_CONF")
        while IFS='#' read -r tag password name filename method; do
            port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag==$tag) | .listen_port' "$SINGBOX_CONF")
            if [[ "$port" == "null" || -z "$port" ]]; then
                continue
            fi
            SUB_LINK="ss://$(echo -n "${method}:${password}" | base64 -w 0)@${SUB_DOMAIN}:${port}#${name}"
            echo "$SUB_LINK" >> "$SINGBOX_SUB_FILE"
            qrencode -o "${SUBSCRIBE_DIR}/ss_${name//[@\/]/_}.png" "$SUB_LINK"
            echoContent green "生成 Sing-box Shadowsocks 订阅链接: $SUB_LINK"
        done <<< "$SINGBOX_SS"

        # Hysteria2 subscriptions
        SINGBOX_HYSTERIA2=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .tag as $tag | .users[] | "\($tag)#\(.password)#\(.name)#\(input_filename)"' "$SINGBOX_CONF")
        while IFS='#' read -r tag password name filename; do
            port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag==$tag) | .listen_port' "$SINGBOX_CONF")
            if [[ "$port" == "null" || -z "$port" ]]; then
                continue
            fi
            SUB_LINK="hysteria2://${password}@${SUB_DOMAIN}:${port}?insecure=0#${name}"
            echo "$SUB_LINK" >> "$SINGBOX_SUB_FILE"
            qrencode -o "${SUBSCRIBE_DIR}/hysteria2_${name//[@\/]/_}.png" "$SUB_LINK"
            echoContent green "生成 Sing-box Hysteria2 订阅链接: $SUB_LINK"
        done <<< "$SINGBOX_HYSTERIA2"

        # TUIC subscriptions
        SINGBOX_TUIC=$(jq -r '.inbounds[] | select(.type=="tuic") | .tag as $tag | .users[] | "\($tag)#\(.uuid)#\(.password)#\(.name)#\(input_filename)"' "$SINGBOX_CONF")
        while IFS='#' read -r tag uuid password name filename; do
            port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag==$tag) | .listen_port' "$SINGBOX_CONF")
            if [[ "$port" == "null" || -z "$port" ]]; then
                continue
            fi
            SUB_LINK="tuic://${uuid}:${password}@${SUB_DOMAIN}:${port}?alpn=h3&congestion_control=bbr#${name}"
            echo "$SUB_LINK" >> "$SINGBOX_SUB_FILE"
            qrencode -o "${SUBSCRIBE_DIR}/tuic_${name//[@\/]/_}.png" "$SUB_LINK"
            echoContent green "生成 Sing-box TUIC 订阅链接: $SUB_LINK"
        done <<< "$SINGBOX_TUIC"

        # Naive subscriptions
        SINGBOX_NAIVE=$(jq -r '.inbounds[] | select(.type=="naive") | .tag as $tag | .users[] | "\($tag)#\(.username)#\(.password)#\(.name)#\(input_filename)"' "$SINGBOX_CONF")
        while IFS='#' read -r tag username password name filename; do
            port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag==$tag) | .listen_port' "$SINGBOX_CONF")
            if [[ "$port" == "null" || -z "$port" ]]; then
                continue
            fi
            SUB_LINK="naive+https://${username}:${password}@${SUB_DOMAIN}:${port}?insecure=0#${name}"
            echo "$SUB_LINK" >> "$SINGBOX_SUB_FILE"
            qrencode -o "${SUBSCRIBE_DIR}/naive_${name//[@\/]/_}.png" "$SUB_LINK"
            echoContent green "生成 Sing-box Naive 订阅链接: $SUB_LINK"
        done <<< "$SINGBOX_NAIVE"

        if [ -s "$SINGBOX_SUB_FILE" ]; then
            echo "$(cat "$SINGBOX_SUB_FILE" | base64 -w 0)" > "$SINGBOX_SUB_FILE"
            chown nobody:nogroup "$SINGBOX_SUB_FILE" "${SUBSCRIBE_DIR}/vless_*.png" "${SUBSCRIBE_DIR}/vmess_*.png" "${SUBSCRIBE_DIR}/trojan_*.png" "${SUBSCRIBE_DIR}/ss_*.png" "${SUBSCRIBE_DIR}/hysteria2_*.png" "${SUBSCRIBE_DIR}/tuic_*.png" "${SUBSCRIBE_DIR}/naive_*.png"
            chmod 644 "$SINGBOX_SUB_FILE" "${SUBSCRIBE_DIR}/vless_*.png" "${SUBSCRIBE_DIR}/vmess_*.png" "${SUBSCRIBE_DIR}/trojan_*.png" "${SUBSCRIBE_DIR}/ss_*.png" "${SUBSCRIBE_DIR}/hysteria2_*.png" "${SUBSCRIBE_DIR}/tuic_*.png" "${SUBSCRIBE_DIR}/naive_*.png"
            echoContent green "Sing-box 订阅已保存至 ${SINGBOX_SUB_FILE}，二维码已生成."
        else
            echoContent red "未生成任何 Sing-box 订阅链接."
        fi
    else
        echoContent red "Sing-box 配置文件 ${SINGBOX_CONF} 不存在."
    fi

    # Reload Nginx to apply changes
    if docker ps | grep -q nginx; then
        docker compose -f "$COMPOSE_FILE" restart nginx
        echoContent green "Nginx 已重启以应用订阅文件."
    fi

    echoContent green "订阅生成完成，可通过 http://${SUB_DOMAIN}/subscribe/ 访问."
}
# Manage logs
manageLogs() {
    echoContent skyBlue "\n日志管理菜单"
    echoContent yellow "1. 查看 Nginx 访问日志"
    echoContent yellow "2. 查看 Nginx 错误日志"
    echoContent yellow "3. 查看 Xray 日志"
    echoContent yellow "4. 查看 Sing-box 日志"
    echoContent yellow "5. 查看证书日志"
    echoContent yellow "6. 清除所有日志"
    echoContent yellow "7. 退出"
    read -r -p "请选择一个选项 [1-7]: " log_option

    case $log_option in
        1) tail -f "${NGINX_LOG_DIR}/access.log" ;;
        2) tail -f "${NGINX_LOG_DIR}/error.log" ;;
        3) tail -f "${XRAY_LOG_DIR}/access.log" ;;
        4) tail -f "${SINGBOX_LOG_DIR}/box.log" ;;
        5) tail -n 100 "${ACME_LOG}" ;;
        6)
            echo > "${NGINX_LOG_DIR}/access.log"
            echo > "${NGINX_LOG_DIR}/error.log"
            echo > "${XRAY_LOG_DIR}/access.log"
            echo > "${XRAY_LOG_DIR}/error.log"
            echo > "${SINGBOX_LOG_DIR}/box.log"
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
updateNSX() {
    echoContent skyBlue "\n进度 5/${TOTAL_PROGRESS} : 更新 NSX 脚本..."
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
    echoContent skyBlue "\n进度 4/${TOTAL_PROGRESS} : Docker 安装..."
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
          chmod 644 "$SINGBOX_CONF"
        fi
        if [[  -f "$COMPOSE_FILE" ]]; then
           cp ./sing-box/config.json "$SINGBOX_CONF"
           chmod 644 "$XRAY_CONF"
        fi       
    fi

    # Check certificates
    if [ ! -d "${CERT_DIR}" ] || [ -z "$(ls -A "${CERT_DIR}"/*.pem 2>/dev/null)" ]; then
        echoContent yellow "未找到证书，运行证书管理..."
        manageCertificates
    fi

    # Check Nginx configuration
    echoContent yellow "检查 Nginx 配置语法..."
    docker run --rm -v "${NGINX_CONF}:/etc/nginx/nginx.conf:ro" -v "${CERT_DIR}:/etc/nginx/certs:ro" -v "${NGINX_SHM_DIR}:/dev/shm/nsx" nginx:alpine nginx -t
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
    find "$NGINX_LOG_DIR" "$XRAY_LOG_DIR" "$SINGBOX_LOG_DIR" -type f -name "*.log" -exec chown nobody:nogroup {} \; -exec chmod 644 {} \;

    echoContent green "Docker 容器启动成功."

    # Check container status
    echoContent yellow "检查容器状态..."
    docker ps -f name=nginx-stream -f name=xray -f name=sing-box

    echoContent green "请使用systemctl enable ufw 和systemctl start ufw开启防火墙，用ufw allow port 开启端口访问..."
    aliasInstall
}
createSystemdServices() {
    echoContent skyBlue "\n配置 systemd 服务..."

    # Nginx 服务文件
    if [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        echoContent green "创建 Nginx systemd 服务..."
        cat <<EOF >/etc/systemd/system/nginx.service
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
ExecStart=/usr/sbin/nginx
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
ExecStart=/usr/local/nsx/sing-box/sing-box -c /usr/local/nsx/sing-box/config.json
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
    echoContent skyBlue "\n启动服务..."

    # 启用并启动服务
    systemctl enable nginx xray sing-box
    systemctl start nginx xray sing-box

    # 检查服务状态
    if systemctl is-active --quiet nginx && systemctl is-active --quiet xray && systemctl is-active --quiet sing-box; then
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
   
    echoContent skyBlue "\n进度 4/${TOTAL_PROGRESS} : 本地安装..."
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
    #!/bin/bash

# Custom echo function (assuming it's defined elsewhere)
echoContent() {
    local color=$1
    local message=$2
    case $color in
        skyBlue) echo -e "\033[1;36m$message\033[0m" ;;
        green) echo -e "\033[1;32m$message\033[0m" ;;
        red) echo -e "\033[1;31m$message\033[0m" ;;
    esac
}

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    release=$ID
else
    echoContent red "\n 错误: 无法检测操作系统类型!"
    exit 1
fi

echoContent skyBlue "\n 安装nginx..."
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
        echoContent skyBlue "\n nginx安装完成..."
        echoContent skyBlue "\n 拷贝配置文件到/etc/nginx..."
        sudo rm /etc/nginx/conf.d/default.conf
        sudo rm /etc/nginx/nginx.conf
        sudo cp /usr/local/nsx/nginx/nginx.conf /etc/nginx/nginx.conf
        sudo chmod 644 /etc/nginx/nginx.conf
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
        echoContent skyBlue "\n nginx安装完成..."
    else
        echoContent red "\n nginx安装失败!"
        exit 1
    fi
else
    echoContent red "\n 错误: 不支持的操作系统: ${release}"
    exit 1
fi


    # Install Xray and Sing-box
    echoContent skyBlue "\n 安装xray..."
   
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
        unzip -o "/usr/local/nsx/xray/${xrayCoreCPUVendor}.zip" -d /usr/local/nsx/xray >/dev/null
        rm -rf "/usr/local/nsx/xray/${xrayCoreCPUVendor}.zip"
        chmod 655 /usr/local/nsx/xray/xray
        echoContent skyBlue "安装xray成功..."
    fi
   
    
    echoContent skyBlue "安装singbox..."
   

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

        tar zxvf "/usr/local/nsx/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz" -C "/usr/local/nsx/sing-box/" >/dev/null 2>&1
        mv "/usr/local/nsx/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}/sing-box" /usr/local/nsx/sing-box
        rm -rf /usr/local/nsx/sing-box/sing-box-*
        chmod 655 /usr/local/nsx/sing-box/sing-box
        echoContent green "singbox安装成功"
    fi
    



    echoContent skyblue "本地安装成功，启动服务."
    # Start services
    createSystemdServices
    startServices
    

    
    echoContent yellpw "请使用systemctl enable ufw 和systemctl start ufw开启防火墙，用ufw allow port 开启端口访问..."
    aliasInstall
}

# Stop NSX
stopNSX() {
    echoContent skyBlue "停止 NSX 容器并清理..."
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
    if [ -d "$NGINX_SHM_DIR" ] && [ -z "$(ls -A "$NGINX_SHM_DIR")" ]; then
        echoContent yellow "目录 $NGINX_SHM_DIR 为空，删除..."
        if ! rm -rf "$NGINX_SHM_DIR"; then
                echoContent red "无法删除 $NGINX_SHM_DIR，请检查权限."
                exit 1
         fi
    elif [ -d "$NGINX_SHM_DIR" ]; then
        echoContent yellow "清理 $NGINX_SHM_DIR 中的文件..."
        if ! rm -rf "$NGINX_SHM_DIR"/*; then
                echoContent red "无法清理 $NGINX_SHM_DIR 中的文件，请检查权限."
                exit 1
        fi
    fi

    echoContent green "NSX 容器已停止并清理完成."
}

uninstallNSX() {
    # Define defaults
 

    echoContent skyBlue "卸载 NSX 服务..."

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
    echoContent yellow "10. 退出"
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