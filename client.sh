#!/bin/bash

# 目标文件夹
DEST_DIR="/media/pi/usb/xray/confdir"
XRAY_CONF="/media/pi/usb/xray/config.json"
mkdir -p "$DEST_DIR"
rm -rf $DEST_DIR/*.*
# GitHub 仓库信息
REPO_USER="judawu"
REPO_NAME="nsx"
BRANCH="main"
FOLDER_PATH="xray/client"

# GitHub API 获取文件列表
API_URL="https://api.github.com/repos/$REPO_USER/$REPO_NAME/contents/$FOLDER_PATH?ref=$BRANCH"

# 查询文件列表并下载
curl -s "$API_URL" | \
jq -r '.[] | select(.type=="file") | .name' | \
while read filename; do
    FILE_URL="https://raw.githubusercontent.com/$REPO_USER/$REPO_NAME/$BRANCH/$FOLDER_PATH/$filename"
    echo "Downloading $filename ..."
    wget -q -P "$DEST_DIR" "$FILE_URL"
done

echo "All files downloaded to $DEST_DIR"
echo "开始进行合并到config.json"

if ! xray run -confdir="$DEST_DIR" -dump > "$XRAY_CONF"; then
            echo "生成 Xray 配置失败"
           
fi
echo "删除所有 streamSettings 中的 port，这是由于 xray run -confdir 不当合并导入的"
     

TMP_CONF="${XRAY_CONF}.tmp"
        
jq 'walk(
              if type == "object" 
                 and has("streamSettings") 
                 and (.streamSettings | type == "object") 
                 and (.streamSettings | has("port"))
              then 
                 .streamSettings |= del(.port)
              else 
                 .
              end
            )' "$XRAY_CONF" > "$TMP_CONF"
 if [ $? -ne 0 ]; then
            echo "错误: jq 删除 port 失败，无法更新 $XRAY_CONF"
            exit 1
fi
        
mv "$TMP_CONF" "$XRAY_CONF" || {
            echo "错误: 无法覆盖 $XRAY_CONF"
            exit 1
}
        
echo "h合并的文件位于/media/pi/usb/xray/config.json，建议进入/media/pi/usb/xray/confdir手动修改所有outbounds的配置"

echo "然后执行xray run -confdir"
