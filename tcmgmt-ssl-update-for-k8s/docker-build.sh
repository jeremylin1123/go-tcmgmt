#!/bin/bash
set -e

# 🏷 Image 名稱
IMAGE_NAME="stg-reg.star-link-oa.com/devops-k8s-morning-jobs/tcmgmt-ssl-update"
TAG="3"
PLATFORMS="linux/amd64,linux/arm64"

# 1️⃣ 確保 buildx builder 存在或使用已存在
if ! docker buildx inspect multiarch-builder >/dev/null 2>&1; then
    echo "🛠 建立 buildx builder..."
    docker buildx create --use --name multiarch-builder
else
    echo "✅ 使用已存在 buildx builder"
    docker buildx use multiarch-builder
fi

# 2️⃣ 確保 docker-entrypoint.sh 換行符是 LF
echo "🔧 轉換腳本換行符為 LF..."
sed -i '' 's/\r$//' docker-entrypoint.sh

# 3️⃣ Build multi-arch image 並直接推到 Harbor
echo "🚀 建構 multi-arch image 並推到 Harbor..."
docker buildx build \
    --platform $PLATFORMS \
    -t ${IMAGE_NAME}:${TAG} \
    --push \
    .
