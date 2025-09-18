# -------- Build 階段 --------
FROM golang:1.25-alpine AS builder

WORKDIR /app

# 先放 go.mod / go.sum，有快取效果
COPY go.mod go.sum ./
RUN go mod download

# 再放程式碼
COPY . .

# 編譯 Go 程式
RUN go build -o domain-ssl .

# -------- Runtime 階段 --------
FROM alpine:3.20
WORKDIR /app

# 安裝必要工具
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    openssl \
    bash \
    jq \
    vim \
    && rm -rf /var/cache/apk/*

# 複製執行檔與設定
COPY --from=builder /app/domain-ssl /app/
COPY decrypt /app/
COPY env.json /app/

# 給 decrypt 執行權限
RUN chmod +x /app/decrypt

# 設定時區
ENV TZ=Asia/Taipei

# 容器啟動直接執行主程式，並在完成後等待一分鐘
ENTRYPOINT ["/bin/bash", "-c", "/app/domain-ssl && echo '任務完成，將在 60 秒後退出...' && sleep 60"]
