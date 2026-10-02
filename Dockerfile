# movieclaw-push 镜像。官方中继和自建用户用的是同一个镜像。
#
#   docker build -t movieclaw-push .
#   docker run -v $PWD/config.yaml:/etc/movieclaw-push/config.yaml \
#              -v $PWD/AuthKey_XXXX.p8:/etc/movieclaw-push/AuthKey_XXXX.p8 \
#              -v movieclaw-push-data:/data -p 8080:8080 movieclaw-push
#
# 管理命令：docker exec <容器> movieclaw-push token create --name 客厅服务器

# 在构建机的原生架构上交叉编译，多架构镜像不用 QEMU 模拟
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS TARGETARCH
# SQLite 用纯 Go 实现，不需要 CGO，产物是静态二进制
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/movieclaw-push ./cmd/movieclaw-push \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/movieclaw-push /usr/local/bin/movieclaw-push
# 镜像以非 root 用户运行，数据目录要预先建好并归它所有，挂载的卷才可写
COPY --from=build --chown=65532:65532 /out/data /data
ENV MOVIECLAW_PUSH_CONFIG=/etc/movieclaw-push/config.yaml
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/movieclaw-push"]
CMD ["serve"]
