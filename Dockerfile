### nas-auth multi-stage build
###  - builder: .NET 10 SDK
###  - runtime: aspnet:10.0（轻量，无 SDK）

ARG REVISION=unknown
# image.source label；CI 会用 labels 覆盖成实际构建的仓库地址
ARG SOURCE_URL=https://github.com/ZhengchenTao/nas-auth

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS builder
WORKDIR /src

# 先拷 csproj 触发 restore，再拷源码 → 利用 layer 缓存
# restore 必须传 --runtime 让 assets.json 包含 linux-x64 target，
# 否则下面 publish --runtime linux-x64 --no-restore 会 NETSDK1047
COPY nas-auth.csproj ./
RUN --mount=type=cache,target=/root/.nuget/packages,sharing=locked \
    dotnet restore nas-auth.csproj --runtime linux-x64

COPY . .
RUN --mount=type=cache,target=/root/.nuget/packages,sharing=locked \
    dotnet publish nas-auth.csproj \
    -c Release \
    -o /out \
    --runtime linux-x64 \
    --self-contained false \
    --no-restore \
    /p:PublishReadyToRun=false \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
ARG REVISION
ARG SOURCE_URL
WORKDIR /app

# 非 root 用户运行（最小权限）。SQLite 数据目录 / app 目录都 chown 给 appuser。
# /app/data 是 compose 挂载点，宿主权限由 docker-compose 保证。
RUN useradd --system --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app
COPY --from=builder --chown=appuser:appuser /out /app/
USER appuser

EXPOSE 8080
ENV ASPNETCORE_URLS=http://0.0.0.0:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_NOLOGO=true

LABEL org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.title="nas-auth" \
      org.opencontainers.image.description="OAuth 2.1 / OIDC / DCR authorization server for self-hosted services"

ENTRYPOINT ["dotnet", "nas-auth.dll"]
