# One core image, multiple deployments

Household and team installations use the same nas-auth source and the same built image.
Keep instance settings, resource/client files, branding, credentials and persistent data
outside the image. Private protocol adapters remain separately versioned services; never
patch or rebuild Auth to install an instance configuration.

## Release gates

- Docker builds run the complete .NET suite, including `DeploymentScenarioTests` for
  root-path household and path-mounted team configurations. Team checks enable a synthetic
  ticket provider, profile schema and an in-memory account-sync adapter. No real directory
  or company credentials are used.
- Both CI systems boot the built runtime image twice with isolated synthetic configuration.
  They check health, discovery, login rendering, administrator-route protection and mounted
  ticket-provider routing. These checks complement, not replace, actual provider sign-in.
- Gitea publishes only after runtime checks. The build summary records the immutable
  `registry/owner/nas-auth@sha256:…` reference. A full-source-SHA tag is also published,
  but **use the digest**: rerunning a commit can rebuild against updated base images.
- Offline transport is exercised before publishing the convenience tags. GitHub CI builds
  and checks an image; it does not independently publish a competing release artifact.

## Online deployment

Set the deployment's Compose `image` to the release digest and recreate only Auth.
The optional Gitea deploy action reconciles the version in the deployment repository;
update that repository first. It does not override a pinned digest with the new build.
Do not use a local `build:` or a floating `latest` reference as the release authority.
Keep UID/file permissions, settings mounts, bootstrap credential injection, issuer,
database and signing/cookie keys unchanged. Verify compatibility with [operations](operations.md)
before switching; the image version does not supersede migration/rollback constraints.

## Offline deployment

On a machine with registry access and Docker, from a trusted source checkout:

```sh
python3 .github/scripts/image-bundle.py export \
  --image registry.example.com/owner/nas-auth@sha256:<release-digest> \
  --output /path/to/new-release-directory
```

Transfer `nas-auth.image.tar.gz` and `manifest.json` through your trusted deployment channel.
The manifest records the registry digest, image configuration digest, source engine image ID,
full source revision and archive SHA-256.
On the destination, with the same trusted helper:

```sh
python3 .github/scripts/image-bundle.py verify /path/to/release/manifest.json
python3 .github/scripts/image-bundle.py import /path/to/release/manifest.json
```

Import checks the archive before loading and the configuration digest/revision before tagging. It prints
`deployment_image`, a `local/nas-auth:<full-revision>` reference for Compose. Keep the manifest
and verify the running image ID matches `loaded_image_id` after recreation. Classic Docker and
containerd image stores can report different IDs for the same image; the configuration digest
is verified by saving the loaded image again. Import does not restart services.
Checksums detect corruption; they are not signatures or proof of provenance. Trust the source
and transport of both files. For rollback retain the previous image, manifest and compatible
configuration; do not restore an old live database merely to roll back presentation code.

## 中文

NAS 与团队实例共用一次构建的核心镜像，部署端只维护版本、配置和必要的私有适配器。
上游 CI 同时检查家庭根路径与团队子路径场景；团队测试使用模拟身份提供方和同步接收器，
不引入公司协议或实际凭据。

在线部署锁定构建摘要中的镜像 digest。离线部署导出这个 digest，传输归档与清单，
导入时核对归档哈希、镜像配置摘要、源码 revision，再修改 Compose 的 `image`。
不同 Docker 存储后端可能报告不同镜像 ID；以清单里的配置摘要确认制品相同，
运行容器 ID 则与导入回执的 `loaded_image_id` 对照。
不要在目标服务器重新编译 Auth。保留原有数据、密钥、配置挂载和凭据注入入口，
按既有备份/恢复规范验收。通用测试不替代私有适配器和真实应用 SSO 的验收。
