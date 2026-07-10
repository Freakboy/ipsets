# 更新日志

[English changelog](CHANGELOG.md)

这里记录 IPSets 的重要版本变更。

## [0.3.0] - 2026-07-10

### 新增

- 支持一键从 Cloudflare 官方 IPv4 和 IPv6 列表同步代理 IP 网段。
- 使用 `source: "cloudflare"` 标记由 Cloudflare 同步管理的白名单条目，后续同步可以移除过期 Cloudflare 网段且不影响手动条目。
- Web UI 显示 Cloudflare 同步进度，以及新增、更新、移除数量。

## [0.2.0] - 2026-07-10

### 新增

- 手动白名单支持 CIDR 格式，包括 IPv4 和 IPv6 网段。
- 保存前规范化 CIDR，例如 `203.0.113.42/24` 会保存为 `203.0.113.0/24`。
- 生成 nftables interval set，使 CIDR 白名单可以正确应用。
- 生成 nftables 规则时自动移除已被更大 CIDR 覆盖的条目，避免 nftables 报 `conflicting intervals`。

### 变更

- 保存受保护端口后自动规范化输入。
- 端口按升序排序。
- 连续端口会折叠为范围，例如 `8082,8008,8080-8081` 会保存为 `8008,8080-8082`。
- 更新 UI 文案、示例配置和文档，说明 CIDR 白名单支持。

## [0.1.0] - 2026-07-02

### 新增

- 初始 Linux IP 白名单 Web UI。
- 用户名密码登录，并使用 HttpOnly 会话 Cookie。
- 一键添加当前访问 IP。
- 手动添加白名单条目并支持备注编辑。
- 可编辑受保护 TCP 端口列表，支持范围语法。
- 配置和白名单持久化到 JSON 文件。
- 持久化显示防火墙状态，包括已应用、待应用、已恢复和异常。
- 使用独立的 `inet ipsets` nftables 表作为防火墙后端。
- 一键恢复，通过删除 IPSets 创建的 nftables 表实现。
- 通过早期 `prerouting` 链兼容 Docker 发布端口保护。
- 支持反向代理后的当前访问 IP 识别。
- 英文和中文 README 文档。
