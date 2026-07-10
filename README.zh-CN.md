# IPSets

[English](README.md)

[更新日志](CHANGELOG.zh-CN.md)

**IPSets** 是一个部署在 Linux 服务器上的 IP 白名单 Web UI。它把配置、白名单、备注和防火墙状态保存到同一个 JSON 配置文件中，并通过独立的 nftables 表对指定 TCP 端口进行访问控制。

## 它解决什么问题

IPSets 面向简单的运维场景：

1. 打开 Web UI。
2. 一键添加当前访问 IP，或手动添加 IP 地址/CIDR 网段。
3. 给 IP 添加备注，方便后续识别。
4. 配置要保护的 TCP 端口，例如 `22,8008,8080-8090`。
5. 点击 **应用规则**。

页面顶部会一直显示规则是否正在生效、是否有待应用的修改，以及最近一次应用或恢复是否失败。

## 功能

- 用户名和密码登录。
- 一键添加当前访问 IP。
- 手动添加 IP 或 CIDR 白名单。
- 白名单备注可编辑。
- 受保护端口列表可编辑，支持范围语法。
- 配置和白名单持久化到 JSON 文件。
- 防火墙操作状态持久化：`applied`、`pending`、`restored`、`error`。
- 使用独立的 `inet ipsets` nftables 表。
- 一键恢复，只删除 IPSets 创建的表。
- 通过早期 `prerouting` 链兼容常见 Docker 端口发布。
- 支持反向代理后的客户端 IP 识别。
- 支持 IPv4 和 IPv6 白名单。

IPSets 支持单个 IP 地址和 CIDR 网段，例如 `203.0.113.42` 或 `203.0.113.0/24`。

## 系统要求

- Linux 服务器。
- 服务器上可用 `nft` 命令。
- 具备管理 nftables 的权限，通常需要 root 或等效的 `CAP_NET_ADMIN` 能力。
- 如果从源码构建，需要与 [go.mod](go.mod) 兼容的 Go 版本。

Web UI 可以从任意现代系统浏览器访问。只有运行 IPSets 的服务器需要 Linux 和 nftables。

## 快速开始

在仓库目录运行：

```bash
go run ./cmd/ipsets
```

首次启动会创建 `./config.json`，并在终端打印一次性生成的管理员密码：

```text
created config at config.json
initial admin login: username=admin password=<generated-password>
```

打开：

```text
http://服务器IP:8008/login
```

使用用户名 `admin` 和生成的密码登录。

生产环境应用规则前，先把当前管理 IP 加入白名单，并确认受保护端口列表无误。

## 构建

```bash
go build -o ipsets ./cmd/ipsets
```

生成的 `ipsets` 二进制已被 Git 忽略。

## 配置

IPSets 默认读取 `config.json`。可以用 `IPSETS_CONFIG_FILE` 指定其他路径。

环境变量会覆盖配置文件里的同名配置：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `IPSETS_LISTEN` | `:8008` | Web UI 监听地址。 |
| `IPSETS_DATA_DIR` | `./data` | 运行数据目录，用于保存第一次应用前的 ruleset 备份。 |
| `IPSETS_CONFIG_FILE` | `config.json` | 配置和白名单 JSON 文件路径。 |
| `IPSETS_TABLE` | `ipsets` | nftables 表名。 |
| `IPSETS_PROTECTED_PORTS` | `22` | 受保护 TCP 端口，支持逗号列表和范围。 |
| `IPSETS_TRUST_PROXY` | `false` | 是否信任非本机反向代理传来的客户端 IP 头，使用 `1` 或 `true` 开启。 |

旧的 `IPGUARD_*` 环境变量仍可作为兼容别名读取。

示例：

```bash
IPSETS_LISTEN=:8008 \
IPSETS_CONFIG_FILE=/etc/ipsets/config.json \
IPSETS_DATA_DIR=/var/lib/ipsets \
IPSETS_PROTECTED_PORTS=22,8008,8080-8090 \
go run ./cmd/ipsets
```

## 配置文件格式

仓库提供了可复制的 [config.example.json](config.example.json)。

手动指定初始密码的最小配置：

```json
{
  "listenAddr": ":8008",
  "tableName": "ipsets",
  "protectedPorts": "22,8008",
  "trustProxy": false,
  "admin": {
    "username": "admin",
    "password": "change-me-now"
  },
  "whitelist": []
}
```

IPSets 启动时如果发现 `admin.password`，会使用 PBKDF2-SHA256 生成哈希，写回 `passwordHash`、`passwordSalt` 和 `passwordIterations`，然后删除明文 `password` 字段。

运行后的配置可能类似：

```json
{
  "listenAddr": ":8008",
  "tableName": "ipsets",
  "protectedPorts": "22,8008,8080-8090",
  "trustProxy": false,
  "admin": {
    "username": "admin",
    "passwordHash": "...",
    "passwordSalt": "...",
    "passwordIterations": 210000
  },
  "firewallState": {
    "status": "pending",
    "message": "配置已修改，需要重新应用规则",
    "updatedAt": "2026-01-01T00:00:00Z"
  },
  "whitelist": [
    {
      "id": "203.0.113.42",
      "ip": "203.0.113.42",
      "note": "example office IP",
      "createdAt": "2026-01-01T00:00:00Z",
      "updatedAt": "2026-01-01T00:00:00Z"
    }
  ]
}
```

不要提交真实的 `config.json`。它可能包含密码哈希、真实 IP 和备注信息。仓库默认已经忽略该文件。

## 端口语法

使用逗号分隔：

```text
22,8008,8080-8090
```

规则：

- 合法端口范围是 `1` 到 `65535`。
- 范围包含起止端口。
- 重复端口会去重。
- 保存后的端口会自动按升序规范化，并尽量折叠为连续范围。
- 至少需要一个端口。
- 不支持 Docker 的 `8080:80` 语法。Docker 发布端口应填写宿主机端口，例如 `8080`。

## 防火墙行为

应用规则后，IPSets 会创建独立的 nftables 表：

```text
table inet ipsets
```

表中包含：

- `whitelist_v4` 和 `whitelist_v6` 集合。
- 优先级为 `-101` 的早期 `prerouting` 链。
- 用于普通主机流量的 `input` 链。

实际效果：

- 白名单 IP 可以访问受保护 TCP 端口。
- 非白名单 IP 只会在访问受保护 TCP 端口时被丢弃。
- 本机 loopback 流量会被放行。
- `input` 链中会放行已建立和相关连接。
- 不会重写系统中其他防火墙表。
- **恢复原始状态** 只会删除 `inet ipsets` 表。

第一次应用规则前，IPSets 会把当前 nftables ruleset 保存到：

```text
<data-dir>/original-ruleset.nft
```

这个文件用于人工审计和恢复参考。恢复按钮不会回放该文件，只会删除 IPSets 创建的表。

## Docker 发布端口

对于 Docker 映射：

```text
8080:80
```

应保护宿主机端口：

```text
8080
```

IPSets 包含早期 `prerouting` 规则，常见 Docker DNAT 处理之前即可完成宿主机端口保护。

## 反向代理和客户端 IP 识别

IPSets 按以下规则识别当前访问 IP：

1. 直连访问使用 TCP 连接来源地址。
2. 如果请求来自本机反向代理，例如 `127.0.0.1` 上的 Caddy 或 Nginx，会自动信任代理头。
3. 如果请求来自非本机反向代理，需要设置 `trustProxy: true` 或 `IPSETS_TRUST_PROXY=1`。
4. 支持的请求头包括 `Forwarded`、`X-Forwarded-For`、`X-Real-IP` 和 `CF-Connecting-IP`。

只有在反向代理可信时才开启 `trustProxy`，否则客户端可以伪造来源 IP 头。

## Caddy 示例

常见部署方式是让 IPSets 只监听本机，由 Caddy 对外提供 HTTPS：

```caddyfile
ipsets.example.com {
    reverse_proxy 127.0.0.1:8008
}
```

这种架构下：

- 尽量让 IPSets 只绑定或只暴露到 localhost。
- 如果想在防火墙层限制来源 IP，应保护公网入口端口，通常是 `80` 和 `443`。
- 如果只保护 `8008`，而 Caddy 转发到 `127.0.0.1:8008`，防火墙看到的后端连接来源会是 Caddy 本机。

对于 Cloudflare 橙云代理域名，服务器防火墙层看到的是 Cloudflare IP。保护源站时，应只允许 Cloudflare IP 段访问 Caddy，并阻止非 Cloudflare 直连。若需要按真实用户 IP 控制访问，建议使用 Cloudflare Access/WAF，或在已经阻止源站直连的前提下，在应用层信任 Cloudflare 头。

对于 DNS-only 域名，服务器能看到真实客户端 IP，因此可以在防火墙层使用 IPSets 白名单。代价是源站 IP 会暴露。

## UI 状态模型

页面顶部会显示醒目的规则状态条：

| 状态 | 含义 |
| --- | --- |
| `applied` | 配置记录显示已应用，并且检测到 nftables 表。 |
| `pending` | 端口、白名单或备注已修改，需要点击 **应用规则**。 |
| `restored` | 已通过恢复操作删除 IPSets 规则。 |
| `error` | 应用、恢复或状态校验失败，需要查看提示并重试。 |

每次刷新页面都会调用状态 API。如果配置记录显示规则已应用，但实际 nftables 表不存在，IPSets 会记录异常，避免 UI 显示过期的成功状态。

## 安全建议

- 通过网络访问 UI 时应放在 HTTPS 后面。
- 不要在没有强密码和网络限制的情况下公开暴露 UI。
- 保护好 `config.json`。
- 应用规则前先加入当前管理 IP。
- 只有确认自己仍能访问服务后，再把 UI 访问端口加入受保护端口。
- 如果使用 Cloudflare，记住防火墙层看到的是 Cloudflare IP，不是真实用户 IP。
- 反向代理部署时，优先让 IPSets 监听本机，由 Caddy/Nginx 对外暴露。

## 排错

### 登录后当前 IP 显示为 `127.0.0.1`

说明 UI 在本机反向代理后面，但代理没有传递客户端 IP 头。请配置代理转发真实 IP。

Caddy 通常会自动维护 `X-Forwarded-For`。Nginx 示例：

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

### 应用规则时报 `nft apply failed`

检查：

- 进程能否执行 `nft`。
- 进程是否有管理 nftables 的权限。
- 受保护端口列表是否只包含合法端口或范围。
- 白名单是否都是合法的 IP 地址或 CIDR 网段。

### 新增端口没有生效

编辑端口后需要点击 **应用规则**。保存端口只会写入配置并把状态标记为 `pending`，不会立即修改 nftables。

### 应用规则后 UI 无法访问

通过服务器控制台检查或删除表：

```bash
nft list table inet ipsets
nft delete table inet ipsets
```

然后加入当前 IP、检查受保护端口，再重新应用。

### Docker 服务仍然能访问

确认保护的是宿主机端口，而不是容器端口。对于 `8080:80`，应保护 `8080`。

## 开发

运行测试：

```bash
go test ./...
```

构建：

```bash
go build -o ipsets ./cmd/ipsets
```

常见本地忽略文件：

- `config.json`
- `data/`
- `ipsets`
- `.env*`
- `.sd/`
- `.superpowers/`
