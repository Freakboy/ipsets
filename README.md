# IPSets

**IPSets** is a small Linux web UI for managing an IP whitelist around selected TCP ports. It stores configuration, whitelist entries, notes, and firewall state in a JSON config file, then applies the effective access policy through an isolated nftables table.

[中文说明](README.zh-CN.md)

[Changelog](CHANGELOG.md)

## What It Does

IPSets is designed for a simple operations workflow:

1. Open the web UI.
2. Add your current public IP, or manually add an IP address or CIDR range.
3. Add or edit notes so the whitelist stays understandable.
4. Configure the protected TCP ports, such as `22,8008,8080-8090`.
5. Click **Apply rules**.

The dashboard always shows whether rules are currently active, whether local changes are pending, and whether the last apply or restore operation failed.

## Features

- Web UI with username and password login.
- One-click add current visitor IP.
- Manual IP or CIDR whitelist entries.
- One-click Cloudflare proxy IP range synchronization.
- Editable notes for whitelist entries.
- Editable protected port list with range syntax.
- Persistent configuration and whitelist storage in one JSON file.
- Persistent firewall operation state: `applied`, `pending`, `restored`, or `error`.
- nftables backend using a dedicated `inet ipsets` table.
- One-click restore that removes only the table created by IPSets.
- Docker published-port friendly rules through an early `prerouting` chain.
- Reverse-proxy-aware client IP detection.
- IPv4 and IPv6 whitelist support.

IPSets supports individual IP addresses and CIDR ranges, such as `203.0.113.42` or `203.0.113.0/24`.

## Requirements

- Linux server.
- `nft` command available on the server.
- Permission to manage nftables, usually by running as root or with equivalent `CAP_NET_ADMIN` capability.
- Go version compatible with [go.mod](go.mod) if building from source.

The web UI can be opened from any modern operating system browser. Only the server running IPSets needs Linux and nftables.

## Quick Start

Run from the repository:

```bash
go run ./cmd/ipsets
```

On the first start, IPSets creates `./config.json` and prints a one-time generated admin password:

```text
created config at config.json
initial admin login: username=admin password=<generated-password>
```

Open:

```text
http://SERVER_IP:8008/login
```

Log in as `admin` with the generated password.

Before applying rules in production, add your current IP to the whitelist and verify the protected port list.

## Build

```bash
go build -o ipsets ./cmd/ipsets
```

The generated `ipsets` binary is ignored by Git.

## Configuration

IPSets reads configuration from `config.json` by default. Use `IPSETS_CONFIG_FILE` to point to another path.

Environment variables override matching config-file values:

| Variable | Default | Description |
| --- | --- | --- |
| `IPSETS_LISTEN` | `:8008` | Web UI listen address. |
| `IPSETS_DATA_DIR` | `./data` | Runtime data directory. Used for the first ruleset backup. |
| `IPSETS_CONFIG_FILE` | `config.json` | Config and whitelist JSON file. |
| `IPSETS_TABLE` | `ipsets` | nftables table name. |
| `IPSETS_PROTECTED_PORTS` | `22` | Protected TCP ports. Supports comma lists and ranges. |
| `IPSETS_TRUST_PROXY` | `false` | Trust proxy headers from non-loopback reverse proxies. Use `1` or `true`. |

Legacy `IPGUARD_*` environment variable names are still accepted as compatibility aliases.

Example:

```bash
IPSETS_LISTEN=:8008 \
IPSETS_CONFIG_FILE=/etc/ipsets/config.json \
IPSETS_DATA_DIR=/var/lib/ipsets \
IPSETS_PROTECTED_PORTS=22,8008,8080-8090 \
go run ./cmd/ipsets
```

## Config File Format

See [config.example.json](config.example.json) for a copyable example.

Minimal first-run config with a manually chosen password:

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

When IPSets starts and sees `admin.password`, it hashes the password with PBKDF2-SHA256, writes `passwordHash`, `passwordSalt`, and `passwordIterations`, then removes the plaintext `password` field.

The runtime config may look like this:

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
    "message": "Configuration changed. Apply rules again.",
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

Do not commit your real `config.json`. It may contain password hashes, IP addresses, and notes. The repository ignores it by default.

## Port Syntax

Use a comma-separated list:

```text
22,8008,8080-8090
```

Rules:

- Valid ports are `1` through `65535`.
- Ranges are inclusive.
- Duplicates are removed.
- Saved ports are normalized into ascending order and compact ranges.
- At least one port is required.
- Docker syntax like `8080:80` is not accepted. For Docker published ports, configure the host port, for example `8080`.

## Firewall Behavior

When rules are applied, IPSets creates a dedicated nftables table:

```text
table inet ipsets
```

The table contains:

- `whitelist_v4` and `whitelist_v6` sets.
- An early `prerouting` chain with priority `-101`.
- An `input` chain for normal host traffic.

The effective behavior is:

- Whitelisted IPs can access protected TCP ports.
- Non-whitelisted IPs are dropped only for protected TCP ports.
- Loopback traffic is accepted.
- Existing and related connections are accepted in the input chain.
- Other system firewall tables are not rewritten.
- **Restore original state** deletes only the `inet ipsets` table.

Before the first apply, IPSets saves the current nftables ruleset to:

```text
<data-dir>/original-ruleset.nft
```

This backup is for manual audit and recovery. The restore button does not replay that file; it removes the IPSets table.

## Docker Published Ports

For Docker mappings such as:

```text
8080:80
```

protect the host port:

```text
8080
```

IPSets includes an early `prerouting` rule so host-level port protection works before common Docker DNAT handling.

## Reverse Proxies and Client IP Detection

IPSets detects the current visitor IP as follows:

1. Direct access uses the TCP remote address.
2. Requests from a loopback proxy, such as Caddy or Nginx on `127.0.0.1`, automatically trust proxy headers.
3. Requests from a non-loopback proxy require `trustProxy: true` or `IPSETS_TRUST_PROXY=1`.
4. Supported headers are `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, and `CF-Connecting-IP`.

Only enable `trustProxy` when the proxy is trusted. Otherwise clients may spoof headers.

## Caddy Example

A common deployment is to keep IPSets on localhost and expose it through Caddy:

```caddyfile
ipsets.example.com {
    reverse_proxy 127.0.0.1:8008
}
```

In this setup:

- Bind or expose IPSets only to localhost if possible.
- Protect the public entry ports, usually `80` and `443`, when you want firewall-level source IP control.
- If you protect only `8008` while Caddy proxies to `127.0.0.1:8008`, the firewall sees Caddy as the source for the backend connection.

For Cloudflare proxied DNS records, your server sees Cloudflare IPs at the firewall layer. To protect the origin, allow Cloudflare IP ranges to reach Caddy and block direct non-Cloudflare traffic. For real end-user IP restrictions behind Cloudflare, use Cloudflare Access/WAF or an application-layer check that trusts Cloudflare headers only after the origin is protected from direct access.

The web UI can sync Cloudflare proxy IP ranges from the official `https://www.cloudflare.com/ips-v4/` and `https://www.cloudflare.com/ips-v6/` lists. Synced entries are marked with `source: "cloudflare"` so the next sync can remove stale Cloudflare ranges without deleting manually managed entries.

For DNS-only records, the server sees the real client IP, so IPSets can whitelist the client IP at the firewall layer. The trade-off is that DNS-only records expose the origin IP.

## UI State Model

The dashboard shows a prominent rule status banner:

| State | Meaning |
| --- | --- |
| `applied` | The config record says rules were applied and the nftables table is detected. |
| `pending` | Ports, whitelist entries, or notes changed. Click **Apply rules**. |
| `restored` | IPSets rules were removed by the restore action. |
| `error` | Apply, restore, or state reconciliation failed. Read the message and retry. |

Every page refresh calls the status API. If the config says rules are applied but the nftables table is missing, IPSets records an error so the UI does not show a stale success state.

## Security Notes

- Run the UI behind HTTPS when used over a network.
- Do not expose the UI publicly without a strong password and network controls.
- Keep `config.json` private.
- Add your current management IP before applying rules.
- Include the UI access port in protected ports only after confirming you can still reach the service.
- If you are behind Cloudflare, remember that firewall-level source IP checks see Cloudflare IPs, not the end-user IP.
- For reverse-proxy deployments, prefer binding IPSets to localhost and exposing only Caddy/Nginx.

## Troubleshooting

### Login works, but the current IP is `127.0.0.1`

The UI is behind a local reverse proxy but proxy headers are missing. Configure the proxy to forward the client IP.

Caddy usually forwards `X-Forwarded-For` automatically. For Nginx:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

### Applying rules fails with `nft apply failed`

Check:

- The process can run `nft`.
- The process has permission to manage nftables.
- The protected port list contains only valid ports or ranges.
- Whitelist entries are valid IP addresses or CIDR ranges.

### A new port does not seem protected

After editing ports, click **Apply rules**. Saving the port list writes the config and marks the state as `pending`; it does not change nftables until apply succeeds.

### The UI becomes unreachable after applying rules

Use server console access to inspect or remove the table:

```bash
nft list table inet ipsets
nft delete table inet ipsets
```

Then add your current IP, review protected ports, and apply again.

### Docker service is still reachable

Make sure you protected the host port, not the container port. For `8080:80`, protect `8080`.

## Development

Run tests:

```bash
go test ./...
```

Build:

```bash
go build -o ipsets ./cmd/ipsets
```

Useful ignored local files:

- `config.json`
- `data/`
- `ipsets`
- `.env*`
- `.sd/`
- `.superpowers/`
