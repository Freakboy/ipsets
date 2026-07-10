# Changelog

[中文更新日志](CHANGELOG.zh-CN.md)

All notable changes to IPSets are documented here.

## [0.3.0] - 2026-07-10

### Added

- Add one-click Cloudflare proxy IP synchronization from the official IPv4 and IPv6 lists.
- Track Cloudflare-managed whitelist entries with `source: "cloudflare"` so future syncs can remove stale Cloudflare ranges without touching manual entries.
- Show Cloudflare sync progress and add/update/remove counts in the web UI.

## [0.2.0] - 2026-07-10

### Added

- Support manual whitelist entries in CIDR notation, including IPv4 and IPv6 ranges.
- Canonicalize CIDR entries before saving, for example `203.0.113.42/24` becomes `203.0.113.0/24`.
- Generate nftables interval sets so CIDR entries can be applied correctly.
- Remove entries already covered by a broader CIDR when generating nftables rules to avoid conflicting interval errors.

### Changed

- Normalize protected port input after saving.
- Sort protected ports in ascending order.
- Compact consecutive ports into ranges, for example `8082,8008,8080-8081` becomes `8008,8080-8082`.
- Update UI copy, example config, and documentation for CIDR whitelist support.

## [0.1.0] - 2026-07-02

### Added

- Initial Linux web UI for IP whitelist management.
- Username and password login with an HttpOnly session cookie.
- One-click add current visitor IP.
- Manual whitelist entries with editable notes.
- Editable protected TCP port list with range syntax.
- Persistent JSON configuration and whitelist storage.
- Persistent firewall state display for applied, pending, restored, and error states.
- nftables backend using an isolated `inet ipsets` table.
- One-click restore by deleting the IPSets nftables table.
- Docker published-port aware protection through an early `prerouting` chain.
- Reverse-proxy-aware current IP detection.
- English and Chinese README files.
