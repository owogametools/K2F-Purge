# Privacy

K2F PURGE performs all analysis on the local machine. It has no network calls, no telemetry, and no crash reporting. No scan result, report, path, or file is uploaded anywhere.

## Network

The application does not import or call `net/http`, `net.Dial`, `net.Listen`, or any HTTP/TLS client. The `net` package is used only for `net.ParseIP` when validating the two blocked IP addresses. There is no updater and no remote rules fetch. Detection rules are compiled into the binary from `internal/ioc/rules.json`; a local JSON overlay can be loaded from disk with `internal/ioc.LoadFile`, and it is never sent anywhere.

## What is read

- **SCAN** reads launcher logs, cache files, LevelDB/local-storage files, code-cache files, temp artifacts, and candidate files under known launcher and Wine/Proton roots. It opens files only inside those scopes and only up to the configured size cap. Matching snippets (up to 160 characters, with control characters stripped) are held in memory and, if you save a report, written into that report.
- **EXPOSURE** does not read file contents. It uses `Lstat`, glob expansion, and directory enumeration to record existence, size, and mtime. Directory enumeration returns names, not file contents.
- **REPORT** writes data already held in memory. It does not re-read scanned files.
- **CLEAN** reads each selected filesystem item to compute its SHA-256 before moving it into quarantine. Registry items are exported with `reg export` before deletion.

## What is written to disk

| Item | Location | Contents |
|---|---|---|
| Quarantine | `<user config dir>/K2F PURGE/quarantine/<unix timestamp>/` | `manifest.json` plus `files/<sha256>__<basename>` for files, or a directory copy with the same naming scheme. The manifest records the original path, kind, rule ID, SHA-256, size, mtime, and, for registry items, the key and backup file name. Files are created with mode 0600 and directories with 0700 where the OS honors Unix modes. |
| Reports | A directory you choose in the save dialog | `scan-report-<UTC timestamp>.md` and `scan-report-<UTC timestamp>.json`, created with mode 0600 where the OS honors Unix modes. They contain the app version, OS/arch, user name, scan targets, findings and snippets, actions taken, block/clean results, exposure summary, and limitations. |
| Rotation checklist | The file you choose in the save dialog | Markdown with paths, existence, size, mtime, and suggested rotation actions. It contains no file contents. |
| Hosts file | `<hosts path>` | A marker-delimited block managed by K2F PURGE. The previous file is saved next to it as `<hosts>.k2f-backup-<unix timestamp>`. The tool changes only its own marker block and keeps a backup. |
| Firewall and persistence | OS-specific | Windows: named `netsh advfirewall` rules called `K2F PURGE - Block <IP>`. Linux: an `nft` table named `inet k2f_purge`, `/etc/k2f-purge/block.nft`, and `/etc/systemd/system/k2f-purge-block.service` (plus iptables rules if nftables fails). macOS: `/etc/pf.anchors/com.k2fpurge` and `/Library/LaunchDaemons/com.k2fpurge.block.plist`. |
| Registry backup | Inside the quarantine session's `files/` directory | A `.reg` export of the single `HKCU` CLSID before deletion. In quarantine mode it stays there until you purge the item. In permanent-delete mode it is removed with the rest of that quarantine session. |
| Elevated-op scratch files | `<user cache dir>/k2f-purge/ops/` | Randomly named `<id>.json` request and `<id>.result.json` response files. The request is created with mode 0600. The result is created with mode 0644 so the unprivileged parent can read it; its body carries operation status and result metadata, never file contents. Both are deleted after the operation. The request contains only a whitelisted operation name and its structured payload. |

Default locations:

- Windows: `%APPDATA%\K2F PURGE\quarantine` and `%LOCALAPPDATA%\k2f-purge\ops`.
- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/K2F PURGE/quarantine` and `${XDG_CACHE_HOME:-$HOME/.cache}/k2f-purge/ops`.
- macOS: `~/Library/Application Support/K2F PURGE/quarantine` and `~/Library/Caches/k2f-purge/ops`.

The app creates no log file. Startup errors are written to standard error by Go's `log` package.

## Retention

Quarantined items remain until you restore or purge them, or delete the quarantine directory yourself. Reports and checklists remain wherever you saved them. Hosts backups remain next to the hosts file until you delete them. The tool does not run background cleanup and does not remove old files on its own.

## Sensitive output

Reports contain absolute paths, the local user name, OS and architecture, and short snippets from matched files. Treat a report as sensitive incident data. The exposure checklist lists credential-bearing paths but not the contents of those files.

## What is not collected

- No credential or wallet file contents from exposure checks.
- No deliberate collection of browsing history, cookies, or token values. A scan snippet may include whatever text surrounds a matched IOC in a scanned log or cache file.
- No collection of file contents beyond scan matching and the SHA-256 hashing performed when an item is quarantined. Files in scan scope may be read in full to search for IOC strings.
- No telemetry, usage counters, crash dumps, or device identifiers.
- No network requests of any kind.
