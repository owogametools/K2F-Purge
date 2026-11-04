# Verifying K2F PURGE

This document lists checks a skeptic can run against the source and a running build. Each check names the claim it tests and the result to expect. Commands assume the repository root.

The interface follows the system language: English by default, Traditional Chinese or Japanese when the system language matches.

The Windows build is the one exercised end-to-end in this repository. Linux and macOS builds are cross-compiled and covered by unit and view tests; verify GUI behavior on those platforms yourself if you depend on it.

## 1. Build from source and run the tests

```sh
go version        # go1.27.3
go test ./...
GOOS=linux GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=amd64 go build ./...
CGO_ENABLED=0 go build ./...
go tool mygo build
```

Expected:

- All tests pass. On Windows, the 0.2.0 suite reports 110 passing tests across 12 packages. On other platforms, use "all tests pass" as the criterion; the platform-specific test set differs.
- Both cross-builds complete.
- The cgo-disabled build completes.
- `go tool mygo build` writes `build/windows-amd64/K2F PURGE.exe` and `build/windows-amd64/k2f-purge-setup-0.2.0-amd64.exe`.

The last command needs Go 1.27.3 because `go.mod` pins the mygo build tool with a `tool` directive.

CI (`.github/workflows/ci.yml`) runs `gofmt -l`, `go vet ./...`, `go test ./...`, and cgo-disabled Linux and macOS cross-builds on every push and pull request. The tag-driven release workflow builds the Windows app with mygo and packages plain Linux and macOS binaries.

## 2. Compare the ruleset with the public record

The public source is the MotherSphere gist:

https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5

The same values are reproduced in `docs/incident-report.zh-Hant.md`. The gist is prose; compare values, not formatting. If `jq` is not installed, read the JSON directly or parse it with PowerShell's `ConvertFrom-Json`.

```sh
jq '{version, iocs}' internal/ioc/rules.json
jq -r '.checks[] | [.id, .kind, .scope, .confidence] | @tsv' internal/ioc/rules.json
```

Expected `version` and `iocs`:

| Field | Expected |
|---|---|
| `version` | `2026-11-04.1` |
| `domains` | `insightjs.com`, `analytics.insightjs.com`, `insightjs.org` |
| `ips` | `89.127.233.127`, `89.126.250.172` |
| `sha256` | `2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203`, `3aaafbd612f04501a6fdb0bb8b2f8a87796223e5584ac18ea5eb180feeafb193`, `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec` |
| `etags` | `6ae78037-3214f`, `6ae8ccff-3214f`, `6ae90538-3214f`, `6ae9d408-3214f`, `6ae9f628-3214f` |

Spot-check the rules that drive the strongest verdicts:

```sh
jq -r '.checks[] | select(.id=="log.k2f_chan" or .id=="state.k2f_agent" or .id=="chrome.helper_dll" or .id=="reg.clsid_hkcu") | [.id, .pattern, .confidence] | @tsv' internal/ioc/rules.json
```

Expected patterns include `k2f_chan registered`, `k2f.agent`, a 64-hex `PlatformExperienceHelper` child containing `platform_experience_helper.dll`, and the `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` key. The registry rule is under HKCU only.

Confirm the embedded copy parses:

```sh
go test ./internal/ioc -run TestLoadEmbedded -v
```

## 3. Confirm there is no network code

```sh
grep -RInE 'net/http|net\.Dial|net\.Listen|http\.(Get|Post|Client|DefaultClient)|tls\.Dial|ListenAndServe' --include='*.go' .
```

Expected: no output.

`net` is imported only for address validation. To confirm:

```sh
grep -RIn '"net"' --include='*.go' internal main.go | grep -v _test.go
```

Expected: `internal/block/block.go` and the platform firewall files use `net.ParseIP`; `internal/ioc/load.go` validates configured IPs. No HTTP client or listener is present.

Telemetry and crash reporters:

```sh
grep -RInE 'sentry|crashpad|bugsnag|rollbar|opentelemetry|telemetry' --include='*.go' internal appui main.go | grep -v _test.go
```

Expected: no application telemetry. `internal/exposure/catalog.go` contains a `~/.sentryclirc` credential path; that is a catalog entry for the Sentry CLI, not a crash reporter.

The block verifier deliberately avoids DNS resolution. `internal/block/block.go` calls `Verify` and comments that a `LookupHost` of an unblocked name would leak DNS. Hosts verification reads the local hosts file instead.

## 4. Confirm there is no cgo and no webview

```sh
grep -RIn 'import "C"' --include='*.go' .
grep -RIni 'webview' --include='*.go' .
CGO_ENABLED=0 go build ./...
```

Expected: the first two commands produce no output, and the cgo-disabled build succeeds. `go.mod` lists `github.com/ebitengine/purego` as an indirect mygo dependency; purego is not cgo.

## 5. Inspect the block plan before applying

Open the BLOCK page. The "Indicators" panel lists the exact hostnames and IPs; the four checkboxes control hosts, firewall, persistence, and DNS flush. Nothing is written until you press Apply block.

Verify the same defaults in source:

```sh
grep -n -A12 'var defaultDomains' internal/block/block.go
grep -n -A4 'var defaultIPs' internal/block/block.go
grep -n -A20 'func buildBlock' internal/block/hosts.go
```

Expected:

- Hosts entries for `insightjs.com`, `www.insightjs.com`, `analytics.insightjs.com`, `insightjs.org`, and `www.insightjs.org`, each pinned to `0.0.0.0` and `::1`.
- Firewall drops for `89.127.233.127` and `89.126.250.172`.
- Windows rule names are `K2F PURGE - Block <IP>`.
- Linux uses the nftables table `inet k2f_purge`; macOS uses the pf anchor `com.k2fpurge`.

The hosts writer only manages its marker block:

```sh
grep -n 'K2F PURGE BLOCK BEGIN\|K2F PURGE BLOCK END' internal/block/hosts.go
```

The writer preserves unrelated lines and the existing newline style, writes atomically, and backs up the previous file before changing it.

## 6. Inspect the changes after applying

Apply the block in a test VM or on a machine you control, then inspect it.

Windows:

```bat
type %SystemRoot%\System32\drivers\etc\hosts
netsh advfirewall firewall show rule name="K2F PURGE - Block 89.127.233.127"
netsh advfirewall firewall show rule name="K2F PURGE - Block 89.126.250.172"
dir %SystemRoot%\System32\drivers\etc\hosts.k2f-backup-*
```

PowerShell equivalents:

```powershell
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts"
Get-NetFirewallRule -DisplayName "K2F PURGE - Block *"
Get-ChildItem "$env:SystemRoot\System32\drivers\etc\hosts.k2f-backup-*"
```

Linux:

```sh
sudo grep -n -A12 -B1 'K2F PURGE BLOCK BEGIN' /etc/hosts
sudo nft list table inet k2f_purge
systemctl status k2f-purge-block.service
cat /etc/k2f-purge/block.nft
```

If nftables failed, check the iptables fallback:

```sh
sudo iptables -C OUTPUT -d 89.127.233.127 -j DROP
```

macOS:

```sh
sudo pfctl -a com.k2fpurge -s rules
sudo cat /etc/pf.anchors/com.k2fpurge
sudo launchctl print system/com.k2fpurge.block
```

Use Remove block in the interface, then repeat the checks. Expected: the marker block is gone, the named Windows rules are gone, the nft table and systemd unit are gone, and the pf anchor and LaunchDaemon are gone. Hosts backups remain until you delete them.

Implementation note: Windows rules and hosts entries are checked before they are added. The Linux nftables path appends rules on each apply, so repeated Apply calls can duplicate rules until Remove is used. macOS rewrites the anchor file. If you are testing idempotence on Linux, apply, remove, then apply again.

## 7. Inspect the quarantine manifest

Run a scan that produces findings, build the cleanup plan, select items, and choose Quarantine. Then inspect the session.

Windows:

```powershell
Get-ChildItem "$env:APPDATA\K2F PURGE\quarantine" -Recurse
Get-Content "$env:APPDATA\K2F PURGE\quarantine\<timestamp>\manifest.json"
```

Linux:

```sh
ls -lR "$HOME/.config/K2F PURGE/quarantine"
cat "$HOME/.config/K2F PURGE/quarantine/<timestamp>/manifest.json"
```

macOS:

```sh
ls -lR "$HOME/Library/Application Support/K2F PURGE/quarantine"
cat "$HOME/Library/Application Support/K2F PURGE/quarantine/<timestamp>/manifest.json"
```

Expected in `manifest.json`: `original_path`, `kind`, `rule_id`, `sha256`, `size`, `mtime`, and `stored_name` for filesystem items; registry items carry `registry_key` and `registry_file`.

For a file item, compare the manifest hash with the stored file:

```sh
sha256sum "<quarantine dir>/files/<stored_name>"          # Linux
shasum -a 256 "<quarantine dir>/files/<stored_name>"      # macOS
Get-FileHash "<quarantine dir>\files\<stored_name>" -Algorithm SHA256   # Windows
```

The stored name is `<sha256>__<original basename>`. Directory items use a hash of the directory contents, so compare with the manifest rather than assuming the name is a single file hash.

Restore selected items from the interface and confirm they return to their original paths. For a registry item, restore uses `reg import` on the exported `.reg` file. Permanent deletion requires typing `PURGE`; in that mode the session files, including the `.reg` export, are removed.

## 8. Check for network egress at runtime

Source checks in section 3 are the strongest evidence. To check the running process:

Windows:

```bat
netstat -ano | findstr <PID>
```

PowerShell:

```powershell
Get-NetTCPConnection -OwningProcess <PID>
```

Linux:

```sh
ss -tupn | grep <PID>
sudo strace -f -e trace=network -p <PID>
```

macOS:

```sh
lsof -nP -i -p <PID>
```

A stronger test: create an outbound block rule for `K2F PURGE.exe` in Windows Defender Firewall with advanced security, or run the app in a VM with no network adapter, then exercise Scan, Block, Clean, Exposure, and Report. The workflow should still complete; no operation needs a network connection.

## 9. Confirm registry operations are HKCU-only

Inspect the allowlist and the forbidden hives:

```sh
grep -n -A12 'allowedCLSIDKey' internal/clean/safety.go
grep -n -A20 'func isForbiddenHive' internal/clean/safety.go
grep -n -A16 'func allowedRegistryKey' internal/clean/safety.go
```

Expected: only `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` and its subkeys are accepted. `HKLM`, `HKEY_LOCAL_MACHINE`, `HKU`, `HKCR`, and `HKCC` are refused.

Inspect the Windows registry calls:

```sh
grep -RInE 'runReg|registryQuery|"reg"' internal/clean internal/scan
```

Expected: `internal/clean/registry_windows.go` validates the key before `reg export` and `reg delete`; `internal/scan/registry_windows.go` only runs `reg query` and refuses HKLM.

Before and after a cleanup on Windows, export the legitimate HKLM key and compare:

```bat
reg export "HKLM\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}" "%TEMP%\hkml-before.reg" /y
rem run the cleanup
reg export "HKLM\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}" "%TEMP%\hkml-after.reg" /y
fc /b "%TEMP%\hkml-before.reg" "%TEMP%\hkml-after.reg"
```

Expected: no difference. The HKLM key is the legitimate Windows Parental Controls component (`wpc.dll`) and is never queried for deletion.

## 10. Confirm exposure checks are metadata-only

```sh
grep -RInE 'os\.(Open|ReadFile)\(' internal/exposure --include='*.go' | grep -v _test.go
go test ./internal/exposure -run TestScanWithHomeLstatOnly -v
```

Expected: the grep produces no output; the test passes. `internal/exposure/scan.go` uses `os.Lstat`, glob expansion, and `os.ReadDir`. `os.ReadDir` returns directory entries, not file contents.

For a runtime check, use Process Monitor on Windows with a filter for the catalog paths and the `ReadFile` operation. Expected: no `ReadFile` on credential files, only metadata queries. On Linux, `strace -f -e trace=openat,newfstatat,lstat` will show directory opens for enumeration; look for opens of the credential files themselves and expect none.

## 11. Confirm the scan is read-only

```sh
grep -RInE 'os\.(WriteFile|Create|Mkdir|MkdirAll|Remove|RemoveAll|Rename)\(' internal/scan --include='*.go' | grep -v _test.go
go test ./internal/scan -run TestRun_DoesNotWrite -v
```

Expected: the grep produces no output; the test passes. The only external command in the scan package is `reg query` on Windows, which reads a registry key.

For a runtime check, snapshot the hashes and timestamps of a launcher directory before and after a scan. Expected: no changes. Process Monitor can also be filtered to write operations from the app during Scan.

## 12. Confirm reports stay local

1. Run a scan and open REPORT.
2. Save the report to a directory you choose.
3. Confirm the directory contains `scan-report-<UTC timestamp>.md` and `scan-report-<UTC timestamp>.json`.
4. Inspect the JSON: it contains the app version, OS/arch, user, scan targets, findings, block/clean state, exposure items, and actions. There is no upload field and no remote endpoint.

The report writer (`internal/report/save.go`) creates both files in the chosen directory. The save dialog is the only path input. The exposure checklist is written to the single path you choose in its save dialog. No other component sends data off the machine.

## 13. Check the elevated-op path

Inspect the whitelist and transports:

```sh
grep -n -A16 'var allowedOps' internal/elev/elev.go
grep -n -A10 'func runElevated' internal/elev/elev_windows.go internal/elev/elev_linux.go internal/elev/elev_darwin.go
grep -n -A18 'func opsDir' internal/elev/elev.go
```

Expected:

- The whitelist contains `hosts.apply`, `hosts.remove`, `firewall.apply`, `firewall.remove`, `dns.flush`, `block.apply`, `block.remove`, `clean.apply`, `clean.restore`, `clean.purge`, `registry.export`, and `registry.delete`.
- Windows uses `ShellExecuteW` with the `runas` verb.
- Linux uses `pkexec` and falls back to `sudo -n`.
- macOS uses a constant AppleScript body with `osascript ... with administrator privileges`; paths are passed as argv and quoted, not interpolated into the script.
- Op request files are created under `<user cache dir>/k2f-purge/ops/` with mode 0600. Result files are 0644 JSON (status and result metadata, never file contents) so the unprivileged parent can read them. Both are removed after the operation.
- The parent passes the directory to the child as `--ops-root`. The child cannot recompute it: under `pkexec`, `sudo`, or `osascript` it runs as root and `os.UserCacheDir` would point at `/root`. `opsRoot` accepts only a path ending in `k2f-purge/ops` that is a private directory, and the op file must be a regular file inside it (0600 on Unix).

Wiring note for 0.1.0:

```sh
grep -RIn 'RunPrivileged' internal/service appui main.go
```

Expected: `internal/service/service.go` calls `elev.RunPrivileged` from `runBlockOp` for `block.apply` and `block.remove` when `elev.Mode()` is `per-op`, which is the Linux/macOS non-root case. Clean operations still call `clean.Apply` in-process; they can move user-owned launcher files without elevation, but privileged actions report permission failures. On Windows, a declined UAC prompt leaves the app in `limited` mode, which does not use the per-op path. Scan, exposure, and report do not need elevation.

## 14. What these checks do not prove

- They do not prove the machine is free of malware. Detection is limited to the published IOCs and the places the scanner looks.
- They do not prove the agent never ran or never exfiltrated data. The launcher log does not record the commands the operator executed.
- They do not prove the release binary matches this source unless you build it yourself from the same commit.
- They do not exercise the Linux or macOS GUI end-to-end. Those builds are cross-compiled and unit/view tested; the Windows build is the one run end-to-end here.
- The test suite uses fixtures and never touches the real hosts file, firewall, or registry. Destructive paths are validated by unit tests and dry runs.
