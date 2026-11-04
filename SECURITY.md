# Security Policy

## Supported versions

Security fixes are provided for the latest release on the 0.3.x line. Older builds are not supported.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on `owogametools/K2F-Purge`:

https://github.com/owogametools/K2F-Purge/security/advisories/new

Do not open a public issue for a vulnerability. Include:

- the K2F PURGE version and the OS/architecture;
- the affected page or package;
- reproduction steps and the observed impact;
- if the issue involves a detection rule, the rule ID and a minimal fixture that does not contain live malware.

There is no bug bounty.

## Threat model

K2F PURGE runs on a machine that may already be compromised by the NIKKE launcher agent. It is an incident-response utility, not a sandbox, an EDR, or an antivirus.

Assets:

- the user's files and credentials (the default exposure catalogue check must not read credential contents; the two content scans are explicit opt-in actions limited to existing catalogue entries);
- system configuration: hosts file, firewall state, and the single HKCU registry key;
- the integrity of the tool's own elevated operations.

Untrusted inputs and adversaries:

- a local attacker or malware that can write files in scanned locations, including crafted log/cache content, symlinks, and path names;
- a local rules JSON passed to `internal/ioc.LoadFile`;
- a local process that races the app while it performs privileged operations;
- a user who is tricked into applying block or clean actions.

Trust boundaries:

- Interface to `internal/service` to the OS. The interface never passes arbitrary cleanup paths; the plan is derived from scan findings and re-validated before every destructive action.
- Elevated child to the OS. The child accepts only whitelisted operation names and structured JSON payloads, with a 120-second timeout.

If the operating system, the Go toolchain, or the K2F PURGE binary itself is compromised, these controls do not help.

## Controls in the code

- **Read-only scan.** `internal/scan` contains no file writes or deletes. It runs `reg query` on Windows and reads files only within selected scopes. Covered by `TestRun_DoesNotWrite`.
- **Metadata-only exposure catalogue check.** `internal/exposure/scan.go` uses `os.Lstat`, glob expansion, and `os.ReadDir`; it never calls `os.Open` or `os.ReadFile`. Covered by `TestScanWithHomeLstatOnly`. Content scans live in separate packages and are invoked by separate service methods.
- **Explicit content scans.** `Service.SecretScan` and `Service.AstrLinkScan` run only after the user presses a button, and only when an exposure result already exists. They receive the existing file, glob, and environment-variable-pointed catalogue entries, skip directories, registry items, symlinks, binary files, and oversized files, and enforce file, finding, and byte caps. `SecretFinding.Value` is used only for the interface and for exports; logs, actions, and error messages use `SecretFinding.Masked`.
- **Bundled model integrity.** `internal/astrlink` locates the model under the application directory, verifies each file's size and SHA-256 before use, and reports unavailability instead of downloading anything. The release scripts verify the same values before packaging.
- **Safe evidence snippets.** Matched context is stripped of control characters and capped at 160 runes before it reaches the interface or a report (`internal/scan/search.go`).
- **Hosts editing.** Only a marker-delimited block is written. The editor preserves unrelated content and line endings, writes atomically, and keeps a backup (`internal/block/hosts.go`).
- **Firewall commands.** Commands run through `exec.Command` with an argv list; no shell is used. IP addresses must pass `net.ParseIP`; hostnames are validated against a restricted character set (`internal/block`).
- **Cleanup allowlist.** Destructive actions re-check the item kind and path. `HKEY_LOCAL_MACHINE` is refused, the `PlatformExperienceHelper` parent folder is refused, symlinks that escape the allowlisted roots are refused, and registry access is limited to the single known HKCU CLSID (`internal/clean/safety.go`, `internal/clean/plan.go`).
- **Quarantine first.** Files are moved into a session directory with a manifest and SHA-256, then chmodded to 0600/0700 where supported. The interface requires the typed confirmation `PURGE` before permanent deletion (`internal/clean/quarantine.go`, `appui/app.go`).
- **Elevated operation whitelist.** `internal/elev` accepts only the names in `allowedOps`, writes the request to a random 0600 file under the user cache directory, writes the result as 0644 JSON (status and result metadata, never file contents) so the unprivileged parent can read it, checks that the op file is inside that directory, times out after 120 seconds, and deletes the request and result files (`internal/elev/elev.go`).
- **No web engine.** The interface is native Go. There is no webview, no JavaScript runtime, and no HTML rendering surface.
- **No network.** The application has no HTTP, TCP, UDP, or TLS client code and no telemetry or crash-reporting dependency. The AstrLink Guard model ships in the release archive; it is never downloaded at runtime.

## What the tool will never do

- Delete or modify anything under `HKLM`.
- Delete the `PlatformExperienceHelper` parent folder.
- Download detection rules, updates, payloads, or any other content.
- Make a network request, send telemetry, or upload a crash report.
- Read catalogue file contents during the default exposure check. The opt-in **Scan contents** and **Show leaked content** actions read only existing catalogue entries, within the documented size, file-count, and byte caps.
- Write complete secret values to logs or error messages. Complete values appear in the interface and in checklists or reports you explicitly save.
- Change passwords, revoke tokens, or touch wallet funds.
- Apply cleanup beyond the items selected in the interface.
- Accept an arbitrary path or command from the interface, or accept an arbitrary command through the elevated-op channel.

## Known limitations

- **IOC-based detection.** Variants, unpublished builds, and artifacts already removed by the attacker can be missed. `CLEAR_OF_LISTED_IOCS` is not a clean bill of health.
- **Logs do not record commands.** The launcher log cannot show what the attacker executed. A `CONFIRMED` result should be treated as a worst-case finding.
- **Non-Windows gaps.** Chrome helper DLL and Windows registry checks are skipped on Linux and macOS and are reported as scan limitations.
- **Elevation wiring at 0.1.0.** Block operations use the whitelisted `--elevated-op` transport on Linux and macOS when the app is not root. Clean operations still call the core in-process; they can move user-owned launcher files, but privileged actions, such as Windows registry changes after a declined UAC prompt, report permission failures. Elevated children receive the op directory as `--ops-root`, because as root they cannot resolve the caller's cache directory; only a private `<...>/k2f-purge/ops` path is accepted.
- **System tools are trusted.** The privileged paths invoke `netsh`, `reg`, `nft`, `iptables`, `systemctl`, `pfctl`, `launchctl`, and similar tools by name. Run the app from a trusted directory with a trusted `PATH`, and use OS-provided binaries.
- **Sensitive reports.** Reports contain paths, user names, OS details, and short matched snippets. After an exposure content scan they also contain complete matched secret and personal-data values. Store and share them accordingly.
- **Content scans are bounded.** They cover only existing catalogue entries, skip symlinks, binaries, and files over the caps, and can miss a secret split across lines or stored in an unsupported format. Rules can produce false positives, and the model can miss or misclassify personal data.
- **No EDR or live protection.** The tool does not monitor processes, block execution, or detect future activity.
