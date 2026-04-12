# Cluster Management Repository

This repository manages a small Linux cluster using Rex (Perl), with a security-hardened workflow for **mesh SSH** — no node is special; every node can reach every other node via both password and key-based SSH.

Core design goals:
- Keep machine inventory in YAML files under cmdb/ (networks and optional MAC data only)
- Keep secrets (usernames, passwords, key material) in an encrypted SQLite database under createdatabase/
- Use bootstrap mode only for first-time access and key deployment
- Use key-based SSH for all normal operations (operational mode)
- All mutating operations produce timestamped audit log entries

## What the Code Does

### system_db_setup/generate_cmdb.pl
Reads `users_db.csv` (hostname, username, password) and `networks_db.csv` (network, hostname, IP) and emits one `cmdb/<hostname>.yml` per machine. The YAML files contain **only** network IPs and optional MAC addresses — credentials are never written to YAML [SEC-CRED-ENCRYPT]. Run this once when adding new machines.

### createdatabase/init_cluster_db.pl
Initialises the AES-256-GCM encrypted SQLite database (`cluster_keys.db`) and imports credentials from `users_db.csv` and optionally public keys from `pubkeys/*.pub`. The database schema stores encrypted usernames, passwords, SSH public keys, host keys, and key passphrases with full rotation tracking. All operations are audit-logged.

### createdatabase/ClusterDB.pm
Pure-Perl encrypted database module. Provides:
- `store_key` / `get_key` / `list_keys` / `delete_key` — SSH public key management
- `store_credential` / `get_credential` / `list_credentials` / `delete_credential` — credential management
- `store_key_passphrase` / `get_key_passphrase` — SSH key passphrase management
- Private `_encrypt` / `_decrypt` using AES-256-GCM (FIPS 140-2) with a per-record IV
- Private `_derive_key` using PBKDF2-SHA256 at 600,000 iterations (NIST SP 800-132)
- Per-operation audit logging to a flat log file [SEC-AUDIT-LOG]
- Permission enforcement: 0600 on database file, 0400 verified on keyfile

### ClusterSSHHelpers.pm (repo root)
Shared helper module used by the Rexfile (and available to other Rexfiles). Provides:
- `ssh_opts` / `ssh_opts_bootstrap` — SSH option builders for operational and bootstrap modes
- `audit_log` — timestamped audit logging [SEC-AUDIT-LOG]
- `detect_admin` — identify the admin machine by matching local IPs to CMDB
- `tcp_pinger` — create a Net::Ping TCP prober on port 22
- `resolve_targets` — resolve `--group`/`--machine` parameters into a target list
- `validate_name` — input validation against shell injection
- `cluster_db` / `get_credential` — lazy-connected encrypted database access
- `ensure_agent_loaded` — load the admin cluster key into ssh-agent via SSH_ASKPASS
- `bootstrap_via_askpass` / `bootstrap_run_or_warn` / `bootstrap_capturex` — run commands with password via SSH_ASKPASS + 0400 tempfile
- `generate_load_cluster_key_script` — generate the node-local key loader script
- `ensure_io_interface` / `cleanup_io_interface` / `get_mac_for_ip` — IO::Interface helpers for MAC discovery
- And other utilities (`command_exists`, `kh_key`, `run_or_warn`, `shell_quote`, `generate_passphrase`, `bootstrap_remote_mktemp`, `all_networks`)

Loaded via `use FindBin qw($Bin); use lib "$Bin/.."; use ClusterSSHHelpers;` and configured with `ClusterSSHHelpers::init(...)` at startup.

### cluster_ssh_setup/Rexfile
Main Rex task file. Defines 14 tasks:

| Task | Description |
|------|-------------|
| `show_cmdb` | Display CMDB network/machine inventory (passwords always redacted) |
| `list_groups` | List defined inventory groups and members |
| `show_keys` | View SSH public key metadata (or full key for one machine) |
| `show_credentials` | View credential metadata (passwords always redacted) |
| `check_network` | TCP-probe node reachability on a named network |
| `nodes_in_network` | List nodes and reachability for one or all networks |
| `networks_for_node` | List networks and reachability for one or all machines |
| `show_known_hosts` | Display known_hosts content on each reachable node |
| `rm_dup_hosts` | Remove duplicate known_hosts entries cluster-wide |
| `setup_ssh_keys` | 9-phase key distribution to build full mesh (bootstrap required) |
| `remove_ssh_keys` | 8-phase key teardown, inverse of setup (bootstrap + confirm required) |
| `shutdown` | Remote shutdown of all non-admin nodes on a network |
| `obtain_mac` | Discover and store MAC addresses in CMDB YAMLs |
| `validate_ssh_mesh` | Probe all pairwise SSH connections (password + key) across a group |

Both tasks accept `--machine=<name>` (target a single node) or `--group=<name>` (default: `all`).
If both are given, `--group` takes precedence.

#### setup_ssh_keys — 9-phase workflow
1. Validates required local commands (`ssh`, `scp`, `ssh-keygen`, `ssh-copy-id`, `sshpass`, `ssh-keyscan`, `openssl`)
2. Generates the admin ECDSA P-521 keypair (`~/.ssh/id_ecdsa_p521_cluster`) with a random passphrase stored in the encrypted DB
3. TCP-probes all group/machine members on port 22 (UP / DOWN / MISSING)
4. Updates admin `~/.ssh/known_hosts` with fresh FIPS-approved host keys for all reachable nodes
5. Generates a unique ECDSA P-521 keypair **on each remote node** (private key never leaves the node); authorizes admin public key via `ssh-copy-id`; deploys a node-local encrypted passphrase store (`~/.ssh/.cluster_node_keyfile`, `~/.ssh/.cluster_node_pp`, `~/.ssh/load_cluster_key.pl`) so the node can unlock its own key autonomously without contacting the admin (enables Node→Node and Node→Admin SSH after bootstrap)
6. Cross-authorizes all node keys on admin and peers (full mesh: node→admin, admin→node, node→node)
7. Propagates admin and all peer host keys to remote `~/.ssh/known_hosts` (no TOFU prompts anywhere)
8. Deploys `~/.ssh/config` with `IdentityFile ~/.ssh/id_ecdsa_p521_cluster` and `StrictHostKeyChecking yes` on admin and all nodes
9. Updates `/etc/hosts` on admin and all reachable nodes with `{network}{machine}` aliases

#### remove_ssh_keys — 8-phase teardown
Reverses all `setup_ssh_keys` changes: removes keypairs, the three node-local passphrase-store files (`~/.ssh/.cluster_node_keyfile`, `~/.ssh/.cluster_node_pp`, `~/.ssh/load_cluster_key.pl`), authorized_keys entries, known_hosts entries, ssh/config blocks, and /etc/hosts aliases. Requires `--bootstrap=1` AND `--confirm=1`.

## Repository Layout

- ClusterSSHHelpers.pm: shared helper module (SSH options, audit, bootstrap, IO::Interface)
- cluster_ssh_setup/
  - Rexfile: main task automation (14 tasks, security-hardened)
- cmdb/
  - One YAML per machine
  - Contains only non-secret inventory data (network IPs, optional MAC addresses)
- createdatabase/
  - ClusterDB.pm: encrypted database module (AES-256-GCM)
  - init_cluster_db.pl: database initialization and import script
  - pubkeys/: optional staged public keys to import
  - (git-ignored) cluster_keys.db — encrypted SQLite database
  - (git-ignored) .cluster_db.keyfile — master encryption key
- system_db_setup/
  - (git-ignored) users_db.csv: input credentials for encrypted DB import
  - (git-ignored) networks_db.csv: network inventory input
  - generate_cmdb.pl: builds non-secret YAML inventory
- logs/
  - (git-ignored) audit.log: timestamped record of all mutating operations

## Security Model

- Credentials and keys are encrypted at rest in `createdatabase/cluster_keys.db`
- Encryption and KDF are configured for strong defaults:
  - AES-256-GCM with per-record random IV (FIPS 140-2, NIST SP 800-38D)
  - PBKDF2-SHA256 with 600,000 iterations (NIST SP 800-132)
- Database keyfile should be owner-read-only:
  - `chmod 400 createdatabase/.cluster_db.keyfile`
- Plaintext credentials are not stored in cmdb/*.yml
- Node-local passphrase store (deployed by Phase 5 of `setup_ssh_keys`):
  - `~/.ssh/.cluster_node_keyfile` (0400) — unique per-node AES key
  - `~/.ssh/.cluster_node_pp` (0400) — SSH key passphrase encrypted with AES-256-CBC PBKDF2-SHA256 600k iter
  - `~/.ssh/load_cluster_key.pl` (0500) — pure-Perl helper that decrypts and loads the key into `ssh-agent`
  - Enables every node to unlock its own cluster key autonomously (Node→Admin, Node→Node SSH without admin)
- All bootstrap password operations use `SSH_ASKPASS` + a 0400 tempfile; the `SSHPASS` environment variable is never set

## Security Practice Labels

The following security-practice labels are used throughout the codebase to tag
the controls each section implements. These are project-defined labels (not
external rule IDs) that describe the actual security property enforced.

| Label | Description | Implementation |
|-------|-------------|----------------|
| SEC-SSH-NOPASSWD | Disable SSH password auth | `PasswordAuthentication=no` in all operational SSH option sets |
| SEC-SSH-CONFIG-PERMS | SSH config file permissions | `~/.ssh/config` enforced to 0600 |
| SEC-KEY-PASSPHRASE | SSH private key passphrase | All keypairs (admin + per-node) generated with random 44-char passphrase; passphrases stored in encrypted DB; `ssh-agent` used to cache unlocked key |
| SEC-STRICT-HOSTKEY | StrictHostKeyChecking | `StrictHostKeyChecking=yes` in operational mode and enforced in the deployed `~/.ssh/config` block; relaxed only in explicit bootstrap mode with `--bootstrap=1` |
| SEC-CRED-ENCRYPT | No plaintext credentials on disk or in process table | Credentials encrypted at rest (AES-256-GCM); bootstrap passwords passed via `SSH_ASKPASS` + owner-read-only (0400) tempfile — `SSHPASS` env var is never set; node passphrases encrypted at rest (AES-256-CBC PBKDF2-SHA256 600k iter) and staged via non-descriptive 0400 tempfiles with 8-char random suffixes (`mktemp`), never in shell args |
| SEC-CRED-REDACT | Passwords not displayed to terminal | Passwords always shown as `(redacted - SEC-CRED-REDACT)` in all display tasks |
| SEC-FIPS-ALGO | FIPS-approved key algorithms | ECDSA P-521 for key generation; `ssh-keyscan` restricted to `ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521` |
| SEC-AUDIT-LOG | Audit logging | All mutating operations write a timestamped ISO-8601 entry to `logs/audit.log`; log file enforced to 0600 |
| FIPS-140 | Approved cipher and KDF | AES-256-GCM (NIST SP 800-38D); PBKDF2-SHA256 at 600,000 iterations (NIST SP 800-132) |

### sudoers prerequisites for hardened systems

The automation tasks require password-free sudo for exactly two commands on each node. Add to `/etc/sudoers` on each node:

```
<cluster-user> ALL=(root) NOPASSWD: /usr/bin/tee /etc/hosts
<cluster-user> ALL=(root) NOPASSWD: /usr/sbin/shutdown
```

No other `NOPASSWD` rules are required.

---

## Known Security Vulnerabilities and Pitfalls

The items below are accepted risks or require operational mitigations.

### MEDIUM

**1. CSV parsing does not fully validate fields — PARTIALLY FIXED**
`users_db.csv` and `networks_db.csv` are parsed with `split /\s*,\s*/, $_, 3`. Hostnames and network names are validated against `/^[a-zA-Z0-9._-]+$/`. IPs are validated against a dotted-decimal regex.
*Residual risk*: passwords containing commas are still silently truncated; switching to `Text::CSV` would resolve this fully.

**2. Bootstrap TOFU — `ssh-keyscan` output not fingerprint-verified — OPEN**
During `setup_ssh_keys` phase 4, host keys are collected via `ssh-keyscan` and installed directly into `~/.ssh/known_hosts` without comparing against a pre-shared fingerprint list. This is inherent to the bootstrap model. Mitigation: run bootstrap only on an isolated, trusted network segment; optionally supply a pre-provisioned known_hosts file.

**3. Password mesh test uses `StrictHostKeyChecking=no` — OPEN**
The inner command that tests password-based SSH for non-admin source nodes uses `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`. This is appropriate for a connectivity test but means the password test does not validate host identity — a MITM would pass the password test. The result could give false assurance that password auth is "working" to the correct destination.

### LOW

**4. Silent `or next` on critical phased operations — OPEN**
`run_or_warn` logs a warning to stderr and returns 0, but callers in `setup_ssh_keys` phase 5 use `or next` to skip a node on failure. The audit log does not record a per-phase failure for skipped nodes. A partially-bootstrapped node would appear to be configured but would fail operational access.

**5. In-memory key material is not zeroed — OPEN**
The `passphrase` and `_enc_key` fields of the `ClusterDB` object and the `state $db` singleton in `cluster_db` persist in Perl memory until garbage-collected. Not a FIPS mandate for scripting platforms but relevant for high-assurance environments.

---

## Data You Must Provide

You need to provide two CSV files in system_db_setup/.

1) users_db.csv

Format:
Hostname, Username, Password

Example:
node-alpha,clusteradmin,ExamplePass!234
node-beta,clusteradmin,ExamplePass!234
node-gamma,clusteradmin,ExamplePass!234

2) networks_db.csv

Format:
Network, Hostname, IP

Example:
labnet,node-alpha,10.20.30.11
labnet,node-beta,10.20.30.12
labnet,node-gamma,10.20.30.13

You can define multiple networks by adding more rows per host with different network names.

## Full Setup Flow

Run from repository root.

1) Generate CMDB YAML files (non-secret inventory only)

perl system_db_setup/generate_cmdb.pl

2) Create encryption keyfile

openssl rand -base64 32 > createdatabase/.cluster_db.keyfile
chmod 400 createdatabase/.cluster_db.keyfile

3) Initialize encrypted DB and import keys/credentials

perl createdatabase/init_cluster_db.pl \
  --keyfile createdatabase/.cluster_db.keyfile \
  --users-csv system_db_setup/users_db.csv

Notes:
- All flags have sensible defaults when run from `createdatabase/`, but explicit paths are needed when running from the repository root
- The script always imports `.pub` files from `createdatabase/pubkeys/` by default; pass `--import <dir>` only to override that directory
- Credentials from users_db.csv are encrypted and stored in DB

4) Verify database content (without exposing passwords)

cd cluster_ssh_setup
CLUSTER_DB_KEY="$(cat ../createdatabase/.cluster_db.keyfile)" rex show_credentials
CLUSTER_DB_KEY="$(cat ../createdatabase/.cluster_db.keyfile)" rex show_keys

## Rex Tasks

From cluster_ssh_setup/:

- rex show_cmdb
  - Display CMDB machine and network inventory
- rex list_groups
  - Show defined Rex groups and members
- rex check_network --network=<name>
  - Check reachability on port 22
- rex show_known_hosts --network=<name>
  - Show known_hosts entries on reachable nodes
- rex rm_dup_hosts --network=<name>
  - Remove duplicate known_hosts entries
- rex setup_ssh_keys --network=<name> --bootstrap=1
  - First-time bootstrap: 9-phase key distribution and full mesh setup
- rex remove_ssh_keys --network=<name> --bootstrap=1 --confirm=1
  - Tear down all cluster keys, authorized_keys, known_hosts, config blocks, /etc/hosts aliases
- rex validate_ssh_mesh --network=<name>
  - Test all pairwise SSH connections (password + key) in the group
- rex shutdown --network=<name>
  - Shutdown reachable non-admin nodes
- rex nodes_in_network
  - Show nodes grouped by network with reachability
- rex networks_for_node
  - Show networks per machine with reachability
- rex obtain_mac
  - Discover and persist MAC addresses into CMDB YAMLs
- rex show_keys
  - List encrypted key metadata or show one machine key
- rex show_credentials
  - List credential metadata or show one machine username (password always redacted)

## Example: 3 Fake Machines End-to-End

This example uses fake hostnames, fake IP addresses, and fake credentials.

### A) Provide input files

system_db_setup/users_db.csv:

Hostname, Username, Password
node-alpha,clusteradmin,FakeP@ssw0rd-A1
node-beta,clusteradmin,FakeP@ssw0rd-B2
node-gamma,clusteradmin,FakeP@ssw0rd-C3

system_db_setup/networks_db.csv:

Network, Hostname, IP
labnet,node-alpha,10.20.30.11
labnet,node-beta,10.20.30.12
labnet,node-gamma,10.20.30.13

### B) Build inventory and secret DB

perl system_db_setup/generate_cmdb.pl
openssl rand -base64 32 > createdatabase/.cluster_db.keyfile
chmod 400 createdatabase/.cluster_db.keyfile
perl createdatabase/init_cluster_db.pl \
  --keyfile createdatabase/.cluster_db.keyfile \
  --users-csv system_db_setup/users_db.csv

Note: `.pub` files in `createdatabase/pubkeys/` are imported automatically.
Pass `--import <dir>` only to override that default directory.

### C) First-time connection checks

cd cluster_ssh_setup
rex check_network --network=labnet

If nodes are reachable, continue with bootstrap key deployment.

### D) First-time key distribution (bootstrap)

CLUSTER_DB_KEY="$(cat ../createdatabase/.cluster_db.keyfile)" \
rex setup_ssh_keys --network=labnet --bootstrap=1

### E) Validate mesh connectivity

CLUSTER_DB_KEY="$(cat ../createdatabase/.cluster_db.keyfile)" \
rex validate_ssh_mesh --network=labnet

### F) Verify ongoing state

rex show_known_hosts --network=labnet
rex rm_dup_hosts --network=labnet
rex nodes_in_network --network=labnet

## Operational Notes

- Keep `createdatabase/.cluster_db.keyfile` off version control and in a secured, backed-up location
- Rotate credentials by updating `users_db.csv` and re-running `init_cluster_db.pl`
- Re-bootstrap only when needed (new nodes, key rotation, trust reset)
- For strict environments, ensure sudoers is configured as described in the prerequisites section
- The keyfile can also be passed via `CLUSTER_DB_KEY` env var instead of the keyfile path

---

## TODO

### Security Improvements

- **[MEDIUM] Comma-in-password CSV limitation**: `users_db.csv` is parsed with `split /\s*,\s*/, $_, 3`. Passwords containing commas are silently truncated. Switch to `Text::CSV` (or `Text::CSV_XS`) to support RFC 4180 quoting in both `generate_cmdb.pl` and `init_cluster_db.pl`.

- **[LOW] Add fingerprint pre-verification for bootstrap keyscan**: Provide an optional `--known-fingerprints=<file>` flag to `setup_ssh_keys`. If provided, compare `ssh-keyscan` output fingerprints against the file before installing into `known_hosts`. Document bootstrap TOFU risk and recommend running only on isolated networks.

- **[LOW] Add audit log entry for skipped nodes in `setup_ssh_keys` phase 5**: Replace bare `or next` with a small block that calls `audit_log('setup_node_skipped', machine => $node->{machine}, reason => 'cmd_failed')` so partially-bootstrapped nodes are visible in the audit trail.

- **[LOW] Zero sensitive strings in memory**: In `ClusterDB::new` and `get_passphrase`, consider overwriting passphrase variables before scope exit (e.g., `substr($pass, 0) = "\0" x length($pass)`). Relevant only for high-assurance environments; Perl does not guarantee memory zeroing on deallocation.

- **Make `$ssh_config_block` a module-level constant**: The SSH config block string is defined inside `setup_ssh_keys` and then duplicated in the removal regex inside `remove_ssh_keys`. Define it once at the top of the file as a constant; use it in both tasks (and simplify the removal regex to match the constant).

- **Extract `_atomic_write($path, $content_or_lines, $mode)`**: The pattern of (1) write to `File::Temp`, (2) `chmod` the temp file, (3) `rename` to target, (4) handle rename failure by unlinking temp, appears in 8+ places across the Rexfile. A helper would reduce each site to one call.

- **Replace inline remote Perl one-liners with heredoc temp scripts**: The Perl one-liners embedded as shell-quoted strings in `remove_ssh_keys` phases 3, 6, and 7 are hard to read and impossible to test in isolation. SCP a temp Perl script to the remote node and execute it with `perl <script>`, then delete the script. This makes the logic readable and auditable.

- **Consolidate CSV parsing into a shared utility**: Both `generate_cmdb.pl` and `init_cluster_db.pl` parse CSV files with nearly identical `split /\s*,\s*/, $_, 3` loops. Switching to `Text::CSV` with a shared helper would eliminate duplication and fix the comma-in-password edge case in both places simultaneously.
