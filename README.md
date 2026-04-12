# Cluster Management Repository

This repository manages a small Linux cluster using Rex (Perl), with a security-hardened workflow for **mesh SSH** — no node is special; every node can reach every other node via both password and key-based SSH.

Core design goals:
- Keep machine inventory in YAML files under cmdb/ (networks and optional MAC data only)
- Keep secrets (usernames, passwords, key material) in an encrypted SQLite database under createdatabase/
- Use bootstrap mode only for first-time access and key deployment
- Use key-based SSH for all normal operations (operational mode)
- All mutating operations produce timestamped audit log entries

**AI Disclaimer:**
This project started as a manual Rex file configuration, and relied heavily on AI additions (mostly via Claude) to refine security measures. In the process, I found that the AI would hallucinate DISA-STIG rules, generate bloatware and at some point even switched to Python (lolz) for tasks. Still the code generation for what I wanted to do (whether the code is actually doing it is a separate issue), was way faster than if I had written the code myself. Manual editing and review is far from complete at the time of this writing (April 12th 2026), so caveat emptor. If you decide to enter the chamber of AI horrors, would very much appreciate feedback or PRs. Having the ability to manage small networks e.g. in homelabs or small research laboratories in a secure manner is a valuable task,and the value of the task justifies the AI bootstrap (IMHO).

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
- `detect_admin` — identify the admin machine by matching local IPs to CMDB (assumes the machine executing the script is the admin node)
- `tcp_pinger` — create a Net::Ping TCP prober on port 22
- `resolve_targets` — resolve `--group`/`--machine` parameters into a target list
- `validate_name` — input validation against shell injection
- `cluster_db` / `get_credential` — lazy-connected encrypted database access
- `ensure_agent_loaded` — load the admin cluster key into ssh-agent via SSH_ASKPASS
- `bootstrap_via_askpass` / `bootstrap_run_or_warn` / `bootstrap_capturex` — run commands with password via SSH_ASKPASS + 0400 tempfile
- `generate_load_cluster_key_script` — generate the node-local key loader script
- `ensure_io_interface` / `cleanup_io_interface` / `get_mac_for_ip` — IO::Interface helpers for MAC discovery (prefers `apt-get` GPG-signed packages on remote nodes for DISA-STIG compliance; falls back to `cpan` temp install only on admin/perlbrew)
- And other utilities (`command_exists`, `kh_key`, `run_or_warn`, `shell_quote`, `generate_passphrase`, `bootstrap_remote_mktemp`, `all_networks`)

Loaded via `use FindBin qw($Bin); use lib "$Bin/.."; use ClusterSSHHelpers;` and configured with `ClusterSSHHelpers::init(...)` at startup.

### cluster_ssh_setup/Rexfile
Main Rex task file. Defines 15 tasks:

| Task | Description |
|------|-------------|
| `show_cmdb` | Display CMDB network/machine inventory (passwords always redacted) |
| `list_groups` | List defined inventory groups and members |
| `show_keys` | View SSH public key metadata (or full key for one machine) |
| `show_credentials` | View credential metadata (passwords always redacted) |
| `check_network` | TCP-probe node reachability on a named network |
| `refresh_known_hosts` | Rescan and update admin known_hosts for reachable nodes on a network |
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
  - Rexfile: main task automation (15 tasks, security-hardened)
- cmdb/
  - One YAML per machine
  - Contains only non-secret inventory data (network IPs, optional MAC addresses)
- createdatabase/
  - ClusterDB.pm: encrypted database module (AES-256-GCM)
  - init_cluster_db.pl: database initialization and import script
  - pubkeys/: staging area for SSH public key files to import into the encrypted DB. Place `<machine>.pub` files here before running `init_cluster_db.pl`; they are imported automatically. The directory is empty by default and is not required for normal CSV-driven workflows.
  - (git-ignored) cluster_keys.db — encrypted SQLite database
  - (git-ignored) .cluster_db.keyfile — master encryption key
- example_hpc_deployments/
  - README.md : Examples of provisioning of software for HPC pipelines
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

### Key assumptions

- **Admin node = executing machine**: `detect_admin` identifies the admin by matching the local machine's IP addresses (via `hostname -I`) against the CMDB network entries. The machine running the Rex tasks is always treated as the admin node.

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

---

## Adding New Nodes

There are two paths to add a new node to an existing cluster, depending on whether the node's SSH public key is already known.

### Path 1: CSV-driven (most common)

Use this when you have SSH access to the new node (via password) but its cluster keypair has not been generated yet. The `setup_ssh_keys` task will generate the keypair on the node and capture its passphrase.

**1) Add rows to the CSV files**

Append the new node to `system_db_setup/users_db.csv`:

```
node-delta,clusteradmin,FakeP@ssw0rd-D4
```

Append one row per network to `system_db_setup/networks_db.csv`:

```
labnet,node-delta,10.20.30.14
```

**2) Regenerate CMDB YAMLs**

```
perl system_db_setup/generate_cmdb.pl
```

This creates `cmdb/node-delta.yml` with its network IPs. Existing YAML files are regenerated with current CSV data; any previously stored MAC addresses are preserved.

**3) Import the new credential into the encrypted DB**

```
perl createdatabase/init_cluster_db.pl \
  --keyfile createdatabase/.cluster_db.keyfile \
  --users-csv system_db_setup/users_db.csv
```

The DB uses upsert logic — existing credentials are updated (with `rotated_at` timestamp), new ones are inserted. No data is lost.

**4) Run setup (no `--rekey` needed)**

```
cd cluster_ssh_setup
CLUSTER_DB_KEY="$(cat ../createdatabase/.cluster_db.keyfile)" \
rex setup_ssh_keys --network=labnet --bootstrap=1
```

This is fully incremental:
- Phase 5 generates a keypair only on `node-delta` (existing nodes already have keys and are skipped)
- Phase 5 collects public keys from **all** reachable nodes (new and existing)
- Phase 6 adds `node-delta`'s key to every existing node's `authorized_keys`, and adds all existing keys to `node-delta`'s `authorized_keys`; keys already present are not duplicated
- Phases 7–9 (known_hosts, ssh/config, /etc/hosts) are all idempotent — they skip entries that already exist

To target only the new node (avoids probing all nodes):

```
CLUSTER_DB_KEY="$(cat ../createdatabase/.cluster_db.keyfile)" \
rex setup_ssh_keys --network=labnet --bootstrap=1 --machine=node-delta
```

Note: with `--machine`, only `node-delta` receives peer keys. After this, run the full command (without `--machine`) once so that existing nodes pick up `node-delta`'s key in their `authorized_keys` and `known_hosts`.

### Path 2: Pre-staged public key via `pubkeys/` (two-stage)

Use this when you already have the node's SSH public key (e.g. exported from another system, or copied manually) and want to import it into the encrypted DB before running bootstrap.

**The `createdatabase/pubkeys/` directory**

This directory is a staging area for SSH public key files. Each file must:
- Be named `<machine-name>.pub` (e.g. `node-delta.pub`)
- Contain a standard SSH public key line: `<key-type> <base64-key> [comment]`

The directory is empty by default. Place `.pub` files here before running `init_cluster_db.pl`; they are imported automatically.

**1) Place the public key file**

```
cp /path/to/node-delta-key.pub createdatabase/pubkeys/node-delta.pub
```

**2) Add rows to the CSV files** (same as Path 1, steps 1–2)

```
# Append to users_db.csv and networks_db.csv, then:
perl system_db_setup/generate_cmdb.pl
```

**3) Import everything into the encrypted DB**

```
perl createdatabase/init_cluster_db.pl \
  --keyfile createdatabase/.cluster_db.keyfile \
  --users-csv system_db_setup/users_db.csv
```

This imports the `.pub` file from `pubkeys/` (storing the key encrypted with its fingerprint) **and** the credential from the CSV, in a single run.

To import `.pub` files from a different directory, pass `--import <dir>`:

```
perl createdatabase/init_cluster_db.pl \
  --keyfile createdatabase/.cluster_db.keyfile \
  --import /path/to/other/pubkeys
```

**4) Run setup** (same as Path 1, step 4)

The key imported via `pubkeys/` is stored in the DB for auditing and display (`rex show_keys`). The `setup_ssh_keys` task still generates the on-node keypair during bootstrap — the pre-imported key does not replace that step. Pre-staging is useful when you want key metadata in the DB before the node is reachable.

### When to use `--rekey=1`

The `--rekey` flag is **not** needed for adding new nodes. It is only needed when:
- A node's keypair was generated before the encrypted DB was available, so its passphrase was never captured
- You want to force key rotation on existing nodes (generates a fresh keypair and captures the new passphrase)

```
# Rekey a single node:
CLUSTER_DB_KEY="$(cat ../createdatabase/.cluster_db.keyfile)" \
rex setup_ssh_keys --network=labnet --bootstrap=1 --rekey=1 --machine=node-beta

# Rekey all nodes:
CLUSTER_DB_KEY="$(cat ../createdatabase/.cluster_db.keyfile)" \
rex setup_ssh_keys --network=labnet --bootstrap=1 --rekey=1
```

`--rekey=1` removes the existing keypair and passphrase store files on the target node(s), then regenerates everything from scratch.

## Operational Notes

- Keep `createdatabase/.cluster_db.keyfile` off version control and in a secured, backed-up location
- Rotate credentials by updating `users_db.csv` and re-running `init_cluster_db.pl`
- Re-bootstrap only when needed (new nodes, key rotation, trust reset)
- For strict environments, ensure sudoers is configured as described in the prerequisites section
- The keyfile can also be passed via `CLUSTER_DB_KEY` env var instead of the keyfile path

---

---
---

## Blast Radius Analysis

This section analyses what an attacker gains — and what remains protected — if a single cluster node is compromised. Two scenarios are considered: compromise of a non-admin (worker) node, and compromise of the admin node.

### Definitions

| Term | Meaning |
|------|---------|
| **Admin node** | The machine running Rex tasks. Holds the encrypted database, the master keyfile, and the admin keypair. |
| **Worker node** | Any non-admin node in the cluster . Holds only its own keypair and the local passphrase store. |
| **Mesh credential** | The credentials (username + password) for each node, stored encrypted in `cluster_keys.db` on the admin. |
| **Node-local passphrase store** | Three files on each worker: `.cluster_node_keyfile` (0400), `.cluster_node_pp` (0400), `load_cluster_key.pl` (0500). Together they allow the node to decrypt its own SSH key passphrase. |

### Scenario 1: Compromised Non-Admin (Worker) Node

**Attacker gains access to one worker node** (e.g. via local privilege escalation, physical access, or an application-level exploit).

#### What the attacker obtains

| Asset | Location | Protection | Attacker access |
|-------|----------|------------|-----------------|
| Node's SSH private key | `~/.ssh/id_ecdsa_p521_cluster` | 0400, passphrase-protected | Has the file; can extract passphrase from local store (see below) |
| Node-local passphrase store | `~/.ssh/.cluster_node_keyfile` + `~/.ssh/.cluster_node_pp` | 0400, AES-256-CBC PBKDF2-SHA256 600k iter | Both files are on the same node — attacker can decrypt the passphrase using `openssl enc -d` with the keyfile |
| Node's `authorized_keys` | `~/.ssh/authorized_keys` | 0600 | Public keys of all peers + admin (public key material only — no secrets) |
| Node's `known_hosts` | `~/.ssh/known_hosts` | 0600 | Host key fingerprints for all cluster nodes |
| Node's `~/.ssh/config` | `~/.ssh/config` | 0600 | Cluster `IdentityFile` and `StrictHostKeyChecking` settings |

#### Blast radius from a compromised worker

| Impact | Scope | Details |
|--------|-------|---------|
| **Full SSH access as cluster user to every other node** | All nodes on the same network | The compromised node's key is in every peer's `authorized_keys`. The attacker can unlock the private key using the local passphrase store and reach any peer node — **this is the primary blast radius**. |
| **SSH access to the admin node** | Admin node | The compromised node's key is also in the admin's `authorized_keys`. The attacker reaches the admin as the cluster user. |
| **known_hosts intelligence** | Informational | IP addresses and host key fingerprints for all cluster nodes are exposed, aiding lateral movement. |
| **Network knowledge** | Informational | `~/.ssh/config` and `/etc/hosts` entries reveal all cluster node aliases and IPs. |

#### What the attacker does NOT obtain from a worker

| Asset | Why it is safe |
|-------|---------------|
| **Other nodes' private keys** | Private keys are generated on-device and never leave their origin node. |
| **Other nodes' passphrases** | Each node's passphrase store uses a unique keyfile; compromising one node's keyfile cannot decrypt another's. |
| **Encrypted database (`cluster_keys.db`)** | Exists only on the admin node. |
| **Master keyfile (`.cluster_db.keyfile`)** | Exists only on the admin node. |
| **Plaintext passwords** | Passwords are never stored on worker nodes. They are used only during bootstrap (via SSH_ASKPASS tempfile) and are not persisted. |
| **Admin's private key** | Only the admin's public key is deployed to workers (via `ssh-copy-id`). The private key stays on the admin. |

#### Mitigation and containment

1. **Revoke the compromised node's key from all peers**: Run `remove_ssh_keys` with `--machine=<compromised-node>`, then re-run `setup_ssh_keys --rekey=1 --machine=<compromised-node>` after the node is re-imaged or remediated.
2. **Rotate all peer keys as a precaution**: If the attacker had time for lateral movement, rekey all nodes with `setup_ssh_keys --rekey=1` after forensic assessment.
3. **Audit `logs/audit.log`**: Check for unexpected `setup_ssh_keys` or `remove_ssh_keys` activity.
4. **Network-level isolation**: The blast radius is limited to nodes on the same network (e.g. WirA). An attacker on a WirA-only node cannot reach WirB-only nodes unless the compromised user account has keys for both networks.

### Scenario 2: Compromised Admin Node

**Attacker gains access to the admin node**  — the single point of control for the cluster.

#### What the attacker obtains

| Asset | Location | Protection | Attacker access |
|-------|----------|------------|-----------------|
| Admin's SSH private key | `~/.ssh/id_ecdsa_p521_cluster` | 0400, passphrase-protected | Has the file; passphrase is in the encrypted DB (see next row) |
| Encrypted database | `createdatabase/cluster_keys.db` | AES-256-GCM, PBKDF2-SHA256 600k iter | Accessible if the attacker also obtains the keyfile |
| Master keyfile | `createdatabase/.cluster_db.keyfile` | 0400 | On the same machine — attacker can read it with the cluster user's privileges |
| **All passwords (decryptable)** | In `cluster_keys.db` | AES-256-GCM | With keyfile + DB, the attacker decrypts **every node's username and password** |
| **All SSH key passphrases (decryptable)** | In `cluster_keys.db` | AES-256-GCM | With keyfile + DB, the attacker decrypts **every node's SSH key passphrase** — even for nodes the attacker has never touched |
| **All public keys + fingerprints** | In `cluster_keys.db` | AES-256-GCM | Full inventory of all cluster SSH public keys |
| Admin's `authorized_keys` | `~/.ssh/authorized_keys` | 0600 | Public keys of all worker nodes |
| Admin's `known_hosts` | `~/.ssh/known_hosts` | 0600 | Host key fingerprints for all cluster nodes |
| CMDB YAML files | `cmdb/*.yml` | Plaintext | All node IPs and MAC addresses across all networks |
| Audit log | `logs/audit.log` | 0600 | Full history of all mutating operations — reveals cluster topology and key rotation history |
| Source code | Repository root | Plaintext | The Rexfile, helpers, and DB module — reveals security mechanisms and aids targeted attacks |

#### Blast radius from a compromised admin

| Impact | Scope | Details |
|--------|-------|---------|
| **Full SSH access to every node on every network** | All nodes, all networks | The admin's key is in every node's `authorized_keys`. The attacker can SSH to any node as the cluster user without needing passwords. |
| **Password-based SSH access to every node** | All nodes, all networks | Decrypted passwords enable `sshpass`-based access even if key-based auth is revoked. |
| **Impersonation of any node** | Any node-to-node path | The attacker has every node's SSH key passphrase. While the private keys are on the nodes (not the admin), the attacker can SSH to a node using the admin key, decrypt the node's passphrase store, and use the node's identity for further lateral movement. |
| **Complete cluster topology disclosure** | Informational | CMDB YAMLs reveal all IPs, networks, and MAC addresses. The audit log reveals the full operational history. |
| **Ability to re-bootstrap the entire cluster** | Destructive | The attacker can run `remove_ssh_keys` + `setup_ssh_keys` to rotate all keys to attacker-controlled values, permanently locking out the legitimate admin. |
| **Encrypted DB exfiltration** | Persistent | The keyfile + DB together enable offline decryption of all secrets even after the admin is recovered. The attacker retains access to passwords and passphrases indefinitely unless they are all rotated. |

#### What the attacker does NOT obtain directly from the admin

| Asset | Why |
|-------|-----|
| **Worker nodes' private keys** | Generated on-device, never transmitted to the admin. However, the attacker can reach each node via SSH and extract them indirectly. |

#### Mitigation and containment

1. **Rotate everything**: All node passwords, all SSH keypairs (`--rekey=1`), the master keyfile, and the database must be regenerated from a trusted machine.
2. **Re-image the admin node**: Assume rootkit persistence on the compromised admin.
3. **Rotate node-local passphrase stores**: After rekeying, the old passphrase stores on worker nodes are replaced. However, if the attacker accessed worker nodes during the breach window, those nodes should also be re-imaged.
4. **Change system-level passwords**: The passwords in `users_db.csv` are typically the OS login passwords for the cluster user. These must be changed on every node.
5. **Review audit logs**: Check `logs/audit.log` and system auth logs on all nodes for unauthorized access during the breach window.

### Summary: Comparative Blast Radius

| Dimension | Worker compromise | Admin compromise |
|-----------|-------------------|------------------|
| Nodes reachable via SSH | All peers on the same network + admin | All nodes on all networks |
| Passwords exposed | None | All (decryptable from DB) |
| Key passphrases exposed | Only the compromised node's | All (decryptable from DB) |
| Other nodes' private keys | Not directly accessible | Not directly — but reachable via SSH to each node |
| Lateral movement difficulty | Immediate (key is pre-authorized) | Immediate (key is pre-authorized everywhere) |
| Recovery effort | Revoke one key, rekey one node | Full cluster re-bootstrap, password rotation, potential re-imaging |
| Fundamental limitation | Inherent to full-mesh SSH — any authorized key reaches all peers | Single point of trust — DB + keyfile co-located on one machine |

### Architectural Observations

1. **Full mesh = full blast radius per network**: By design, every node's key is authorized on every other node. Compromising any one node grants immediate SSH access to all peers. This is the accepted trade-off of a mesh topology. The blast radius is bounded by network — a node with only WirA access cannot reach WirB-only nodes.

2. **The node-local passphrase store is security theater against root**: The `.cluster_node_keyfile` and `.cluster_node_pp` files are both owned by the same user on the same machine. A root-level attacker trivially decrypts the passphrase. The store's purpose is convenience (autonomous key loading) — not defense against local privilege escalation.

3. **Admin node is a single point of catastrophic failure**: The encrypted database, keyfile, credentials, and Rex automation are all co-located. Compromising the admin is equivalent to compromising the entire cluster. Mitigations include: hardware security modules (HSM) for the keyfile, MFA for admin access, network-level isolation of the admin node, and offline/encrypted backups of the keyfile separate from the database.

4. **Passwords persist after bootstrap**: Even after key-based SSH is established, the passwords remain in the encrypted DB. If the admin is compromised, these passwords enable password-based access even after all SSH keys are revoked. Consider deleting credentials from the DB after successful bootstrap (`$db->delete_credential(machine => $name)`) and relying exclusively on key-based auth.

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

### Blast-Radius Reduction (derived from Blast Radius Analysis)

- **[HIGH] Separate keyfile from encrypted DB — break admin single-point-of-failure**: Move `.cluster_db.keyfile` off the admin node entirely (e.g. USB hardware token, HSM, or a separate vault host). The admin should fetch the key at task-run time via a challenge (PIN, MFA) and hold it only in memory. This prevents an attacker who compromises the admin filesystem from decrypting the DB offline. Implementation: add a `--keyfile-cmd` option to `ClusterSSHHelpers::init()` that executes an external command (e.g. `gpg --decrypt keyfile.gpg`) instead of reading a plaintext file.

- **[HIGH] Purge passwords from DB after successful bootstrap**: Once key-based SSH is verified (via `validate_ssh_mesh`), delete plaintext credentials from `cluster_keys.db` (`$db->delete_credential(machine => $name)`). Passwords remaining in the DB after bootstrap serve no operational purpose but become a catastrophic asset if the admin is compromised. Add a `--purge-credentials` flag to `validate_ssh_mesh` that deletes credentials for all nodes that pass both key-based and password-based validation, with audit logging.

- **[HIGH] Disable password authentication cluster-wide after bootstrap**: After successful key distribution, deploy `PasswordAuthentication no` to each node's `/etc/ssh/sshd_config` (or a drop-in file) and reload `sshd`. This eliminates password-based lateral movement even if the admin DB is exfiltrated. Add a new Rex task `harden_sshd` that deploys the configuration and verifies key-based access still works before committing. Requires a sudoers entry for `sshd` reload.

- **[MEDIUM] Restrict admin `authorized_keys` to worker-to-admin traffic only**: Currently every worker node's key is authorized on the admin with no restrictions. Add `from="<ip-list>"` options to each key in the admin's `authorized_keys`, limiting each worker key to connections originating from that worker's known IPs. This prevents a stolen worker key from being used from an arbitrary host to reach the admin.

- **[MEDIUM] Add `command=` restrictions to cross-node `authorized_keys`**: Not all nodes need arbitrary shell access to each other. For nodes that only need to perform specific operations (e.g. file transfer, job submission), prepend `command="/usr/bin/rsync --server ..."` or `command="/usr/local/bin/allowed-cmd"` to the relevant `authorized_keys` entries. This limits what an attacker can do even after obtaining a peer's key.

- **[MEDIUM] Implement per-network key isolation**: Currently `setup_ssh_keys` deploys the same keypair identity across all networks. Generate a separate keypair per network per node (e.g. `id_ecdsa_p521_cluster_WirA`, `id_ecdsa_p521_cluster_WirB`). Cross-authorize only within the same network. This ensures that compromising a node on WirA does not grant access to WirB-only nodes even if the same user account is used, hardening the network boundary observed in the blast radius analysis.

- **[MEDIUM] Add intrusion-detection tripwires for key material**: Deploy a cron job or systemd timer on each node that periodically checks: (1) `~/.ssh/authorized_keys` has not been modified outside of Rex (compare SHA-256 against a signed manifest), (2) `~/.ssh/id_ecdsa_p521_cluster.pub` fingerprint matches the encrypted DB record, (3) `~/.ssh/config` has not been tampered with. Report anomalies via syslog or a webhook. Add a Rex task `deploy_tripwire` that installs and configures the monitor.

- **[MEDIUM] Rate-limit and alert on failed SSH attempts cluster-wide**: Configure `fail2ban` or equivalent on every node to jail IPs after repeated SSH failures. Add a Rex task `deploy_fail2ban` that installs the package (via `apt`, DISA-STIG-compliant), deploys a cluster-specific jail config targeting the cluster user, and verifies the service is active. This slows brute-force lateral movement from a compromised node.

- **[LOW] Enforce key expiry and automated rotation**: Add a `--max-key-age=<days>` parameter to `validate_ssh_mesh`. For each node whose key is older than the threshold (tracked via `created_at` in the DB), emit a warning or automatically trigger `--rekey=1`. This limits the window of exposure if a key is silently compromised.

- **[LOW] Encrypt CMDB YAML files at rest**: CMDB YAMLs contain IP addresses and MAC addresses — network topology that aids targeted attacks. Encrypt them with the same AES-256-GCM scheme used by ClusterDB, decrypting only at Rex runtime. Alternatively, move network data into `cluster_keys.db` alongside credentials so all sensitive data shares a single encryption boundary.

- **[LOW] Add remote audit log forwarding**: Currently `logs/audit.log` exists only on the admin node. An attacker who compromises the admin can tamper with or delete it. Forward audit entries to a remote syslog server or append-only log service in real-time so that a tamper-evident copy survives admin compromise.
