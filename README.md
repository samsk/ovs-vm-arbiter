# ovs-vm-arbiter

**ovs-vm-arbiter** helps when you run **Proxmox** and **Open vSwitch** on several machines and stretch **L2 over tunnels** (VXLAN-style). In that world, ARP and broadcast can turn into **ARP who-has storms** and wide flooding. This tool runs **one daemon per hypervisor**: it figures out **which IP belongs on which bridge and VLAN**, **tells the other nodes**, and **answers ARP** in a controlled way so traffic stays saner than “flood everything and hope.”

It is **not** a full SDN product—more like **focused glue** for people who already like their OVS + Proxmox setup and want **less broadcast pain** without adopting OVN, EVPN, or Proxmox SDN wholesale.

**You** are still responsible for **how ARP and broadcast move on the tunnels**: e.g. **OpenFlow rules** on tunnel ports, **OVS port flags** (`protected`, `no-learning`, or whatever matches your pipeline), VLAN maps, and upstream filters. This daemon coordinates **answers** and **state** across nodes; it does **not** replace a deliberate **underlay/overlay policy** for what may flood where.

**Status:** **Beta**: CLI, mesh format, and behaviour may still change. The authors already run it **in production without problems**; still **try it in your staging or lab** before you rely on it everywhere.

## Quick start

Daemon mode needs **`--service`** (systemd passes it for you). Otherwise you must use a **`--list-*`** action, **`--test`**, or **`--version`**—bare tuning flags alone exit with an error so you do not start the long-lived process by mistake.

```bash
ovs-vm-arbiter.py --service --broadcast-iface dcnet --bridges vmbr0
# one-shot / diagnostics (no --service)
ovs-vm-arbiter.py --list-neigh              # neighbours and exit
ovs-vm-arbiter.py --list-fdb                # ovs FDB and exit
ovs-vm-arbiter.py --list-pve-db             # parsed PVE instances only
ovs-vm-arbiter.py --list-vlans              # VLAN scope + assigned IPs
ovs-vm-arbiter.py --list-remote             # active mesh peers
ovs-vm-arbiter.py --version                 # zip build time or "source"
ovs-vm-arbiter.py --test                    # run tests and exit
```

## Daemon single instance

**`--service`** selects long-lived daemon mode. Without it, the process only runs if you passed at least one **list** flag (`--list-db`, `--list-neigh`, …), **`--test`**, or **`--version`**; anything else (e.g. only `--bridges` / `--debug`) is rejected with a short usage error.

In normal (non–list-mode) operation the process takes an exclusive lock on `<state-dir>/ovs-vm-arbiter.lock`. A second instance exits with an error if the lock is held.

## Key options


| Option                                     | Default                        | Meaning                                                                                                                                                                                             |
| ------------------------------------------ | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--service`                                | off                            | Run as long-lived daemon; **required** for that mode unless using `--list-*` / `--test` / `--version`                                                                                                |
| `--bridges`                                | vmbr0                          | OVS bridges to monitor                                                                                                                                                                              |
| `--db-path`                                | /var/lib/pve-cluster/config.db | Proxmox config DB (read-only)                                                                                                                                                                       |
| `--state-dir`                              | /var/lib/ovs-vm-arbiter        | State JSON dir                                                                                                                                                                                      |
| `--port`                                   | 9876                           | UDP mesh port                                                                                                                                                                                       |
| `--node`                                   | auto                           | Node ID (IP or hostname); mesh prefers `--broadcast-iface` IP when unset                                                                                                                            |
| `--broadcast-iface`                        | first bridge                   | Interface for UDP broadcast (`SO_BINDTODEVICE`)                                                                                                                                                     |
| `--mesh-ttl`                               | 990                            | Entry TTL (sec); no activity → entry marked expired                                                                                                                                                 |
| `--mesh-interval`                          | 3                              | Seconds between mesh send attempts after change                                                                                                                                                     |
| `--mesh-send-on-change`                    | on                             | Only send when entries changed                                                                                                                                                                      |
| `--mesh-send-max-interval`                 | 99                             | Max seconds without mesh send when unchanged (0=off)                                                                                                                                                |
| `--mesh-keepalive-interval`                | 59                             | Keepalive when 0 entries (0=off)                                                                                                                                                                    |
| `--mesh-silence-restart`                   | on                             | Warn and restart mesh if no peer message for 10×keepalive; `--no-mesh-silence-restart` to disable                                                                                                   |
| `--mesh-sign-key` / `--mesh-sign-key-file` | none                           | Optional HMAC-SHA256 for mesh payloads                                                                                                                                                              |
| `--of-priority`                            | 999                            | OpenFlow mirror flow priority                                                                                                                                                                       |
| `--arp-reply`                              | on                             | Answer ARP who-has for known IPs (packet-out path)                                                                                                                                                  |
| `--arp-reinject`                           | off                            | Re-inject unknown ARP who-has to flood (`--arp-reinject` to enable)                                                                                                                                 |
| `--arp-responder`                          | off                            | Install per-IP OpenFlow ARP responder flows (`--arp-responder` to enable)                                                                                                                           |
| `--snoop-vlans`                            | all                            | Snoop only on these VLANs (e.g. `20,30-50,99`); 0 = untagged                                                                                                                                        |
| `--no-snoop-vlans`                         | none                           | Do not snoop on these VLANs (list/ranges)                                                                                                                                                           |
| `--arp-reply-strict-vlan`                  | on                             | Reply / responder only when request vlan matches snooped vlan (and optionally untagged if `--arp-reply-no-vlan`). `**--no-arp-reply-strict-vlan`:** VLAN/FDB caution in *Strict / no-vlan* section. |
| `--arp-reply-no-vlan`                      | off                            | Also reply to untagged ARP requests (packet-out only; **ignored for arp-responder**). **VLAN/FDB caution** under *Strict / no-vlan / packet-out details*.                                           |
| `--arp-reply-remote-vlan`                  | none                           | Tunnel VLAN (inter-host/VXLAN): match/reply for **remote** IPs on this VLAN only; local IPs use real vlan                                                                                           |
| `--arp-reply-localize-vlan`                | on                             | When strict vlan is on, treat remote entries whose vlan is “local” like local (use entry vlan instead of remote tunnel vlan where applicable)                                                       |
| `--tunnel-vlans` / `--tunnel-vlan`         | none                           | Shortcut: no-snoop these VLANs (so remote traffic is not attributed to local node); if single VLAN also set `arp-reply-remote-vlan` (multiple → warn)                                               |
| `--arp-reply-set-register`                 | 0                              | On ARP reply packet-out, load value into NXM_NX_REG0[] (0=off); e.g. 1 for downstream flow matching                                                                                                 |
| `--arp-responder-vlan-register`            | unset                          | Match VLAN by NXM_NX_REG[]=vlan (N=0-7) instead of vlan_tci; use when OVS doesn't see 802.1Q                                                                                                        |
| `--arp-responder-learning`                 | on                             | Responder uses `learn()` so the bridge learns the response MAC on the node port                                                                                                                     |
| `--exclude-subnet`                         | none                           | Exclude CIDR(s) from snooping (repeatable)                                                                                                                                                          |
| `--ping-neighbours`                        | 0 (off)                        | Ping mesh neighbours from host every SEC; native ICMP, no reply wait; random order, 0–50 ms between pings                                                                                           |


## Technical overview

**Quick start**, **daemon lock**, and **key options** above are enough to run the tool. Read this section for **mechanics and rationale** in one place; **everything after** expands mesh, ARP, Proxmox DB, metrics, and code layout topic by topic.

### What it does (mechanics)

- **Per-hypervisor daemon** on **Proxmox + OVS** (typical use: **VXLAN** or similar between host bridges).
- **Learns** IP→MAC per **(bridge, VLAN)** from **ARP/DHCP snooping** and read-only Proxmox `**config.db`** (VM/LXC placement).
- **Replicates** ownership to peers over a **UDP mesh** (small JSON payloads).
- **Handles ARP** via **mirrored packets** (userspace) and, optionally, **OpenFlow per-IP responder** flows in OVS so **who-has** does not flood the whole overlay when the design allows.
- **Entry point:** `ovs-vm-arbiter.py` or `python -m src.main`. **All configuration is CLI flags**—no separate config file in the shipped layout. **Daemon:** pass **`--service`** (see *Quick start* / *Daemon single instance*).

### Why this approach (vs “real” SDN)

Full **Proxmox SDN**, **BGP/EVPN**, **OVS OVN**, and similar stacks can be **rigid** (you must fit their model of segments, controllers, and routing) or **heavy to operate** (many moving parts, day-two debugging across layers). **ovs-vm-arbiter** is a **small, boring alternative** for clusters that already run **OVS on Linux bridges** and **Proxmox**: it **reuses** what you already have—`config.db` for “which MAC lives on which bridge/tag”, OVS for ports and OpenFlow—instead of introducing another full network control plane.

Roughly, it aims for **configure once and leave it running**: a daemon per hypervisor that **learns** IP→MAC→(bridge, VLAN) from **snooped** ARP/DHCP and **shares** it with peers over a **lightweight UDP mesh**, so each node can answer or steer **ARP** with the right **VXLAN / tunnel context** without flooding the whole L2 domain. **Mirrored** ARP/DHCP to userspace plus optional **datapath ARP responder** flows reduce blind flooding and pointless who-has storms where the design allows. **Ownership** and **migration** are handled with **snoop + mesh timing**, optional **Proxmox DB confirmation**, and FDB invalidation hooks—not with a separate EVPN route reflector or OVN northbound API.

It is a good fit when **VXLAN (or similar)** is used to **connect host bridges** across hypervisors while you still want to **keep ARP and broadcast traffic constrained**: coordinated IP→MAC state means fewer blind **who-has** floods and less **broadcast** churn on the overlay than “pure flood and learn” across the tunnel—each node can resolve and forward with **correct port / VLAN / tunnel context** instead of treating the fabric as one giant flat broadcast domain.

That is **not** a feature-complete replacement for every SDN story (no built-in L3 VPN, no generic BGP policy engine, no OVN logical switches). It is **opinionated glue**: good when you want **fast, coordinated L2/L3 edge behaviour on vmbr + VXLAN-style tunnels** without adopting an entire parallel network stack.

## Mesh transport (separate channel from tenant VXLAN)

The UDP mesh (`--port`, `--broadcast-iface`) is the **control plane** between hypervisors: small JSON payloads that replicate IP→MAC ownership. It should **not** ride on the **same VXLAN / overlay network** that this tool is helping you **manage** (customer bridges, tunnel VLAN, inter-host VM traffic).

**Why:** Mesh and data-plane share the same failure domain if you collapse them—filters, congestion, or ARP/broadcast policy on the **tenant** tunnel can **starve or break** mesh at the worst time. You also avoid **tight coupling**: the arbiter is not meant to depend on the overlay it optimizes. Prefer a **separate** path: **management VLAN**, **corosync / cluster network**, **dedicated physical** link between nodes, or any **stable L3/L2** that is **not** the exclusive VM VXLAN underlay you tune for restricted ARP/broadcast. Point `**--broadcast-iface`** at an interface on that **side channel** so mesh packets never compete with the fabric they configure.

## Mesh signing and receive limits

### Security model (UDP mesh)

Mesh traffic is **UDP broadcast** (or directed broadcast) on `port` / `broadcast_iface`. **Without a signing key**, any host that can reach that socket can inject JSON and influence neighbours’ IP→MAC state—same broadcast domain risk as any unauthenticated control plane on L2.

With `**--mesh-sign-key` or `--mesh-sign-key-file`**, outgoing payloads get an `**_sign**` field: **HMAC-SHA256** over the canonical JSON. On receive, if a key is configured, the **raw datagram is verified before parsing**; bad or missing signatures are **dropped**. That gives **shared-secret authentication** of payload integrity: only peers that know the key produce valid messages.

**Not provided:** **Encryption** (payload is still readable on the wire), **per-peer identities** beyond the shared secret, or **replay protection** beyond your existing mesh dedup/TTL behaviour. Treat the key like a cluster password: high entropy, file permissions `0600`, never in shell history for production.

**Uniform rollout:** Every node in the mesh must use the **same** key once signing is enabled. A node that has a key **rejects** unsigned or wrongly signed packets; a node **without** a key **does not** verify. Plan a cutover where **all** hypervisors enable signing together (or isolate old/new groups by VLAN/firewall until aligned).

### Setup (CLI)

Create a **one-line** key file with mode `0600` (adjust the path; use the same path on every node when using a shared mount):

```bash
umask 077 && openssl rand -hex 32 > /path/to/ovs-vm-arbiter-mesh.key
```

Then on **each** node, pass the same secret either:

- `**--mesh-sign-key SECRET`** (inline; convenient for tests, easy to leak in `ps`), or
- `**--mesh-sign-key-file /path/to/keyfile**` (preferred): point at the file above; first line only is read, stripped; UTF-8 text becomes the key bytes.

If both `--mesh-sign-key-file` and `--mesh-sign-key` are set, **file wins** when it exists and the first line is non-empty; otherwise the inline `**--mesh-sign-key`** value is used.

Restart the daemon after changing keys so send and recv agree.

### Central key on Proxmox + Ceph (CephFS)

To avoid copying secrets by hand and to keep a **single source of truth**:

1. Create a **CephFS** (or other cluster-wide) subtree that **every** Proxmox node mounts—typical pattern: add a **CephFS** storage in the Proxmox UI and use the mount point Proxmox assigns (often under `/mnt/pve/<storage-name>/` or your chosen path).
2. Store **one file** there, e.g. `/mnt/pve/cephfs-common/security/ovs-vm-arbiter-mesh.key`, using the same command as above with that path (`umask 077 && openssl rand -hex 32 > …`), owner root or the service user.
3. Point **the same `--mesh-sign-key-file`** path on **all** nodes (adjust only if mount paths differ per host—prefer identical mount names via `/etc/fstab` or Proxmox storage so the path is stable).

CephFS gives **consistent visibility** across the cluster: update the file once (carefully, with rolling restarts) instead of editing many host-local copies. **Do not** commit this file to git or bake it into VM templates in the clear.

### Receive limits (abuse bounds)

Regardless of signing, `**--mesh-recv-max-size`**, `--mesh-recv-max-keys`, `--mesh-recv-max-depth`, and `--mesh-recv-max-key-len`** cap JSON size and shape so a peer cannot exhaust memory with a huge payload (defaults suit typical clusters).

## ARP refresh (FDB)

When `**--arp-refresh`** is on, a background `**ArpRefresher`** thread sends ARP via the correct OVS port to refresh MACs in the FDB for active peers. Related: `--arp-refresh-interval` (base interval, ± jitter), `--arp-peer-timeout`, `--arp-peer-limit`, `--arp-global-limit`. `**--list-refreshers**` dumps peer state (LOCAL, REMOTE, VLAN, PORT, TTL).

## Ping neighbours (optional)

When `--ping-neighbours SEC` is set (SEC > 0), a daemon thread pings every mesh neighbour (nodes from `get_node_last_seen()` except self) every SEC seconds. Uses a raw ICMP socket (no subprocess); sends one echo request per neighbour in random order with **0–50 ms** random delay between pings; does not wait for replies. Requires CAP_NET_RAW; if the raw socket cannot be opened, ping is disabled with a warning.

## Mesh silence watchdog

If at least one peer message was ever received and then no mesh message is received for **10 × mesh_keepalive_interval** (default 590s with keepalive 59), the process logs a warning and **restarts the mesh** (socket + recv thread). Single-node (no peers) never triggers. Disable with `--no-mesh-silence-restart`.

## Snoop silence watchdog

After at least one snooped packet, if **no IP is snooped** for `**--snoop-silence-warn-after-sec`** (default 3600), the daemon logs **WARNING** and repeats every `**--snoop-silence-warn-interval-sec`** (default 3600; `0` = warn once per idle episode). That is often **normal on idle nodes** with no guests. If silence reaches `**--snoop-silence-restart-sec`** (default 86400), it logs **ERROR** and **exits** so the service supervisor can restart. Set restart to `**0`** for warnings only, no restart.

## Expiry and cleanup

- **Expiry:** Entries with no activity for `mesh_ttl` seconds are marked expired (`entry.expired = now`). They stop being used for ARP/mesh but stay in the in-memory store.
- **Cleanup:** Entries that have been expired for at least `expired_entry_cleanup_sec` seconds are **removed** from the store (and thus from the next state save). Default 50400 (14h). Set to `0` to disable cleanup.
- **Timing:** `expiry_check_interval` (default 30s) controls how often expire and cleanup run. `expiry_grace_sec` (default 60) is the grace period after start before first expiry.


| Option                              | Default     | Meaning                                                        |
| ----------------------------------- | ----------- | -------------------------------------------------------------- |
| `--expiry-grace-sec`                | 60          | Grace before first expiry run                                  |
| `--expired-entry-cleanup-sec`       | 50400 (14h) | Remove expired entries after this many sec (0=off)             |
| `--expiry-check-interval`           | 30          | Interval for expire + cleanup                                  |
| `--main-loop-interval`              | 2           | Main loop sleep                                                |
| `--save-interval`                   | 13          | How often `state.json` is written                              |
| `--snoop-silence-warn-after-sec`    | 3600        | First WARNING if no IP snooped this long; 0=off (idle node OK) |
| `--snoop-silence-warn-interval-sec` | 3600        | Repeat WARNING while silent; 0=once                            |
| `--snoop-silence-restart-sec`       | 86400       | ERROR+restart if still no snoop; 0=off                         |


## State and paths

- **State file:** `<state-dir>/state.json`; saved every `save_interval` (default 13s). Keys: `"<ip>|<bridge>|<vlan>"`.
- **Auxiliary:** `mesh_last_seen.json`, `arp_refresh_peers.json` (when ARP refresh is used).
- **Load:** If `--no-load-state`, state is not loaded. Else if state is older than `load_state_max_age_sec` (default 60), load is skipped and overwritten. Entries without `node` are dropped on load.
- **Registry:** `/run/ovs-flow-registry` (flow cookie; shared with ovs-flow-mgr), resolved via `/usr/local/lib/ovs-flow-lib.sh` when present.

## Proxmox `config.db` (how, why, trade-offs)

### How we read it

- **Path:** Default `/var/lib/pve-cluster/config.db` (`--db-path`). This is the **pmxcfs** SQLite replica of the cluster configuration (same logical data Proxmox uses for VM/LXC definitions).
- **Mechanism:** The file is opened **read-only** (SQLite URI `file:…?mode=ro`, short timeout). The `**tree`** table (`inode`, `parent`, `name`, `data`, …) is queried, inode paths are reconstructed, `*.conf` files under `…/qemu-server/` and `…/lxc/` are selected, and each body is parsed line-by-line for `netN:` lines.
- **Parsed fields:** Per NIC line: `bridge=`, optional `tag=` (VLAN), QEMU `virtio=` / `mac=`, LXC `hwaddr=`, LXC static `ip=` when present, plus top-level `tags:` for tags. Results populate a MAC → `InstanceInfo` map (`InstanceStore`).
- **Cluster scope:** Rows under `nodes/<nodename>/…` are associated with that node. **Local** instances are those where `<nodename>` matches this host’s name (`socket.gethostname()`). With `**--verify-remote-migration`**, the watcher also records MAC → owning node for cluster-wide checks.
- **Polling:** Reads are **debounced** (`--db-debounce-sec`), **periodically** forced (`--db-periodic-sec`), and optionally **skipped** when `mtime` is unchanged (`--db-stat-optimization`). `**poll(force_refresh=True)`** (used for migration confirmation) bypasses the mtime shortcut but is still **rate-limited** by `--db-force-debounce-sec`. If the file is missing or locked, the watcher **retains the last successful store** and retries (`--db-retry-sec`), logging at `--db-unavail-log-sec` intervals.

### Why use it (not only snoop)

- **Authoritative NIC identity:** Snooping sees traffic; the DB says which VM/LXC owns which MAC, bridge, and tag—needed for **config IP injection** (LXC), **migration verification** (MAC present under `nodes/<this-node>/`), and optional **remote** verification against cluster ownership.
- **No REST API or tokens:** Read-only local file access; no separate service dependency for discovery.
- **Aligned with Proxmox:** Same source as the UI and `qm`/`pct`; ownership checks match what the cluster believes.

### Pros

- Simple operations model: **read-only** access cannot corrupt cluster state.
- Works **offline** from the HTTP API (only filesystem access to the replica).
- **Replicated** across the cluster like any other pmxcfs file—each node has a local copy to read.

### Caveats

- **Must match a real Proxmox node layout:** The `tree` schema and paths are **Proxmox-specific**; arbitrary SQLite databases will not work.
- **Hostname vs `nodes/` name:** Local configs are selected when `nodes/<name>/` equals `**gethostname()`**. If the directory name and system hostname differ (short name vs FQDN, custom casing), **local instances may appear empty** until names align.
- **Staleness vs load:** Debounce and **mtime** optimization can delay seeing edits until the next periodic read or a **forced** refresh (e.g. migration path). Tighten debounce or disable `db-stat-optimization` if you need faster convergence.
- **DB temporarily unreadable:** Locks, permissions, or a missing file leave the watcher on **cached** data; migration confirmation and inject can be wrong until reads succeed again.
- **Parsing limits:** Only **standard `netN:`** lines are understood; exotic NIC definitions may not appear in `InstanceStore` until expressed in that form.
- **Not a substitute for snoop:** The DB does not carry live ARP or per-VLAN runtime state—that still comes from the packet path and mesh.

### Why not `/etc/pve` (mounted configs) — freezes and design

Proxmox exposes cluster config under `**/etc/pve`**, which is a **FUSE** filesystem (**pmxcfs**): every `open`, `read`, `readdir`, and `stat` on those paths goes through the FUSE daemon and can **block** while pmxcfs talks to corosync, waits on locks, or replays the journal.

**Why that is a problem for this daemon**

- **Hang / “freeze” behaviour:** When the cluster is stressed, split-brain recovery is in progress, or pmxcfs is wedged, operations on `/etc/pve` are a common source of **indefinite or very long hangs** (admin shells stuck on `ls /etc/pve`, `qm list` blocking, etc.). The arbiter runs continuously and polls config for **migration checks** and **instance injection**; if every read went through FUSE, a single stuck call could **stall the whole process**—including mesh, snoop coordination, and flow maintenance—not just “slow config refresh.”
- **Many small operations vs one database:** Walking `nodes/<name>/qemu-server/*.conf` and `lxc/*.conf` means **many** path lookups and reads—each multiplied by FUSE latency and failure modes. Opening `**config.db`** is a **single** local file with **read-only** SQLite access and a **bounded wait** (`timeout=` on connect); you get a full `**tree`** snapshot in a small number of queries instead of dozens of virtual file operations.
- **Same logical data:** The SQLite file under `/var/lib/pve-cluster/config.db` is the **backing store** pmxcfs uses for the `tree` of configs; the `.conf` bodies you would read under `/etc/pve` are the same blobs available as `data` in the `tree` table. The code does **not** duplicate policy—it reads the authoritative replica **without** the FUSE layer.
- **Explicit product choice:** The entry point documents **pmxcfs DB only (no `/etc/pve` fallback)** so behaviour stays predictable on unhealthy clusters.

**What this does *not* guarantee**

- `**config.db` is not magically immune** to cluster trouble: another process can hold a **SQLite write lock**; reads can still block or fail until the lock clears. The difference is **avoiding FUSE-induced hangs** and keeping the I/O pattern **small, ro, and timeout-bounded** where possible.
- If the node’s storage or pmxcfs is badly broken, **both** `/etc/pve` and `config.db` can be unusable; the watcher then **keeps the last good cache** (see caveats above).

## ARP reply and responder (strict vlan / no vlan / remote vlan)

- **All snooped entries** are eligible for ARP reply and for ARP responder flows; `arp_reply_strict_vlan`, `arp_reply_no_vlan`, and `arp_reply_remote_vlan` control **when** we reply and **which** flows are installed.
- `**--arp-reply-strict-vlan`** and `**--arp-reply-remote-vlan**` apply to **both** packet-out ARP reply and ARP responder flows. `**--arp-reply-no-vlan`** is **ignored for arp-responder** (untagged requests are expected to hit packet monitor).
- `**--arp-reply-remote-vlan` VLAN:** For IPs on **remote** nodes, match and reply on this VLAN (tunnel) instead of the snooped vlan. Local IPs always use their real (snooped) vlan.
- `**--tunnel-vlans` / `--tunnel-vlan` VLANS:** Shortcut: add these VLANs to no-snoop list; if exactly one VLAN is given, also set `--arp-reply-remote-vlan` to it. If multiple VLANs, a warning is printed and you must set `--arp-reply-remote-vlan` manually.

### OVS ARP responder (datapath) vs userspace

With `**--arp-responder`**, the daemon installs **native OpenFlow rules** in OVS so ARP who-has is answered **in the datapath** (kernel/OVS fast path). Replies happen **without** consulting the **ovs-vm-arbiter** process for that packet—useful because userspace handling (mirror, parse, packet-out) is **relatively slower** at scale.

The daemon still runs for **mirroring**, **state**, **mesh**, **migration**, and for **ARP reply** when no responder flow applies. Think of the responder as an **accelerator**: offload when flows match; the process remains the **slow path** and policy brain.

### VLANs and OpenFlow (caveats)

On many bridges, **OpenFlow matches do not see 802.1Q the way you see it in tcpdump**: VLAN may be **stripped** before the table where responder flows live, or **applied when the frame leaves** the bridge, so **flow rules often have no usable `vlan_tci` match** for customer VLANs.

When datapath rules cannot express the real VLAN, **ovs-vm-arbiter** still receives a **mirrored copy** of the **full frame** (including VLAN) and can answer ARP as **last-resort responder**—correct, but via userspace/packet-out rather than pure OpenFlow.

`**--arp-responder-vlan-register N` (N = 0–7):** Responder flows match VLAN using `**NXM_NX_REG<N>[]`** instead of `vlan_tci`. **You** must install **upstream** OpenFlow rules that **load the real VLAN ID into that register** before traffic hits the responder table; then the **fast datapath** responder can work on **tagged** networks too.

**Pipeline tweaks:** Alternatively, **push_vlan** / **pop_vlan** (or reorder tables) so VLAN is visible where responder rules match—depends on your OVS pipeline.

**Practical default:** For **most** networks, **userspace ARP reply** alone (mirror + packet monitor) is **fast enough**; enable `**--arp-responder`** when you want datapath offload and can accept VLAN/OpenFlow constraints—or use `**arp-responder-vlan-register**` plus a pipeline that fills the register.

### Tunnel VLAN (inter-host)

The **tunnel VLAN** is used for **inter-host communication** (over VXLAN). Customer VLANs (e.g. 100+) may exist only on some nodes; if a VLAN is **not present on the local node**, it cannot be reached via vmbr0 and its patch ports, so traffic to IPs in that VLAN must go **via the tunnel VLAN** to the destination host. On the local bridge, **every remote node is therefore visible only on this single VLAN** (the tunnel VLAN), regardless of the real VLAN the IP lives in on the remote side.

- **Exclude from snooping:** The tunnel VLAN **must** be in `--no-snoop-vlans` (or set via `--tunnel-vlans`). If we snoop on it, we would see ARP/replies from remote IPs arriving on the tunnel VLAN and wrongly attribute them to the **local** node (same bridge, tunnel VLAN), which would break correct in_port/VXLAN forwarding for those IPs.
- **Match and reply on tunnel VLAN:** With `--arp-reply-remote-vlan` set (e.g. via `--tunnel-vlan 10`), we match incoming ARP *who-has* requests for **remote** IPs only when the request is on the tunnel VLAN, and we send the reply on that same VLAN so the requester reaches the remote host via VXLAN.

### Strict / no-vlan / packet-out details

**Caution (VLANs and FDB learning):** `**--arp-reply-no-vlan`** (answer **untagged** ARP who-has even when the snooped entry is on a **tagged** VLAN) and `**--no-arp-reply-strict-vlan`** (reply **without** requiring the request VLAN to match the entry) change **where** the reply is sent and **which VLAN context** the bridge associates with the client MAC. In **802.1Q / VLAN** setups that can **distort or break FDB port learning** (MAC learned on the wrong port or VLAN, odd forwarding until entries age out). Treat these as **debug or special-case** toggles; prefer `**--arp-reply-strict-vlan` on** and `**--arp-reply-no-vlan` off** in production VLAN networks unless you understand the tradeoff.

- `**--arp-reply-strict-vlan` on (default):** Reply only when request vlan **matches** (snooped vlan for local; remote_vlan for remote when set). With `**--arp-reply-no-vlan` on** (packet-out only), also reply to **untagged** requests. OF responder: no untagged flow for tagged entries (no_vlan ignored).
- `**--arp-reply-strict-vlan` off:** Reply regardless of request vlan; OF responder: one flow per (bridge, ip, mac) with no vlan in match.
- `**--arp-reply-no-vlan` off:** Do not reply to untagged requests when strict (packet-out path); OF responder for tagged entries has no (None) key.
- `**--arp-reply-set-register N`:** When sending ARP reply via packet-out, prepend `load:N->NXM_NX_REG0[]` to actions so downstream flows can match on REG0 (0 = disabled).
- `**--arp-reply-local-fallback`:** Allow LOCAL `in_port` fallback when the VXLAN port is not found (default off).

## Migration and FDB


| Option                        | Default     | Meaning                                                                                                                                                                                                                                   |
| ----------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--verify-local-migration`    | on          | When the mesh still credits a **remote** node but local snoop sees traffic, require a **forced Proxmox `config.db` read** proving the MAC is on this host before flipping ownership—**if** the remote entry is still “fresh” (see below). |
| `--verify-remote-migration`   | off         | Allow remote takeover only when the mesh claim matches PVE DB cluster confirmation.                                                                                                                                                       |
| `--migration-invalidates-fdb` | on          | On ownership change, invalidate local FDB and kernel ARP as appropriate.                                                                                                                                                                  |
| `--snoop-takeover-sec`        | mesh_ttl/10 | Staleness window on the **current owner’s** `last_seen`: after this many seconds without an update from the remote claim, local snoop may take ownership **without** a DB check (CLI default: `mesh_ttl/10` when omitted).                |


### `--snoop-takeover-sec` and `--verify-local-migration` together

- **Time gate:** If another node owns the entry and `now − last_seen ≤ snoop_takeover_sec`, the remote side is treated as **fresh**. Local snoop does **not** move `node` to self on time alone.
- **After the gate:** If `last_seen` is older than `snoop_takeover_sec` (or the entry is expired), local takeover is allowed without asking Proxmox.
- **DB override when `--verify-local-migration` is on (default):** While the remote claim is still fresh, local takeover is allowed **only** if a forced read of `**config.db`** shows that MAC belongs to a VM/LXC on **this** host per the cluster database. If that check fails, ownership stays remote and an `ALERT migration denied ... reason=local_confirm_failed` is logged. If it passes, takeover can proceed **even** while the remote timestamp is still inside the window (immediate migration when Proxmox agrees).
- `**--no-verify-local-migration`:** No DB override; a fresh remote owner blocks local takeover until the time gate passes (pure staleness rule).
- **Different VLAN, same IP+bridge:** The monitor avoids clobbering a remote-owned row on another VLAN unless migration is confirmed (same confirmation path when verification is enabled).

**Recommendation (small, tightly controlled environments):** Set `--snoop-takeover-sec 0` so the time gate is effectively off: local snoop can take ownership as soon as the last update from the remote side is not “just now.” That yields **fast migration without waiting for Proxmox to confirm** the MAC in the usual path. Use only where you trust the LAN and mesh (mis-snooping or hostile traffic could flip ownership more easily). For stricter clusters, keep the default or a positive value and leave `--verify-local-migration` on.

## Bridge IPs: guests vs local (what is snooped and what is distributed)

The daemon learns **two kinds** of IPv4 on your monitored bridges:

1. **Guest / workload addresses** — VM and LXC IPs seen in ARP/DHCP, plus addresses pulled from **Proxmox** (for example LXC static `ip=` from the cluster database), plus whatever other nodes send on the **UDP mesh**. These are the addresses you normally want **known everywhere** so ARP and forwarding stay consistent after migration.
2. **Local bridge addresses** — the **hypervisor’s own** IP on a bridge (management, API, cluster-on-vmbr, etc.): traffic the kernel treats as “this host,” not a tenant.

Both kinds can be **learned into local state** so this node can answer ARP for them. They differ in what is **broadcast to other hypervisors**.

### What gets learned

- **Guests:** From **snooping** on `--bridges`, from **Proxmox `config.db`** where relevant, and from **mesh** updates from peers.
- **Local bridge IPs:** Identified using the host’s **routing / address tables** (loopback, unusable zero address, and addresses marked **host scope** on an interface—i.e. “belongs to this machine”). `**--snoop-host-local`** (default **on**) allows those to be learned from the wire as well so ARP for the hypervisor IP works; `**--no-snoop-host-local`** skips learning them from snoop.

### What gets sent on the mesh

**Guest/workload IPs** owned by this node are included in mesh gossip so neighbors can resolve and forward correctly. **Local bridge IPs are not sent** on the mesh: other nodes should never treat your management or host-on-bridge address as if it were a VM that moved to them.

### OpenFlow responder and cache

`**--arp-responder-local-iface`** can still add extra interface addresses for responder rules and diagnostics; that does not change mesh export rules above. `**--host-local-cache-ttl**` controls how often the host re-reads interface addresses for “is this IP local?” checks.

## Logging and debug

- **Levels:** `--log-level` (`debug`|`info`|`warning`|`error`), or `--debug` for debug logging.
- `**--debug-flags`:** Bitmask for fine-grained traces; `**--debug-arp-reply`** sets bit 0 (verbose ARP reply logging).
- **Debug dedup:** Consecutive duplicate DEBUG messages are suppressed (only the first of a run is emitted). Application code can force a line to always print when needed (e.g. ARP reply traces).
- **ARP reinject:** At debug level, reinject logs `arp reinject who-has <ip> bridge=... vlan=... (unknown, flood)` and `arp reinject failed: ...` on error.

## DB and cache tuning (selected)


| Option                       | Default | Meaning                                       |
| ---------------------------- | ------- | --------------------------------------------- |
| `--db-debounce-sec`          | 5       | Debounce after config.db change               |
| `--db-periodic-sec`          | 60      | Force re-read interval                        |
| `--db-stat-optimization`     | off     | Skip DB read when `config.db` mtime unchanged |
| `--host-local-cache-ttl`     | 60      | Host-local address cache                      |
| `--bridge-subnets-cache-ttl` | 60      | Bridge subnet cache                           |
| `--ovs-node-port-cache-ttl`  | 60      | OVS `remote_ip` → port cache                  |


## Architecture (for humans and LLMs)

- **Config** (`config.py`): Single dataclass; built from CLI via `Config.from_args(argparse.Namespace)`.
- **IPEntry** (`models.py`): One IP→MAC; key = (ipv4, bridge, vlan). Fields: ipv4, mac, bridge, vlan, node, last_seen, last_received, expired, scope. `expired` set when TTL elapsed; then removed after `expired_entry_cleanup_sec`.
- **IPEntryStore** (`models.py`): Thread-safe store keyed by (ip, bridge, vlan). Methods: get, set, update, discard, get_active, get_entries_for_bridge_ip, get_any_active_for_bridge_ip, items, keys, to_dict, load_from_dict.
- **ArbiterCore** (`core.py`): Owns store, InstanceWatcher, PacketMonitor, MeshBroadcaster, OVSManager, OFManager, StateManager. Main loop: poll instances, mesh silence check (warn+restart if no recv for 10×keepalive), _expire_entries, _cleanup_expired_entries, save, mesh send/recv, OF verify, ARP responder sync. Optional _ping_neighbours_loop (when ping_neighbours_interval > 0): pings mesh neighbours from host via native ICMP.
- **InstanceWatcher**: Polls Proxmox config.db; returns InstanceStore (MAC→InstanceInfo).
- **PacketMonitor**: ARP/DHCP snoop per bridge; updates IPEntryStore; optional ARP reply and reinject. **Per-VLAN snoop**: at most one snooped VLAN per (ip, bridge); does not overwrite remote node when seeing VM on local VLAN; same-VLAN re-sight sets node=self (VM moved); after TTL expiry can snoop on another VLAN. **ARP reply** gated by `arp_reply_strict_vlan`, `arp_reply_no_vlan`, and `arp_reply_remote_vlan` (local=entry vlan, remote=tunnel vlan when set); reply_vlan used for packet and in_port. **ARP reinject**: unknown who-has re-injected to flood; debug logs who-has and bridge/vlan. Filter by `--snoop-vlans` / `--no-snoop-vlans`.
- **MeshBroadcaster**: UDP broadcast; send state keyed by "|bridge|vlan"; receive merges into store (node from payload). Optional HMAC.
- **OFManager**: Mirror flows + ARP responder flows; sync from IPEntryStore via compute_desired_responders (strict/no_vlan/arp_reply_remote_vlan, for_responder=True) + sync_arp_responder_flows.
- **StateManager**: Load/save IPEntryStore to state.json.
- **NetlinkInfo** (`netlink.py`): Cached netlink: self/tap MACs, host-local, subnets, bridge identity; **PeerTracker** for ARP refresh peers.

## Module map (LLM)


| Module                | Role                                                                                                                 |
| --------------------- | -------------------------------------------------------------------------------------------------------------------- |
| main.py               | Entry; CLI; Config.from_args; ArbiterCore.run or list dumps; tunnel-vlan merge; daemon lock; `--version`             |
| config.py             | Config dataclass, from_args, get_node_ip, registry paths; list mode bitmasks                                         |
| core.py               | ArbiterCore: main loop, _expire_entries, _cleanup_expired_entries, _ping_neighbours_loop, snoop silence warn/restart |
| icmp_ping.py          | send_icmp_echo: native ICMP echo (no subprocess); used by ping-neighbours                                            |
| models.py             | IPEntry, IPEntryKey, IPEntryStore, InstanceInfo, InstanceStore                                                       |
| state.py              | StateManager load_into / save_from IPEntryStore                                                                      |
| instance_watcher.py   | Poll config.db → InstanceStore                                                                                       |
| netlink.py            | NetlinkInfo; PeerTracker; bridge identity / host-local                                                               |
| ttl_cache.py          | TTLCache; used by NetlinkInfo and OVSManager                                                                         |
| ovs_cmd.py            | OVSCommand: ovs-vsctl / ovs-ofctl subprocess helpers                                                                 |
| packet_monitor.py     | Snoop ARP/DHCP; update store; inject_config_ips; ArpRefresher hook; ARP reply/reinject                               |
| packet_monitor_arp.py | Shared ARP packet builders for monitor                                                                               |
| arp_refresher.py      | ArpRefresher thread: periodic ARP for FDB refresh                                                                    |
| logging_util.py       | DebugDedupFilter; setup_logging                                                                                      |
| mesh.py               | MeshBroadcaster send/recv; HMAC optional; node from payload; get_last_recv_any() for silence watchdog                |
| of_manager.py         | ensure_flows, sync_arp_responder_flows, compute_desired_responders                                                   |
| ovs_manager.py        | ovs-vsctl; get_bridge_node_to_ofport; remote_ip cache; dump_remote_ips, dump_local_ips                               |
| packet_out.py         | PacketOutRequest; AsyncPacketSender queue                                                                            |
| flow_registry.py      | Cookie from /run/ovs-flow-registry                                                                                   |
| dump.py               | dump_db, dump_peers, dump_neigh, dump_refreshers, dump_responders                                                    |


## List modes (exit after output)

List modes are **one-shot**: they start the process, gather inputs once, print, and exit. They are **not** a live view of the dataplane (no running snoop thread, no mesh receive loop for that session).

**What “recent snapshot” means here**

- **Persisted IP / mesh view (`state.json`):** Most neighbour-/peer-/VLAN-style dumps load `**state.json`** into the store first (unless the specific flag only queries other sources). That file is written by the **daemon** on `save_interval` (default 13s). If the daemon has not run recently—or never—output can be **stale or empty**. TTL columns (e.g. `--list-neigh`) are computed **at print time** from `last_seen` in that loaded data, not from live packets.
- **Proxmox `config.db`:** Where a dump calls `poll(force_refresh=True)`, you get a **point-in-time** read of the SQLite replica at invocation—not a subscription to future edits. `**--list-pve-db`** uses only that path (no `state.json` merge).
- **OVS / kernel:** `--list-fdb`, `--list-responders`, and the early-exit `**--list-remote-ips` / `--list-local`** paths query **ovs-vsctl / ovs-appctl (and similar) once**; results reflect the bridge/FDB/OpenFlow state **at that instant**, which can change immediately after the command returns.

Use list modes for **debugging and spot checks**, not as a substitute for metrics or a continuous observer unless you understand this staleness.


| Flag                  | Purpose                                                                         |
| --------------------- | ------------------------------------------------------------------------------- |
| `--list-db`           | Instance cache merged with snoop state                                          |
| `--list-pve-db`       | Parsed PVE DB instances only                                                    |
| `--list-peers`        | Mesh peers (node → activity)                                                    |
| `--list-neigh`        | Neighbours: ip, mac, vlan, node, ttl (aliases: `--list-n`, `--list-neighbours`) |
| `--list-remote-ips`   | VXLAN `remote_ip` → port (alias: `--list-remote`)                               |
| `--list-local`        | Local IPs on bridges / patch ports                                              |
| `--list-refreshers`   | ARP refresh peers                                                               |
| `--list-responders`   | OFS ARP responder rows (alias: `--list-arp-responders`)                         |
| `--list-vlans`        | VLANs with scope and assigned IPs                                               |
| `--list-fdb [BRIDGE]` | FDB dump; default bridge = first `--bridges`                                    |


## Prometheus / OpenMetrics

Metrics endpoint is disabled by default.

- `--prometheus-metrics` enables `/metrics`.
- `--prometheus-host HOST` sets listen host (default `localhost`).
- `--prometheus-port PORT` sets listen port (default `9108`).
- `--prometheus-metrics-extra` enables high-cardinality entry mapping metrics.

Format behavior:

- Default scrape format: Prometheus text (`text/plain; version=0.0.4`).
- OpenMetrics format when requested with `Accept: application/openmetrics-text`.

Examples:

- `curl http://127.0.0.1:9108/metrics`
- `curl -H 'Accept: application/openmetrics-text' http://127.0.0.1:9108/metrics`

### Base metrics


| Metric                                               | Type    | Labels                                           | Description                                                                        |
| ---------------------------------------------------- | ------- | ------------------------------------------------ | ---------------------------------------------------------------------------------- |
| `ovs_vm_arbiter_build_info`                          | gauge   | `version`, `role`                                | Static build/runtime identity (always `1`).                                        |
| `ovs_vm_arbiter_config_info`                         | gauge   | `node`, `bridges_count`, `arp_responder_enabled` | Effective runtime config snapshot (always `1`).                                    |
| `ovs_vm_arbiter_mesh_sign_enabled`                   | gauge   | -                                                | `1` when mesh signing key is configured, else `0`.                                 |
| `ovs_vm_arbiter_pve_instances`                       | gauge   | `type`                                           | Parsed Proxmox instance count by `qemu`/`lxc`.                                     |
| `ovs_vm_arbiter_pve_config_db_ok`                    | gauge   | -                                                | `1` when last config.db read succeeded, else `0`.                                  |
| `ovs_vm_arbiter_pve_config_db_last_success_unixtime` | gauge   | -                                                | Unix time of the last successful config.db read.                                   |
| `ovs_vm_arbiter_entries_total`                       | gauge   | -                                                | Current number of entries in `IPEntryStore`.                                       |
| `ovs_vm_arbiter_entries_active_total`                | gauge   | -                                                | Entries with `expired == None`.                                                    |
| `ovs_vm_arbiter_entries_inactive_total`              | gauge   | -                                                | Entries with `expired != None`.                                                    |
| `ovs_vm_arbiter_process_uptime_seconds`              | gauge   | -                                                | Daemon uptime in seconds.                                                          |
| `ovs_vm_arbiter_last_snoop_age_seconds`              | gauge   | -                                                | Age since last snooped packet (`-1` means unknown).                                |
| `ovs_vm_arbiter_main_loop_tick_unixtime`             | gauge   | -                                                | Last main loop tick timestamp.                                                     |
| `ovs_vm_arbiter_mesh_known_nodes`                    | gauge   | -                                                | Count of nodes seen via mesh receiver.                                             |
| `ovs_vm_arbiter_mesh_peer_ttl_seconds`               | gauge   | `peer_ip`                                        | Remaining peer TTL (`mesh_ttl - peer_age`) per peer.                               |
| `ovs_vm_arbiter_mesh_peer_messages_age_seconds`      | gauge   | -                                                | Age since last peer mesh message (`-1` means unknown).                             |
| `ovs_vm_arbiter_arp_refresh_peers_total`             | gauge   | -                                                | Active ARP refresher peer tuples.                                                  |
| `ovs_vm_arbiter_arp_responder_flows_total`           | gauge   | -                                                | Installed datapath ARP responder flow count.                                       |
| `ovs_vm_arbiter_arp_responder_flows`                 | gauge   | `bridge`                                         | Installed ARP responder flows by bridge.                                           |
| `ovs_vm_arbiter_mesh_rx_messages_total`              | counter | -                                                | Received mesh datagrams.                                                           |
| `ovs_vm_arbiter_mesh_tx_messages_total`              | counter | -                                                | Sent mesh datagrams (payload + keepalive).                                         |
| `ovs_vm_arbiter_mesh_rx_invalid_total`               | counter | -                                                | Rejected mesh datagrams (bad json/signature/limits/errors).                        |
| `ovs_vm_arbiter_owner_changes_total`                 | counter | `reason`                                         | Ownership change events (`reason="migration"`).                                    |
| `ovs_vm_arbiter_ip_migrations_total`                 | counter | -                                                | Total IP ownership migrations.                                                     |
| `ovs_vm_arbiter_migration_refused_total`             | counter | `reason`                                         | Refused local migrations (`local_confirm_failed`).                                 |
| `ovs_vm_arbiter_migration_confirmed_total`           | counter | `reason`                                         | Local migration confirmations (`local_confirmed`).                                 |
| `ovs_vm_arbiter_remote_migration_confirmed_total`    | counter | -                                                | Remote migration confirmations (only when `--verify-remote-migration` is enabled). |
| `ovs_vm_arbiter_remote_migration_refused_total`      | counter | -                                                | Remote migration refusals (only when `--verify-remote-migration` is enabled).      |
| `ovs_vm_arbiter_entries_expired_total`               | counter | -                                                | Entries marked expired by TTL checks.                                              |
| `ovs_vm_arbiter_entries_cleaned_total`               | counter | -                                                | Expired entries removed by cleanup.                                                |
| `ovs_vm_arbiter_db_polls_total`                      | counter | `result`                                         | DB poll outcome (`ok`, `fail`, `skipped`).                                         |
| `ovs_vm_arbiter_arp_responder_sync_total`            | counter | `result`                                         | ARP responder sync runs (`ok`, `error`).                                           |
| `ovs_vm_arbiter_arp_responder_flows_added_total`     | counter | -                                                | Flows added by sync.                                                               |
| `ovs_vm_arbiter_arp_responder_flows_removed_total`   | counter | -                                                | Flows removed by sync.                                                             |
| `ovs_vm_arbiter_arp_reply_attempts_total`            | counter | -                                                | ARP reply send attempts.                                                           |
| `ovs_vm_arbiter_arp_reply_sent_total`                | counter | -                                                | ARP replies sent successfully.                                                     |
| `ovs_vm_arbiter_arp_reply_failed_total`              | counter | -                                                | ARP replies that failed on send.                                                   |
| `ovs_vm_arbiter_arp_reply_skipped_total`             | counter | -                                                | ARP replies skipped (no match/vlan/no port).                                       |
| `ovs_vm_arbiter_arp_reinject_sent_total`             | counter | -                                                | Unknown ARP reinject sends.                                                        |
| `ovs_vm_arbiter_arp_reinject_failed_total`           | counter | -                                                | Unknown ARP reinject send failures.                                                |


### Extra metrics

Extra metrics are enabled only with `--prometheus-metrics-extra`.


| Metric                                     | Type  | Labels                                                | Description                                       |
| ------------------------------------------ | ----- | ----------------------------------------------------- | ------------------------------------------------- |
| `ovs_vm_arbiter_entry_mapping_info`        | gauge | `ip`, `mac`, `bridge`, `vlan`, `node`, `snoop_origin` | One series per entry mapping (`1`).               |
| `ovs_vm_arbiter_entry_mapping_ttl_seconds` | gauge | `ip`, `mac`, `bridge`, `vlan`, `node`                 | Remaining TTL per entry (`0` if already expired). |


High-cardinality warning: extra mapping metrics can create many time-series. Keep disabled unless required.

## Technical decisions

**Why not a native OVS bridge controller?** The daemon does **not** aim to be the **primary OpenFlow controller** for your bridges (no “take over the whole pipeline” model). It stays a **normal process** that installs **narrow** flows (mirror, optional ARP responder) via `ovs-ofctl`-style usage alongside whatever else you run. That keeps the **failure and trust boundary smaller**: a bug or crash in **ovs-vm-arbiter** is easier to **contain and disable** than a controller that owns forwarding tables end-to-end. While the project is still **beta** and maturing, that separation is intentional—**safety and operability** over tight integration. A fuller controller story could be revisited later if the design stabilizes and demand is clear.

**Other choices people ask about** (details live in the linked sections above):

| Question | Short answer |
| --- | --- |
| **Why read Proxmox `config.db` instead of `/etc/pve`?** | Avoid **pmxcfs FUSE** stalls on many small reads; **one read-only SQLite** session with bounded waits vs walking virtual config files. |
| **Why put the UDP mesh on a different network than the tenant VXLAN?** | **Split failure domains**: mesh stays up when the overlay is wedged or filtered; the tool must not depend on the path it optimizes. |
| **Why CLI-only config (no default config file)?** | **Single source of truth** for runtime flags; service units or wrappers stay the “file”; no silent merge with on-disk YAML. |
| **Why HMAC on mesh payloads but no encryption / no central store?** | **Cheap integrity** on a **broadcast** control plane; **no etcd**-style dependency—**gossip + TTL** is enough for this threat model if the L2 segment is trusted or the key is secret. See *Mesh signing*. |
| **Why mirror + userspace ARP reply before optional datapath responder?** | **VLAN / pipeline reality**: mirrors see full frames; **OpenFlow matches** often miss customer VLANs—**packet-out** stays the portable fallback; responder is an **accelerator** when rules can match. |
| **Why ship as a Python zipapp (`ovs-vm-arbiter.zip`) in the role?** | **One artifact** on the host; no pip/venv coupling in production; launcher script execs the zip. |
| **Why don’t hypervisor “bridge” IPs ride the mesh?** | **Host addresses** are not workload ownership; exporting them would confuse peers. See *Bridge IPs: guests vs local*. |

## Development / tests

- **Installed script:** Run `ovs-vm-arbiter.py --test` to execute the built-in test suite and exit.
- **From source checkout (this role):** Change into the `files` directory and run `python3 -m src.main --test`. This avoids clashes with the standard-library `types` module when importing `src.types`. Use `python3 -m src.main --service …` for daemon experiments from a checkout.

## How this project was built

This is an **AI-assisted** codebase: most of the typing, refactors, and day-to-day edits were done in **Cursor** (chat/agent plus editor), sometimes alongside other assistants. **Design and architecture** are **human-driven**: goals, trade-offs, and invariants are set and reviewed by a person, not produced as one end-to-end automated pass.

**Testing is central:** there is a substantial `src/test/` suite, and behaviour changes are expected to come with **focused tests** (run via `--test`; see *Development / tests* above). The maintainer treats failing tests and edge cases as part of the contract, not an afterthought.

## Dependencies

scapy (optional, for snooping); pyroute2 (optional, host-local / bridge identity); prometheus_client (optional, only needed when `--prometheus-metrics` is enabled). Run without for list modes and no snoop.