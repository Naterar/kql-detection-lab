# SOC Detection Lab

Hands-on security operations work in a Microsoft Defender XDR and Sentinel
environment: writing detections, generating the telemetry behind them,
operating endpoint response tooling, and running a full intrusion
investigation end to end.

Environment provided by the LogN Pacific Cyber Range. This is a **study
repository** — most queries originate from the course curriculum or from
AI-assisted exploration. What's mine is running them against live data,
troubleshooting them, understanding what each one catches and misses, and the
written investigation work in `/investigation`.

---

## Contents

| Folder | What's in it |
|---|---|
| `detections/` | KQL detection queries by telemetry source |
| `telemetry/` | Generating each Defender XDR table on purpose, and confirming it landed |
| `threat-intel/` | Building and matching custom TI indicators in Sentinel |
| `endpoint-response/` | MDE device isolation and investigation package collection |
| `investigation/` | Written incident report and containment plan from a full threat hunt |

---

## Environment

Multi-subscription Azure cyber range: peered VNets, NSG-segmented subnets,
Azure Bastion, a Tenable scan engine, and Windows endpoints onboarded to
Microsoft Defender for Endpoint. Log Analytics feeds both Sentinel and
Defender XDR Advanced Hunting.

The range is internet-exposed by design — real opportunistic attack traffic
reaches it, which is why the failed-logon and port-scan data below is genuine
rather than simulated.

---

## Detections

### Authentication — `DeviceLogonEvents`

**Failed logon volume.** Counts `LogonFailed` events per source IP and device,
flagging anything above 10.

*Limitation:* noisy on its own. Stale service accounts and expired cached
credentials generate failures constantly.

**Successful logon following failures.** Builds failure counts and success
counts separately — each keyed by account, device, and source IP — then
inner-joins them. Only combinations appearing in both survive. Filters for
more than 10 failures alongside at least one success.

Failures alone are noise. A success alone looks normal. The pair is the signal.

*Limitations:* no time ordering, so a success that occurred *before* the
failures still matches. Misses password spray, where one attempt per account
never crosses the threshold. Misses slow brute force spread beyond the window.

**Remote interactive logons from public IPs.** Successful RemoteInteractive,
Network, and Unlock logons where `RemoteIPType` is Public.

**Inbound authentication origins, geo-mapped.** Enriches external source IPs
with `geo_info_from_ip_address()` and aggregates by location, counting
successes and failures separately per origin. Plots one bubble per source IP.

The value is the mix: a location with 400 failures and zero successes is
background noise. The same location with 400 failures and one success is an
incident.

*Limitation:* geo databases are approximate and VPN or cloud egress points
resolve to the provider's location, not the operator's.

---

### Lateral movement — `DeviceLogonEvents`

Buckets successful remote logons into one-hour windows and counts distinct
target devices per account. Five or more machines in an hour from one account
is the pattern.

Binning is what makes it work. An admin touching 20 machines across a week is
normal; 20 in an hour is not.

*Limitation:* management and automation accounts trip this. Needs an allowlist.

---

### Network flow — `NTANetAnalytics`

**Port scan detection.** Counts distinct destination ports per source-destination
pair, flagging sources touching more than 50.

*Limitation:* a slow scan spread over hours falls under the threshold.

**Overly permissive NSG rules.** Summarizes allowed flow volume by ACL rule
name, filtering for rules named with "allow_all", "danger", or "any". Shows
which loose rules actually carry traffic.

*Limitation:* depends entirely on naming convention. A permissive rule with a
professional-sounding name is invisible.

**Denied inbound flows.** Aggregates blocked inbound attempts by source,
destination, and port. Renaming `SrcIp` to `IpAddress` lets Defender recognize
the field as an IP and enrich it automatically.

**Exfiltration by volume, geo-mapped.** Parses the packed `DestPublicIps` tuple
— pipe-delimited IP, flow timestamps, allowed and denied counts, bytes in and
out — extracts outbound byte totals, geolocates the destination, and aggregates
by location. Tracks how many distinct internal hosts fed each destination.

Fan-in matters as much as volume. One host sending 500MB somewhere is a large
transfer. Twelve hosts sending to the same unfamiliar destination is shared
infrastructure.

**Allowed inbound flows from threat-intel-listed IPs.** Builds a deduplicated,
active TI watchlist from `ThreatIntelIndicators` — using `arg_max` by indicator
ID to handle re-ingestion, filtering on `IsActive` and unexpired `ValidUntil`
— then inner-joins it against inbound flows that were **allowed**.

This is the query that answers a specific question: not "did hostile traffic
reach us" but "did hostile traffic get through."

---

### Outbound C2 — `DeviceNetworkEvents`

Filters egress to public IPs, strips known-legitimate Microsoft destinations by
URL suffix, geolocates what remains, and keeps destinations contacted by
multiple devices.

*Limitation:* suffix-based allowlisting is coarse. An attacker on a domain
ending in a filtered suffix passes through.

---

### Process execution — `DeviceProcessEvents`

**Suspicious PowerShell.** Command lines containing encoding flags, hidden
window styles, download cmdlets, or base64 conversion.

**Office and browser applications spawning shells.** A parent like winword,
excel, outlook, or a browser launching cmd, PowerShell, wscript, mshta,
rundll32, or regsvr32. The classic phishing payload chain.

**Execution from unusual paths.** Executables running from temp, appdata,
downloads, or public user folders.

**Living-off-the-land binaries.** certutil, bitsadmin, mshta, regsvr32,
rundll32, wmic, msbuild, installutil. Their presence is normal; their command
lines are the signal.

---

### Control plane — `AzureActivity`

**VM creations and deletions.** Successful compute operations with caller and
source IP projected.

**NSG rule changes.** Any create, update, or delete against network security
groups or security rules.

*Limitation:* control-plane logs show requests, not resulting state. A
permissive rule created once stops generating events after the write.

---

## Telemetry generation

Detections are only as good as your understanding of what fills the table
behind them. This set generates each Defender XDR table deliberately, then
confirms the event landed:

| Table | Action | Key ActionType |
|---|---|---|
| `DeviceLogonEvents` | RDP into the host | `LogonSuccess` |
| `DeviceProcessEvents` | `powershell.exe -Command "cmd /c whoami"` | process create |
| `DeviceNetworkEvents` | `Invoke-WebRequest` to an external host | `ConnectionSuccess` |
| `DeviceFileEvents` | Copy an executable into `C:\Windows\Temp\` | `FileCreated` |
| `DeviceRegistryEvents` | `reg add` a Run-key value | `RegistryValueSet` |
| `DeviceEvents` | `schtasks /create` a daily task | `ScheduledTaskCreated` |

Two things worth knowing that only surface by doing this: Advanced Hunting is
near-real-time but not instant — allow 5 to 15 minutes. And a single action
frequently lands in more than one table. Creating a scheduled task appears in
both `DeviceEvents` and `DeviceProcessEvents`, recorded two different ways.

Every action here is benign and reversible. The point is learning the detection
surface, not the payload.

---

## Threat intelligence

Full cycle: find suspicious IPs in live logon failure data, create TI
indicators for them in Sentinel with confidence ratings and expiry dates,
confirm they landed in `ThreatIntelIndicators`, then match them against
network flow and authentication telemetry.

Also covered: matching against Microsoft's built-in indicator feed. Worth
noting that a clean environment returns zero matches on built-in malware
hashes — which is good security but means a rule built on them won't fire on
its own, and needs a known-present artifact to validate against.

---

## Endpoint response — Microsoft Defender for Endpoint

**Device onboarding.** Deployed Windows VMs and installed MDE onboarding
packages, confirming successful enrollment in the portal.

**Device isolation.** Isolated a live host from the portal and verified the
effect — a running ping to the host's public IP stops, because isolation
permits only security-related traffic. Released the isolation afterward.

**Investigation package collection.** Triggered a forensic package collection,
tracked it through the Action Center, and reviewed the contents.

---

## Investigation

A full intrusion investigation against a Windows host, working from a help desk
ticket reporting overnight login prompts.

**What the investigation reconstructed:** initial access through an account
that had no business authenticating from where it did, remote execution via
WMI, an implant staged in a temp directory, outbound beaconing to an external
domain, four separate persistence mechanisms, creation of a backdoor local
account promoted to Administrators, and lateral movement to a second host.

**Deliverables in `/investigation`:**
- `incident-report.md` — timeline, scope, impact, and the reasoning behind each
  detection point
- `containment-plan.md` — isolation, accounts to disable, IOCs to block, and
  every persistence mechanism requiring removal

The exercise is a graded capture-the-flag; specific artifact values are
withheld so the exercise stays intact for others. The methodology and written
analysis are what matter here anyway.

---

## Notes

All tenant IDs, subscription IDs, and portal URLs have been removed. Queries
reference schema and table names only.

The brute-force-that-succeeded detection logic is being rebuilt as a standalone
Python tool so it runs outside the SIEM and can be unit tested. Separate
repository.

---

## Reference

- [AzureActivity schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity)
- [NTANetAnalytics schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/ntanetanalytics)
- [DeviceLogonEvents schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicelogonevents)
- [DeviceProcessEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Collect investigation package](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts#collect-investigation-package-from-devices)
