# KQL Detection Lab Notes

Working notes and queries from hands-on SOC training in a Microsoft Sentinel
cyber range environment (LogN Pacific). Azure Log Analytics, Sentinel, Defender
for Endpoint, and M365 Security.

This is a **study repository**, not a production detection library. Queries come
from the course curriculum and from AI-assisted exploration; my contribution is
running them against live log data, troubleshooting them, and writing the
explanations below of what each one detects and where it falls short.

---

## Environment

Multi-subscription Azure cyber range with peered VNets, NSG-protected subnets,
Azure Bastion, a Tenable scan engine, and Log Analytics feeding Sentinel and
Defender. Member resources across four subscriptions generate the telemetry
these queries run against.

---

## Tables covered

| Table | What it holds |
|---|---|
| `SigninLogs` | Entra ID sign-in activity with geo enrichment |
| `AzureActivity` | Control-plane operations — VM create/delete, NSG changes |
| `NTANetAnalytics` | Network flow logs — traffic allowed and denied |
| `DeviceLogonEvents` | Endpoint logon success and failure |
| `DeviceProcessEvents` | Process execution and command lines |

---

## Detections

### Control plane — `AzureActivity`

**VM deletions and creations.** Filters successful compute operations in the last
24 hours and projects the caller and source IP. Useful for spotting resources
created or destroyed outside a change window.

**NSG rule changes.** Catches any create, update, or delete against network
security groups or security rules. A firewall rule changing at 2am is worth a
look regardless of who did it.

*Limitation:* control-plane logs show what was requested, not what the resulting
configuration is. A permissive rule created and left in place stops generating
events after the write.

---

### Network flow — `NTANetAnalytics`

**Port scan detection.** Counts distinct destination ports per source-destination
pair and flags sources touching more than 50. A scanner hits many ports; a real
client hits a few.

*Limitation:* a slow scan spread across hours falls under the threshold.
Threshold tuning is environment-specific.

**Overly permissive NSG rules.** Summarizes allowed flow volume by ACL rule name,
filtering for rules containing "allow_all", "danger", or "any". Surfaces which
loose rules are actually carrying traffic — useful for prioritizing cleanup.

*Limitation:* depends entirely on naming conventions. A permissive rule with a
professional-sounding name is invisible to this query.

**Denied inbound flows.** Aggregates blocked inbound attempts by source IP,
destination, and port. Renaming `SrcIp` to `IpAddress` lets Defender recognize
the field as an IP and enrich it automatically.

---

### Endpoint authentication — `DeviceLogonEvents`

**Failed logon volume.** Counts `LogonFailed` events per source IP and device,
flagging anything above 10. The baseline signal for password guessing.

*Limitation:* high false positive rate on its own. Stale service accounts and
expired cached credentials generate failures constantly.

**Successful logon following failures.** The most useful query in this set.
Builds two datasets — failure counts and success counts, each keyed by account,
device, and source IP — then inner-joins them so only account/device/IP
combinations appearing in both survive. Filters for more than 10 failures
alongside at least one success.

The logic matters: failures alone are noise, and a success alone looks normal.
The pair is the signal — a password attack that eventually landed.

*Limitations:* no time ordering, so a success that happened *before* the failures
still matches. Misses password spray, where one attempt is made against many
accounts and no single account crosses the failure threshold. Misses slow brute
force spread beyond the query window.

**Remote interactive logons from public IPs.** Filters successful
RemoteInteractive, Network, and Unlock logons where `RemoteIPType` is Public.
Internal lateral movement is invisible here by design — this one looks for
external entry.

---

### Lateral movement — `DeviceLogonEvents`

Buckets successful remote logons into one-hour windows and counts distinct
target devices per account. Five or more machines in an hour from one account is
the pattern — a compromised credential being walked across the network.

Binning is what makes it work. An admin touching 20 machines over a week is
normal; 20 in an hour is not.

*Limitation:* legitimate automation and management accounts will trip this. Needs
an allowlist to be usable.

---

### Process execution — `DeviceProcessEvents`

**Suspicious PowerShell.** Matches command lines containing encoding flags,
hidden window styles, download cmdlets, or base64 conversion — the fingerprints
of fileless execution.

**Office and browser applications spawning shells.** Flags a parent process like
winword, excel, outlook, or a browser launching cmd, PowerShell, wscript, mshta,
rundll32, or regsvr32. The classic phishing payload chain.

**Execution from unusual paths.** Legitimate binaries live in System32 and
Program Files. Executables running from temp, appdata, downloads, or public user
folders are worth reviewing.

**Living-off-the-land binaries.** Surfaces native Windows tools attackers abuse
for download and execution — certutil, bitsadmin, mshta, regsvr32, rundll32,
wmic, msbuild, installutil. Their presence is normal; their command lines are
where the signal is.

---

## Notes

All environment identifiers, tenant IDs, subscription IDs, and portal links have
been removed. Queries reference schema and table names only.

Detection logic from the DeviceLogonEvents brute-force-that-succeeded query is
being rebuilt as a standalone Python tool so it runs outside the SIEM and can be
unit tested. That work lives in a separate repository.

---

## Reference

- [AzureActivity schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity)
- [NTANetAnalytics schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/ntanetanalytics)
- [DeviceLogonEvents schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicelogonevents)
- [DeviceProcessEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
