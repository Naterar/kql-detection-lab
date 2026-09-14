# KQL Detections

Queries from SOC lab work in Microsoft Sentinel and Defender XDR Advanced
Hunting, grouped by telemetry source. Notes under each cover what it detects
and where it falls short.

All tenant IDs, subscription IDs, and portal URLs removed.

**Provenance:** most queries come from the LogN Pacific Cyber Range curriculum.
Those marked *(AI-assisted)* were developed by exporting log samples and using
an LLM to explore what the schema could support, then verifying and tuning the
result against live data. The notes are mine.

---

## Contents

- [Authentication — DeviceLogonEvents](#authentication--devicelogonevents)
- [Lateral movement](#lateral-movement)
- [Network flow — NTANetAnalytics](#network-flow--ntanetanalytics)
- [Outbound C2 — DeviceNetworkEvents](#outbound-c2--devicenetworkevents)
- [Process execution — DeviceProcessEvents](#process-execution--deviceprocessevents)
- [Azure control plane — AzureActivity](#azure-control-plane--azureactivity)
- [Identity — SigninLogs](#identity--signinlogs)
- [Threat intelligence](#threat-intelligence)
- [Telemetry generation and verification](#telemetry-generation-and-verification)

---

## Authentication — DeviceLogonEvents

### Failed logon volume (brute force)

Counts failed attempts per source IP and device. A spike from one IP, or
against one account, is the brute-force signal.

```kql
let startTime = datetime(2026-06-01 00:00:00);
let endTime   = datetime(2026-06-02 00:00:00);
DeviceLogonEvents
| where TimeGenerated between (startTime .. endTime)
| where ActionType == "LogonFailed"
| summarize FailedCount = count(), Accounts = make_set(AccountName, 20)
    by RemoteIP, DeviceName, FailureReason
| where FailedCount > 10
| sort by FailedCount desc
```

**Limitation:** high false positive rate alone. Stale service accounts and
expired cached credentials generate constant failures. This is a starting
point, not an alert.

---

### Successful logon following failures

The most useful query in this set. Builds failure counts and success counts
separately, each keyed by account + device + source IP, then inner-joins them —
so only combinations present in *both* survive.

```kql
let startTime = datetime(2026-06-01 00:00:00);
let endTime   = datetime(2026-06-02 00:00:00);
let failures =
    DeviceLogonEvents
    | where TimeGenerated between (startTime .. endTime)
    | where ActionType == "LogonFailed"
    | summarize Failures = count() by AccountName, DeviceName, RemoteIP;
let successes =
    DeviceLogonEvents
    | where TimeGenerated between (startTime .. endTime)
    | where ActionType == "LogonSuccess"
    | summarize Successes = count(), LastSuccess = max(TimeGenerated)
        by AccountName, DeviceName, RemoteIP;
failures
| join kind=inner successes on AccountName, DeviceName, RemoteIP
| where Failures > 10 and Successes > 0
| project AccountName, DeviceName, RemoteIP, Failures, Successes, LastSuccess
| sort by Failures desc
```

**Why the join matters:** failures alone are noise. A success alone looks
normal. The pair is the signal — a password attack that eventually landed.

**Limitations:**
- No time ordering. A success that happened *before* the failures still matches.
- Misses password spray — one attempt across many accounts never crosses a
  per-account threshold.
- Misses slow brute force spread beyond the query window.

---

### Remote interactive logons from external IPs

Surfaces successful RemoteInteractive, Network, and Unlock logons sourced from
public addresses. `RemoteIPType` filters out internal traffic.

```kql
let startTime = datetime(2026-06-01 00:00:00);
let endTime   = datetime(2026-06-02 00:00:00);
DeviceLogonEvents
| where TimeGenerated between (startTime .. endTime)
| where ActionType == "LogonSuccess"
| where LogonType in ("RemoteInteractive", "Network", "Unlock")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP, RemotePort, Protocol
| sort by Timestamp desc
```

**Limitation:** internal lateral movement is invisible here by design. This
looks for external entry only.

---

### Inbound authentication origins, geo-mapped

Enriches external source IPs with geolocation and aggregates by location,
counting successes and failures separately per origin.

```kql
DeviceLogonEvents
| where RemoteIPType == "Public"
| where isnotempty(RemoteIP)
| where LogonType in ("Network", "RemoteInteractive")
| extend geo = geo_info_from_ip_address(RemoteIP)
| extend Latitude  = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country   = tostring(geo.country),
         City      = tostring(geo.city)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize Attempts        = count(),
            Successes       = countif(ActionType == "LogonSuccess"),
            Failures        = countif(ActionType == "LogonFailed"),
            TargetedDevices = dcount(DeviceName),
            Accounts        = make_set(AccountName, 25)
        by RemoteIP, Country, City, Latitude, Longitude
| extend MapLabel = strcat(RemoteIP, " (", Country, ") — ", Successes, " success / ", Attempts, " total")
| project Latitude, Longitude, MapLabel, Attempts, Successes, Failures, TargetedDevices, RemoteIP, Country, City, Accounts
| order by Successes desc, Attempts desc
```

**Why successes and failures are split:** a location with 400 failures and zero
successes is background noise. The same location with 400 failures and one
success is an incident.

**Limitations:** geo databases are approximate. VPN and cloud egress points
resolve to the provider's location, not the operator's. Rows the geo database
can't resolve are dropped, so anything unresolvable is silently excluded.

---

## Lateral movement

*(AI-assisted)*

Buckets successful remote logons into one-hour windows and counts distinct
target devices per account.

```kql
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where LogonType in ("Network", "RemoteInteractive")
| where isnotempty(AccountName)
| summarize
    DistinctTargets = dcount(DeviceName),
    Targets         = make_set(DeviceName, 25),
    Logons          = count(),
    SourceIPs       = make_set(RemoteIP, 10)
    by AccountName, bin(TimeGenerated, 1h)
| where DistinctTargets >= 5
| sort by DistinctTargets desc
```

**Why binning matters:** an admin touching 20 machines across a week is normal.
Twenty in an hour is not. Without the time bucket this returns every
administrative account in the environment.

**Limitation:** management and automation accounts trip this constantly. Needs
an allowlist to be usable in production.

---

## Network flow — NTANetAnalytics

### Port scan detection

Counts distinct destination ports per source-destination pair.

```kql
let startTime = datetime(2026-06-02 00:00:00);
let endTime   = datetime(2026-06-03 00:00:00);
NTANetAnalytics
| where TimeGenerated between (startTime .. endTime)
| where FlowStatus == "Allowed"
| where isnotempty(SrcIp)
| summarize DistinctPorts = dcount(DestPort), Ports = make_set(DestPort, 50)
    by SrcIp, DestIp, AclRule
| where DistinctPorts > 50
| sort by DistinctPorts desc
```

**Limitation:** a slow scan spread across hours stays under the threshold.
Threshold tuning is environment-specific — 50 is a starting guess, not a
universal value.

---

### Traffic allowed by overly permissive NSG rules

Summarizes allowed flow volume by ACL rule name, filtering for loosely-named
rules. Shows which permissive rules actually carry traffic.

```kql
let startTime = datetime(2026-06-02 00:00:00);
let endTime   = datetime(2026-06-03 00:00:00);
NTANetAnalytics
| where TimeGenerated between (startTime .. endTime)
| where FlowStatus == "Allowed"
| where AclRule has_any ("allow_all", "danger", "any")
| summarize FlowCount = count(), Sources = dcount(SrcIp), Dests = dcount(DestIp)
    by AclRule
| sort by FlowCount desc
```

**Limitation:** depends entirely on naming convention. A permissive rule with a
professional-sounding name is invisible to this query.

---

### Denied inbound flows

Aggregates blocked inbound attempts. Renaming `SrcIp` to `IpAddress` lets
Defender recognize the field as an IP address and enrich it automatically.

```kql
let startTime = datetime(2026-06-02 00:00:00);
let endTime   = datetime(2026-06-03 00:00:00);
NTANetAnalytics
| where TimeGenerated between (startTime .. endTime)
| where isnotempty(SrcIp)
| where FlowDirection == "Inbound"
| where DeniedInFlows > 0
| summarize TotalDenied = sum(DeniedInFlows)
    by IpAddress = SrcIp, DestIp, DestPort, L4Protocol
| sort by TotalDenied desc
```

---

### Beaconing / C2 detection

*(AI-assisted)*

Measures the time gap between consecutive outbound flows for the same
connection, then flags connections where the gaps are unusually regular.

```kql
let startTime = datetime(2026-06-02 00:00:00);
let endTime   = datetime(2026-06-03 00:00:00);
NTANetAnalytics
| where TimeGenerated between (startTime .. endTime)
| where FlowDirection == "Outbound"
| where isnotempty(SrcIp) and isnotempty(DestIp)
| order by SrcIp asc, DestIp asc, DestPort asc, TimeGenerated asc
| serialize
| extend Key = strcat(SrcIp, "_", DestIp, "_", DestPort)
| extend GapSeconds = iff(Key == prev(Key),
                          datetime_diff('second', TimeGenerated, prev(TimeGenerated)),
                          long(null))
| where isnotnull(GapSeconds)
| summarize Beacons = count(), AvgGap = avg(GapSeconds), StdevGap = stdev(GapSeconds)
    by SrcIp, DestIp, DestPort
| where Beacons >= 5
| extend Regularity = StdevGap / AvgGap
| where Regularity < 0.2
| sort by Regularity asc
```

**The logic:** malware calling home does it on a schedule. A person browsing
doesn't. `Regularity` is the coefficient of variation — standard deviation over
mean — so a lower number means more machine-like timing.

`serialize` is required because `prev()` only means anything once row order is
locked in.

**Limitation:** the 0.2 threshold is a guess that has to be tuned per
environment. Tighten it and you miss jittered beacons; loosen it and legitimate
polling services flood the results. Modern C2 frameworks add deliberate jitter
specifically to defeat this.

---

### Data exfiltration by volume

*(AI-assisted)*

Sums outbound bytes per destination and computes an out-to-in ratio.

```kql
let startTime = datetime(2026-06-02 00:00:00);
let endTime   = datetime(2026-06-03 00:00:00);
NTANetAnalytics
| where TimeGenerated between (startTime .. endTime)
| where FlowDirection == "Outbound"
| where FlowStatus == "Allowed"
| where isnotempty(DestPublicIps)
| summarize
    TotalBytesOut = sum(BytesSrcToDest),
    TotalBytesIn  = sum(BytesDestToSrc),
    FlowCount     = count(),
    Ports         = make_set(DestPort, 20)
    by SrcIp, DestIp, DestPublicIps
| extend TotalMBOut = round(TotalBytesOut / 1024.0 / 1024.0, 2)
| extend OutInRatio = todouble(TotalBytesOut) / (TotalBytesIn + 1)
| where TotalMBOut > 100
| sort by TotalBytesOut desc
```

**Why the ratio:** normal browsing pulls far more down than it pushes up. A
connection sending much more than it receives is the shape of exfiltration. The
`+ 1` avoids divide-by-zero.

**Limitation:** cloud backup, video calls, and file sync all produce the same
shape. Needs a destination allowlist.

---

### Exfiltration by volume, geo-mapped

Parses the packed `DestPublicIps` tuple, geolocates the destination, and tracks
how many internal hosts fed each one.

```kql
NTANetAnalytics
| where TimeGenerated {TimeRange}
| where SubType == "FlowLog"
| where isnotempty(DestPublicIps)
| extend Parts = split(DestPublicIps, "|")
| extend PublicIp     = tostring(Parts[0]),
         AllowedFlows = tolong(Parts[3]),
         DeniedFlows  = tolong(Parts[4]),
         BytesIn      = tolong(Parts[5]),
         BytesOut     = tolong(Parts[6])
| where isnotempty(PublicIp)
| where BytesOut > 0
| extend geo = geo_info_from_ip_address(PublicIp)
| extend Latitude  = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country   = tostring(geo.country),
         City      = tostring(geo.city)
| where isnotempty(City) and isnotempty(Country)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize BytesOut = sum(BytesOut),
            BytesIn  = sum(BytesIn),
            Sources  = dcount(SrcIp),
            Ports    = make_set(DestPort, 15)
        by PublicIp, Country, City, Latitude, Longitude
| extend MB_Out = round(BytesOut / 1048576.0, 1)
| extend MapLabel = strcat(PublicIp, " (", City, ", ", Country, ") - ", MB_Out, " MB out, ", Sources, " sources")
| project Latitude, Longitude, MapLabel, BytesOut, MB_Out, BytesIn, Sources, Ports, PublicIp, Country, City
| order by BytesOut desc
```

**The tuple format:** `DestPublicIps` packs
`IP|flowStarted|flowEnded|allowedInFlows|deniedInFlows|bytesIn|bytesOut`,
pipe-delimited, one IP tuple per row.

**Why fan-in matters:** one host sending 500MB somewhere is a large transfer.
Twelve hosts sending to the same unfamiliar destination is shared
infrastructure.

---

### Allowed inbound flows from threat-intel-listed IPs

Joins accepted inbound traffic against the live TI feed. Each result is a
threat-intel-listed external IP whose traffic was **let in**.

```kql
let TI_IPs =
    ThreatIntelIndicators
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by Id
    | where IsActive == true
    | where isempty(ValidUntil) or ValidUntil > now()
    | where ObservableKey in ("ipv4-addr:value",
                              "network-traffic:src_ref.value",
                              "network-traffic:dst_ref.value")
    | extend ThreatType = tostring(Data.indicator_types[0])
    | project TI_IP = ObservableValue, Confidence, ThreatType, Tags
    | where isnotempty(TI_IP);
NTANetAnalytics
| where TimeGenerated {TimeRange}
| where SubType == "FlowLog"
| where AllowedInFlows > 0
| where isnotempty(SrcIp)
| join kind=inner TI_IPs on $left.SrcIp == $right.TI_IP
| extend geo = geo_info_from_ip_address(SrcIp)
| extend Latitude  = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country   = tostring(geo.country),
         State     = tostring(geo.state),
         City      = tostring(geo.city)
| where isnotempty(City) and isnotempty(Country)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize AllowedFlows  = sum(AllowedInFlows),
            DeniedFlows   = sum(DeniedInFlows),
            BytesIn       = sum(BytesSrcToDest),
            Targets       = dcount(DestIp),
            Ports         = make_set(DestPort, 15),
            MaxConfidence = max(Confidence),
            ThreatTypes   = make_set(ThreatType, 10)
        by SrcIp, Country, State, City, Latitude, Longitude
| extend MapLabel = strcat(SrcIp, " (", City, ", ", State, ", ", Country, ") - ", AllowedFlows, " allowed, ", Targets, " targets")
| project Latitude, Longitude, MapLabel, AllowedFlows, DeniedFlows, BytesIn, Targets, Ports, MaxConfidence, ThreatTypes, SrcIp, Country, State, City
| order by AllowedFlows desc, Targets desc
```

**The question this answers:** not "did hostile traffic reach us" but "did
hostile traffic get through." `AllowedInFlows > 0` is the whole point.

**Why `arg_max` by `Id`:** indicators get re-ingested, producing duplicate rows.
Taking the latest row per indicator ID deduplicates before the join.

---

## Outbound C2 — DeviceNetworkEvents

Filters egress to public IPs, strips known-legitimate Microsoft destinations,
geolocates what remains, and keeps destinations contacted by multiple devices.

```kql
DeviceNetworkEvents
| where Timestamp {TimeRange}
| where RemoteIPType == "Public" and isnotempty(RemoteIP)
| where isempty(RemoteUrl) or RemoteUrl !endswith "microsoft.com"
| where isempty(RemoteUrl) or RemoteUrl !endswith "windows.com"
| where isempty(RemoteUrl) or RemoteUrl !endswith "windowsupdate.com"
| where isempty(RemoteUrl) or RemoteUrl !endswith "azure.com"
| where isempty(RemoteUrl) or RemoteUrl !endswith "office.com"
| where isempty(RemoteUrl) or RemoteUrl !endswith "msftncsi.com"
| extend geo = geo_info_from_ip_address(RemoteIP)
| extend Latitude  = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country   = tostring(geo.country),
         State     = tostring(geo.state),
         City      = tostring(geo.city)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize Connections = count(),
            Devices     = dcount(DeviceName),
            Processes   = make_set(InitiatingProcessFileName, 25),
            Ports       = make_set(RemotePort, 15),
            SampleUrl   = take_any(RemoteUrl)
        by RemoteIP, Country, State, City, Latitude, Longitude
| where Connections >= 5
| extend MapLabel = strcat(SampleUrl, " (", City, ", ", State, ", ", Country, ") — ", Devices, " devices")
| project Latitude, Longitude, MapLabel, Devices, Connections, Processes, Ports, SampleUrl, RemoteIP, Country, State, City
| order by Devices desc, Connections desc
```

**Why filter Microsoft domains:** without it the map is entirely Windows Update,
telemetry, and Office traffic, and the interesting destination is buried.

**Limitation:** suffix-based allowlisting is coarse. An attacker hosting on a
subdomain of a filtered suffix passes straight through. Rows with an empty
`RemoteUrl` survive all six filters by design — they're IP-only connections,
which is itself worth looking at.

---

## Process execution — DeviceProcessEvents

### Suspicious PowerShell command lines

Flags encoded, hidden, or download-style PowerShell — common in fileless
attacks.

```kql
let startTime = datetime(2026-06-02 00:00:00);
let endTime   = datetime(2026-06-03 00:00:00);
DeviceProcessEvents
| where TimeGenerated between (startTime .. endTime)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any (
    "-enc", "-encodedcommand", "-e ",
    "downloadstring", "downloadfile", "iex", "invoke-expression",
    "-windowstyle hidden", "-w hidden", "frombase64string", "bypass")
| project Timestamp, DeviceName, AccountName, FileName,
          InitiatingProcessFileName, ProcessCommandLine
| sort by Timestamp desc
```

**Limitation:** string matching on command lines is trivially evaded — string
concatenation, variable substitution, and alternate casing all bypass it.
Catches the unsophisticated, which is still most of it.

---

### Office or browser applications spawning shells

Detects a parent like winword, excel, outlook, or a browser launching a shell
or scripting host — the classic phishing payload chain.

```kql
let startTime = datetime(2026-06-02 00:00:00);
let endTime   = datetime(2026-06-03 00:00:00);
DeviceProcessEvents
| where TimeGenerated between (startTime .. endTime)
| where InitiatingProcessFileName in~ (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "chrome.exe", "msedge.exe", "firefox.exe")
| where FileName in~ (
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by Timestamp desc
```

**Strength:** this one is high-signal. There is almost no legitimate reason for
Word to launch cmd.exe.

---

### Processes running from unusual locations

Legitimate system binaries live in System32 and Program Files. Execution from
temp, downloads, or appdata is worth a closer look.

```kql
let startTime = datetime(2026-06-02 00:00:00);
let endTime   = datetime(2026-06-03 00:00:00);
DeviceProcessEvents
| where TimeGenerated between (startTime .. endTime)
| where FolderPath has_any (
    @"\temp\", @"\appdata\", @"\downloads\",
    @"\users\public\", @"\programdata\", @"\windows\temp\")
| where FileName endswith ".exe"
| summarize Count = count(), Cmds = make_set(ProcessCommandLine, 10)
    by DeviceName, FileName, FolderPath
| sort by Count desc
```

**Limitation:** software installers and updaters run from temp directories
routinely. Needs baselining before it's useful.

---

### Living-off-the-land binaries (LOLBins)

Native Windows tools attackers abuse for download and execution.

```kql
let startTime = datetime(2026-06-02 00:00:00);
let endTime   = datetime(2026-06-03 00:00:00);
DeviceProcessEvents
| where TimeGenerated between (startTime .. endTime)
| where FileName in~ (
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wmic.exe", "msbuild.exe", "installutil.exe")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp desc
```

**Reading it correctly:** the presence of these binaries is normal. The command
line is where the signal is — certutil downloading a file, rundll32 with an odd
export. This query is a hunting starting point, not an alert.

---

## Azure control plane — AzureActivity

### VM deletions

```kql
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/delete"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceGroup, _ResourceId
| sort by TimeGenerated desc
```

### VM creations

```kql
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/write"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceGroup, _ResourceId
| sort by TimeGenerated desc
```

### NSG rule changes

Any create, update, or delete against network security groups or security rules.

```kql
AzureActivity
| where TimeGenerated > ago(48h)
| where OperationNameValue has "networkSecurityGroups" or OperationNameValue has "securityRules"
| where OperationNameValue endswith "write" or OperationNameValue endswith "delete"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue,
          ActivityStatusValue, ResourceGroup, _ResourceId
| sort by TimeGenerated desc
```

**Limitation across all three:** control-plane logs record what was *requested*,
not the resulting configuration. A permissive rule created once stops
generating events after the write — it sits there silently thereafter.

---

## Identity — SigninLogs

Sign-in activity with location detail, filtered by user.

```kql
SigninLogs
| where UserPrincipalName contains "<username>"
| project TimeGenerated,
          UserPrincipalName,
          UserDisplayName,
          City    = LocationDetails.city,
          Country = LocationDetails.countryOrRegion
```

---

## Threat intelligence

### Find candidate malicious IPs

Starting point for building indicators — the sources hammering the environment.

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize Count = count() by RemoteIP, ActionType
| order by Count desc
```

### Confirm custom indicators were ingested

```kql
ThreatIntelIndicators
| where Data.name == "<indicator name>"
| project ObservableValue, IsActive, ValidUntil
```

### Match indicators against network traffic

```kql
let BadIPs = toscalar(
    ThreatIntelIndicators
    | where TimeGenerated > ago(365d)
    | where Data.name == "<indicator name>"
    | summarize make_set(ObservableValue));
NTANetAnalytics
| where isnotempty(SrcPublicIps)
| extend RemoteIP = split(SrcPublicIps, "|")[0]
| where RemoteIP in (BadIPs)
| project TimeGenerated, RemoteIP, DestPort, FlowDirection, FlowType
```

### Match indicators against logons

```kql
let BadIPs = toscalar(
    ThreatIntelIndicators
    | where TimeGenerated > ago(365d)
    | where Data.name == "<indicator name>"
    | summarize make_set(ObservableValue));
DeviceLogonEvents
| where RemoteIP in (BadIPs)
```

### Confirm built-in indicators exist

```kql
ThreatIntelIndicators
| where TimeGenerated > ago(7d)
| where IsActive == true
| where ObservableKey == "network-traffic:src_ref.value"
| project TimeGenerated, SourceSystem, ObservableValue, ObservableKey, ValidUntil, Confidence
| order by TimeGenerated desc
```

**Worth knowing:** Microsoft's built-in hash indicators are global
known-malware. A clean environment returns zero matches — good security, but it
means a rule built on them never fires, and needs a known-present artifact to
validate against before you trust it.

---

## Telemetry generation and verification

Detections are only as good as your understanding of what fills the table
behind them. Each action below populates one Defender XDR table on purpose;
the query confirms it landed. All actions are benign and reversible.

Advanced Hunting runs 5 to 15 minutes behind — don't expect rows immediately.

| Table | Action | Key ActionType |
|---|---|---|
| `DeviceLogonEvents` | RDP into the host | `LogonSuccess` |
| `DeviceProcessEvents` | `powershell.exe -Command "cmd /c whoami"` | process create |
| `DeviceNetworkEvents` | `Invoke-WebRequest` to an external host | `ConnectionSuccess` |
| `DeviceFileEvents` | Copy an executable into `C:\Windows\Temp\` | `FileCreated` |
| `DeviceRegistryEvents` | `reg add` a Run-key value | `RegistryValueSet` |
| `DeviceEvents` | `schtasks /create` a daily task | `ScheduledTaskCreated` |

### Verification queries

```kql
// Logon events
DeviceLogonEvents
| where DeviceName == "<hostname>"
| where Timestamp > ago(30m)
| project Timestamp, ActionType, AccountName, LogonType, RemoteIP, InitiatingProcessFileName
| sort by Timestamp desc

// Process events — parent/child chain
DeviceProcessEvents
| where DeviceName == "<hostname>"
| where Timestamp > ago(30m)
| where FileName in~ ("cmd.exe", "whoami.exe", "powershell.exe")
| project Timestamp, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName, AccountName
| sort by Timestamp desc

// Network events
DeviceNetworkEvents
| where DeviceName == "<hostname>"
| where Timestamp > ago(30m)
| where InitiatingProcessFileName == "powershell.exe"
| project Timestamp, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| sort by Timestamp desc

// File events
DeviceFileEvents
| where DeviceName == "<hostname>"
| where Timestamp > ago(30m)
| where FolderPath has @"\Temp\"
| where FileName startswith "labtest"
| project Timestamp, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName
| sort by Timestamp desc

// Registry events
DeviceRegistryEvents
| where DeviceName == "<hostname>"
| where Timestamp > ago(30m)
| where RegistryKey has @"\CurrentVersion\Run"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, ActionType, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| sort by Timestamp desc

// Sensor events — scheduled task creation
DeviceEvents
| where DeviceName == "<hostname>"
| where Timestamp > ago(30m)
| where ActionType == "ScheduledTaskCreated"
| project Timestamp, ActionType, AdditionalFields,
          InitiatingProcessFileName, InitiatingProcessAccountName
| sort by Timestamp desc
```

**Two things that only surface by doing this:**

A single action often lands in more than one table. `schtasks /create` appears
in both `DeviceEvents` as a `ScheduledTaskCreated` sensor event and in
`DeviceProcessEvents` as a process execution — the same event recorded two
different ways, which matters when you're deciding which table to build a
detection on.

`DeviceEvents` is the catch-all for typed sensor events without a dedicated
table. A service installation raises `ServiceInstalled` there the same way.
