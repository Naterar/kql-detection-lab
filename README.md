# SOC Detection Lab

Hands-on security operations work in a Microsoft Defender XDR and Sentinel
environment — writing detections, generating the telemetry behind them,
operating endpoint response tooling, and running full intrusion investigations
end to end.

Environment provided by the LogN Pacific Cyber Range.

**Detections and notes:** [kql-detections.md](kql-detections.md)
**Investigation report:** [incident-report.md](incident-report.md)

---

## What this is

A study repository. Most queries come from the course curriculum or from
AI-assisted exploration of the log schemas. What's mine is running them against
live data, troubleshooting them, and working out what each one catches and what
it misses — the notes under each query in `kql-detections.md`, and the analysis
in the investigation report.

---

## The environment

Multi-subscription Azure range: peered VNets, NSG-segmented subnets, Azure
Bastion, a Tenable scan engine, and Windows endpoints onboarded to Microsoft
Defender for Endpoint. Log Analytics feeds both Sentinel and Defender XDR
Advanced Hunting.

The range is internet-exposed on purpose, so the failed-logon and port-scan data
is real opportunistic attack traffic rather than simulated.

---

## What I worked on

**Detection engineering.** KQL queries across authentication, network flow,
process execution, and Azure control-plane telemetry. Brute force, brute force
that succeeded, port scanning, lateral movement, outbound C2, data exfiltration,
suspicious PowerShell, and living-off-the-land binaries. Geo-enrichment with
`geo_info_from_ip_address()` to map where inbound authentication originates and
where outbound data goes.

**Telemetry generation.** Deliberately generated each Defender XDR table — RDP
for logon events, process chains for process events, an outbound request for
network events, a temp-directory file write, a Run-key registry value, a
scheduled task — then confirmed each landed and matched what I expected.

Two things that only surface by doing this: Advanced Hunting runs 5 to 15
minutes behind, and a single action often lands in more than one table. A
scheduled task creation appears in both `DeviceEvents` and
`DeviceProcessEvents`, recorded two different ways.

**Threat intelligence.** Pulled suspicious IPs out of live logon-failure data,
created TI indicators for them in Sentinel with confidence ratings and expiry
dates, confirmed ingestion, then matched them against network flow and
authentication telemetry. Also worked with Microsoft's built-in indicator feed —
which returns zero matches in a clean environment, meaning a rule built on it
needs a known-present artifact to validate against.

**Endpoint response in Defender for Endpoint.** Deployed and onboarded Windows
VMs. Isolated a live host from the portal and verified the effect — a running
ping to its public IP stops, because isolation permits only security-related
traffic. Collected a forensic investigation package and reviewed the contents.

---

## Investigations

### Operation JadePuffer — agentic ransomware

**Live community threat hunt, completed September 2026.**
Full report: [incident-report.md](incident-report.md)

An autonomous LLM agent compromised a four-host estate and completed a full
ransomware campaign in **seventeen minutes**. A single human prompt started it.
Everything after that — exploitation, persistence, credential theft,
reconnaissance, lateral movement, privilege escalation, encryption, and ransom
delivery — the agent executed on its own.

Reconstructed across 25 investigation points: initial access through an RCE in
an internet-facing application, C2 beacon on a non-standard port, cron
persistence under a service account, API key theft via `pg_dump`, an internal
service sweep, lateral movement on unchanged vendor default credentials, direct
modification of `/etc/shadow` to create a rogue account, a failed container
escape probe, and AES encryption of two production database tables.

Three findings worth pulling out of the report:

**The fileless hypothesis did not hold.** No process hashes were recorded for
the spawned processes. That is absence of evidence, not evidence of absence —
missing hash data means the sensor did not capture them, not that nothing was
written to disk. Calling it fileless would have been a conclusion the telemetry
could not support, and it would have changed the containment plan for the worse.

**The agent adapted mid-operation.** A configuration fetch returned XML it could
not parse. Rather than failing, it modified its own parser and refetched.
Conventional malware breaks on unexpected input — that brittleness is something
defensive strategy quietly relies on. An agent that diagnoses and works around
its own failures removes that safety net.

**The credential theft outweighs the ransomware.** Encrypted database rows
restore from backup. Eight stolen third-party API keys operate under the
victim's identity and billing, outside the estate entirely, and stay valid until
each provider revokes them. The ransom note draws attention to the loud damage
while the quiet damage walks out the door.

The report includes the full attack timeline, MITRE ATT&CK mapping across 15
techniques, the IOC set, a phased containment and remediation plan, and detection
recommendations — including velocity-based alerting, since a seventeen-minute
campaign completes before most correlation cycles run.

### Core Investigation Skills — endpoint intrusion

Worked a help desk ticket reporting overnight login prompts on a finance
workstation into a full investigation: reconstructing initial access, remote
execution via WMI, an implant staged in a temp directory, outbound beaconing,
four separate persistence mechanisms, a backdoor account promoted to
Administrators, and lateral movement to a second host. Deliverables were a
written incident report and a containment plan.

This exercise is a graded capture-the-flag, so specific artifact values are
withheld to keep it intact for others.

---

## Notes

All tenant IDs, subscription IDs, and portal URLs have been removed. Queries
reference schema and table names only.

The brute-force-that-succeeded detection logic is planned as a standalone Python
tool, so it can run outside the SIEM and be unit tested.

---

## Reference

- [AzureActivity schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity)
- [NTANetAnalytics schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/ntanetanalytics)
- [DeviceLogonEvents schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicelogonevents)
- [DeviceProcessEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Collect investigation package](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts#collect-investigation-package-from-devices)
