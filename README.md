SOC Detection Lab
Hands-on security operations work in a Microsoft Defender XDR and Sentinel environment — writing detections, generating the telemetry behind them, operating endpoint response tooling, and running a full intrusion investigation end to end.

Environment provided by the LogN Pacific Cyber Range.

Queries and notes: kql-detections.md


What this is
A study repository. Most queries come from the course curriculum or from AI-assisted exploration of the log schemas. What's mine is running them against live data, troubleshooting them, and working out what each one catches and what it misses — the notes under each query in kql-detections.md.


The environment
Multi-subscription Azure range: peered VNets, NSG-segmented subnets, Azure Bastion, a Tenable scan engine, and Windows endpoints onboarded to Microsoft Defender for Endpoint. Log Analytics feeds both Sentinel and Defender XDR Advanced Hunting.

The range is internet-exposed on purpose, so the failed-logon and port-scan data is real opportunistic attack traffic rather than simulated.


What I worked on
Detection engineering. KQL queries across authentication, network flow, process execution, and Azure control-plane telemetry. Brute force, brute force that succeeded, port scanning, lateral movement, outbound C2, data exfiltration, suspicious PowerShell, and living-off-the-land binaries. Geo-enrichment with geo_info_from_ip_address() to map where inbound authentication originates and where outbound data goes.

Telemetry generation. Deliberately generated each Defender XDR table — RDP for logon events, process chains for process events, an outbound request for network events, a temp-directory file write, a Run-key registry value, a scheduled task — then confirmed each landed and matched what I expected.

Two things that only surface by doing this: Advanced Hunting runs 5 to 15 minutes behind, and a single action often lands in more than one table. A scheduled task creation appears in both DeviceEvents and DeviceProcessEvents, recorded two different ways.

Threat intelligence. Pulled suspicious IPs out of live logon-failure data, created TI indicators for them in Sentinel with confidence ratings and expiry dates, confirmed ingestion, then matched them against network flow and authentication telemetry. Also worked with Microsoft's built-in indicator feed — which returns zero matches in a clean environment, meaning a rule built on it needs a known-present artifact to validate against.

Endpoint response in Defender for Endpoint. Deployed and onboarded Windows VMs. Isolated a live host from the portal and verified the effect — a running ping to its public IP stops, because isolation permits only security-related traffic. Collected a forensic investigation package and reviewed the contents.

Intrusion investigation. Worked a help desk ticket reporting overnight login prompts on a finance workstation into a full investigation: reconstructing initial access, remote execution via WMI, an implant staged in a temp directory, outbound beaconing, four separate persistence mechanisms, a backdoor account promoted to Administrators, and lateral movement to a second host. Deliverables were a written incident report and a containment plan.

The exercise is a graded capture-the-flag, so specific artifact values are withheld to keep it intact for others.


Notes
All tenant IDs, subscription IDs, and portal URLs have been removed. Queries reference schema and table names only.

The brute-force-that-succeeded detection logic is being rebuilt as a standalone Python tool, so it runs outside the SIEM and can be unit tested. Separate repository.


Reference
AzureActivity schema
NTANetAnalytics schema
DeviceLogonEvents schema
DeviceProcessEvents table
Collect investigation package

