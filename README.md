# info_sec_labs 🚧 *Under Development*

## Overview

info_sec_labs is a collection of hands-on cybersecurity labs designed to build practical skills in incident response, SaaS security, and more. Each lab focuses on real-world scenarios, providing structured exercises to improve detection, analysis, and mitigation techniques.

---

### Incident Response / SaaS Security

#### Web and Email Server Security

This lab covers essential security measures for web and email servers, including:

- **Certificates**: Understanding SSL/TLS for secure communication - also implementing newer version certificate.
- **Secure Network Ports & Protocols**: Identifying and enforcing best practices.
- **Comparing PCAP Files**: Analyzing traffic differences between unencrypted and encrypted emails.
- **Enhancing Email Security**: Implementing SPF, DKIM, and DMARC to reduce phishing and spoofing risks.

---

### DNS Infrastructure

- **DNS Mapping**: Understanding the network.
- **View/Create DNS Records**: Using DNS Manager and PowerShell.
- **Certificate Transparency Logs**: Reviewing for security insights.
- **Creating and Accessing a DNS Sinkhole**: Mitigating malicious domains.

---

### Indicators of Compromise (IoCs)

- **Searching for IoCs in Event Logs**.
- **Persistence Detection**: Comparing SID history of an AD user to the SID of the Domain Admins group.
- **Privilege Escalation (Privesc) Techniques**:
  - Identifying `PATH` environment variable manipulation.
  - Detecting DLL hijacking occurrences.
- **Defense Evasion**:
  - PowerShell script to identify suspicious activity.
  - Checking digital signatures of binaries in File Explorer vs. PowerShell.
- **Credential Access**:
  - Analyzing IIS logs for IoCs.
  - Using PowerShell to filter event records with IoCs.
  - Performing event log analysis to detect password spray attacks.
- **IoCs in Lateral Movement**:
  - Reviewing aggregated Windows system event logs to detect IoCs.
  - Viewing and running a log aggregation script in PowerShell.

---

### Ransomware Defense

- **Blocking Malicious IPs**: Creating and applying firewall rules in pfSense.
- **Resetting KRBTGT Account Password**:
  - Verifying last set date.
  - Identifying the PDC emulator.
  - Resetting the KRBTGT account password and confirming the reset.
- **Active Directory Backup**:
  - Identifying PDC emulator for AD backup.
  - Checking if Windows Server Backup Utility is installed.
  - Performing AD backup.
- **Application Allowlisting**:
  - Checking current settings on a Domain Controller.
  - Converting a CI policy XML to binary format.
  - Testing CI policy by launching an application again.
- **Disabling SMBv1 with Group Policy**:
  - Checking SMBv1 status on a Domain Controller.
  - Creating a Group Policy to disable SMBv1.
  - Applying the new policy and confirming after a reboot.
- **Sinkholing Malicious Domains**:
  - Checking connection to a malicious site and its IP.
  - Creating a DNS sinkhole for the bad site.
  - Verifying the sinkhole implementation.

---

### Log Management

- **Configure Log Forwarding with Syslog**:
  - Set up a Syslog server (LinuxGUIserver).
  - Set up a Syslog client.
  - Analyze log results and verify Syslog monitoring on the server.
- **Configure Secure Logging with TLS**:
  - Create a new sudo user on LinuxGUIserver and LinuxGUIclient.
  - Configure TLS encryption.
  - Distribute CA certificate.
  - Verify that Syslog packets are sent securely.
- **Configure Event Forwarding to SIEM**:
  - Install and configure SIEM agent.
  - Configure SIEM/Wazuh agent.
  - Perform SIEM agent enrollment.
  - Verify encryption of forwarded logging data to SIEM.

---

### Implementing SaaS Guidelines

- **Secure Identity and Access Management Configuration**:
  - Admin and user accounts.
  - Password complexity.
  - MFA.
  - Identity Provider (IdP) configurations.
- **Monitoring of M365 Events Using a SIEM**:
  - Wazuh dashboard and security modules.
  - Viewing JSON documents containing O365 audit events.
  - Examining fields and values to identify key data.

---

### Incident Response Triage - Preparing the Environment for Detection

- **Initial Compromise Detection**:
  - Identify unauthorized RDP login alerts in SIEM logs (Security Onion, QRadar, Splunk, Palo Alto DMZ firewall).
  - Review RDP logs in Event Viewer on a web server (access remote host).
- **Web Shell Deployment Detection**:
  - Examine Security Onion alerts for PowerShell user-agent activities.
  - Locate and analyze a web shell installed in the IIS web root (using QRadar).
- **Lateral Movement & Domain Controller Compromise**:
  - Trace usage of PsExec and credential reuse with SAM tools in Security Onion.
  - Pivot to QRadar for further analysis.
  - Identify AD database dump via `ntdsutil` utility in Windows temp directory using QRadar.
  - Review Windows audit events for the DC.
- **Exfiltration & Alert Response**:
  - Detect exfiltration of `ntds.dit.zip` using SIEM tools (Security Onion and Splunk).
  - Analyze and respond to SIEM alert for HTTP transfer to an external IP (Security Onion & Splunk).

---

### Cyber Threat Intelligence (CTI)

- **Review and Analyze a Specific Threat Advisory** to develop threat-hunting operations.
- **Leverage CTI to Develop a Hunt**:
  - Use insights from an advisory to discover APT activity.
  - Devise an incident response approach.
- **Discover Adversary Tactics and Behaviors**:
  - Understand how to approach mitigation upon discovering a compromise during a hunt.
- **Operationalizing and Integrating CTI**:
  - Extract applicable IoCs and IoAs from CTI sources.
  - Apply defensive measures proactively to reported IoCs and IoAs.
- **Preparing for the Next Wave of Cyber Threats**:
  - Understand sources of sector-specific threat intelligence.
  - Analyze how the threat landscape evolves to define a proactive security strategy.
- **Exploring the Role of IoCs and IoAs in Zero Trust Architecture (ZTA)**:
  - Utilize AI to augment IoC/IoA analysis and defensive implementation.

---

## How to Use

Each lab includes step-by-step instructions, required tools, and key takeaways. Start with the overview, follow the hands-on exercises, and review the analysis sections to reinforce learning.

## Additional Reference Materials

- [IMPLEMENTATION GUIDANCE: SEGMENTING TRAFFIC AND TELEMETRY FROM AGENCY GUEST NETWORKS AND SECURITY APPLIANCES (CISA)](https://www.cisa.gov/sites/default/files/2024-10/Implementation%20Guidance%20-%20Segmenting%20Traffic%20and%20Telemetry%20From%20Agency%20Guest%20Networks%20and%20Security%20Appliances.pdf)
- [PROTECTIVE DOMAIN NAME SYSTEM RESOLVER SERVICE FACT SHEET (CISA)](https://www.cisa.gov/sites/default/files/2024-08/Protective%20DNS%20Fact%20Sheet%20-%20August%202024.pdf)
- [Protective DNS Resolver Service FAQs (CISA)](https://www.cisa.gov/sites/default/files/2024-08/Protective%20DNS%20FAQ%20-%20August%202024.pdf)

---

## Inspiration

These labs are inspired by training programs from the Cybersecurity and Infrastructure Security Agency (CISA) and have been adapted into structured, practical exercises. 
For official CISA training resources, visit [CISA Training Resources](https://www.cisa.gov/resources-tools/training).

## Contributing

Suggestions and contributions are welcome! Feel free to submit issues or pull requests to improve and expand the labs.
