# A few select utils to get you started.

This repository contains a curated set of specialized Linux utilities designed to simplify system administration, security auditing, and troubleshooting. Each tool is lightweight, efficient, and crafted to address specific operational challenges — from normalizing filenames to monitoring sockets, auditing mail systems, diagnosing servers, and analyzing logs.  

Every tool has its own dedicated documentation file (`.md`) for detailed usage and instructions. This README provides an overview of each tool with a concise description and highlights of its most powerful features.

---

## RAL (Rename and Lowercase)

RAL is a high-performance utility written in C for normalizing filenames across directories. It systematically replaces spaces with dots (or another chosen character) and converts all filenames to lowercase, ensuring consistency across diverse file sets. Unlike shell scripts or Python wrappers, RAL is designed to be lightning-fast, capable of handling thousands of files in seconds.  

This tool is particularly useful in environments where file naming standards are critical—such as media servers, shared directories, or automation pipelines. By automatically detecting and resolving conflicts, RAL avoids errors that can arise from case-sensitive duplicates or messy naming conventions, ensuring predictable and repeatable outcomes.  

**Key Features**
- Replace spaces in filenames with dots (or custom characters).  
- Convert all filenames to lowercase automatically.  
- Recursively process directories with speed and accuracy.  
- Safely handle conflicts by overwriting duplicates.

---

## Socket Snoop – Real-Time Socket Monitoring

Socket Snoop is a lightweight, real-time socket monitoring solution built on eBPF. It provides immediate visibility into system-level network activity by capturing TCP state transitions, source/destination IPs, ports, process IDs, and the commands behind them. The tool emphasizes clarity and speed, formatting raw kernel events into structured logs for administrators.  

By focusing on socket states rather than raw packets, Socket Snoop simplifies network debugging, security monitoring, and operational audits. It reduces the need for heavier tools like `tcpdump` or Wireshark while maintaining a low system footprint. Its real-time log file output and optional continuous monitoring make it a reliable companion for live production systems.  

**Key Features**
- Capture and log live TCP state changes using eBPF.  
- Provide detailed context including PID, command name, IPs, and ports.  
- Lightweight and efficient compared to packet capture utilities.  
- Real-time console and log file output for operational visibility.  

---

## mail-audit.py – Domain & Mail Flow Auditor

`mail-audit.py` is a comprehensive auditing tool for email infrastructure, designed to analyze every layer of mail delivery and domain configuration. It checks DNS records, SPF/DMARC/DKIM authentication, TLS encryption quality, MX record hygiene, blacklist status, and client exposure. The tool outputs both machine-friendly JSON and clear human-readable reports, making it suitable for automation pipelines or one-off audits.  

This tool is invaluable for system operators, security professionals, and auditors looking to assess mail delivery reliability and compliance. By scoring domains across authentication, transport, hygiene, and client surface exposure, it not only identifies misconfigurations but also provides actionable remediation steps. Its safety features, such as query throttling, make it safe to run in production environments.  

**Key Features**
- Perform deep DNS and resolver audits with DNSSEC and hygiene checks.  
- Validate SPF, DKIM, and DMARC policies with detailed parsing.  
- Test TLS/STARTTLS with cipher, version, and certificate analysis.  
- Score domains with structured JSON and text reports including remediation guidance.  

---

## debian-diagnostics.sh – System Diagnostic Reporter

`debian-diagnostics.sh` is a one-stop diagnostic script that generates a detailed Markdown report (`diagnostic.md`) covering networking, system health, security posture, and package states. Designed for incident response and day-to-day troubleshooting, it collects vital data such as routing tables, DNS resolution, system logs, authentication failures, and package integrity checks in a single run.  

The script is structured into six sections: Networking, System & Logs, Security & Firewall, APT Package Audit, Common Services, and Performance. By consolidating this data, it saves administrators significant time during outages, postmortems, and audits. It gracefully degrades when optional tools are missing, ensuring portability across environments while maximizing insights where possible.  

**Key Features**
- Capture full networking snapshot (interfaces, routing, DNS, sockets).  
- Scan logs, failed units, disk usage, and security events.  
- Audit APT repositories, keys, package states, and upgrade status.  
- Collect performance metrics and hardware health (e.g., SMART).  

---

## LogHog (lh) – Log Forensics Simplified

LogHog is a powerful log forensics tool designed to make log analysis fast, intuitive, and accessible to anyone. Its default `TAIL` mode automatically stitches logs together by timestamp, creating a single unified timeline across multiple sources. This makes it especially effective for real-time monitoring of authentication failures, permission denials, SQL injections, or any critical event stream.  

For deeper analysis, LogHog provides a secondary `LESS` mode, which buffers logs into an interactive environment for advanced searching, editing, and correlation. By combining simplicity with raw speed, LogHog enables both quick incident response and complex forensic investigations. Written in C, it is built for performance and scales seamlessly across local files, mounted shares, and remote log sources.  

**Key Features**
- Automatically stitch logs together by timestamp across sources.  
- Filter logs with simple keywords or advanced regex patterns.  
- Analyze network events and errors with protocol-specific filtering.  
- Remote-ready, blazing fast, and capable of handling massive log sets.  

---

## Meta-Scrape – AWS EC2 Metadata Inspector  

Meta-scrape is a lightweight Python utility that queries the AWS EC2 Instance Metadata Service (IMDS) to provide a clean, human-friendly view of an instance’s identity and environment. It supports both IMDSv2 (secure, token-based) and IMDSv1 (fallback), and presents results in either Markdown or JSON, making it equally useful for human troubleshooting or machine automation.  

This tool is particularly valuable for operators, SREs, and security teams who need quick, credential-free insight into where a system is running, which account it belongs to, and how it is configured. Beyond one-off checks, its JSON output makes it a natural fit for automation pipelines, inventory management, and monitoring dashboards.  

**Key Features**  
- Fetch instance identity data directly from AWS IMDS without API keys.  
- Summary mode: display essentials such as instance ID, type, region, availability zone, account ID, hostname, IPs, and IAM role.  
- Full mode: export the entire metadata tree in JSON with sensitive fields redacted.  
- IMDSv2-first with fallback to IMDSv1, including a clear warning if v1 is used.  
- Multiple output formats (Markdown or JSON) for human or machine consumption.  
- Robust HTTP client with retries, timeouts, and urllib3 v1/v2 compatibility.

---
