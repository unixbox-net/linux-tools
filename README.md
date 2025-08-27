# The Linux Tool Kit, a few of my personal tools to get you started

This repository contains a set of specialized Linux utilities designed to help system administrators, engineers, and power users streamline tasks across filesystems, networking, email infrastructure, and diagnostics. Each tool is lightweight, focused, and crafted to solve a particular class of problems efficiently.

---

## utils/RAL (Rename and Lowercase)

RAL is a high-performance utility written in C for normalizing filenames across directories. It systematically replaces spaces with dots (or another chosen character) and converts all filenames to lowercase, ensuring consistency across diverse file sets. Unlike shell scripts or Python wrappers, RAL is designed to be lightning-fast, capable of handling thousands of files in seconds.

This tool is particularly useful in environments where file naming standards are critical—such as media servers, shared directories, or automation pipelines. By automatically detecting and resolving conflicts, RAL avoids errors that can arise from case-sensitive duplicates or messy naming conventions, ensuring predictable and repeatable outcomes.

**Key Features**
- Replaces spaces in filenames with dots (or custom characters).  
- Converts all filenames to lowercase automatically.  
- Recursively processes directories with speed and accuracy.  
- Handles conflicts by safely overwriting duplicates.  

---

## monitoring/Socket Snoop – Real-Time Socket Monitoring

Socket Snoop is a lightweight, real-time socket monitoring solution built on eBPF. It provides immediate visibility into system-level network activity by capturing TCP state transitions, source/destination IPs, ports, process IDs, and the commands behind them. The tool emphasizes clarity and speed, formatting raw kernel events into structured logs for administrators.

By focusing on socket states rather than raw packets, Socket Snoop simplifies network debugging, security monitoring, and operational audits. It reduces the need for heavier tools like `tcpdump` or Wireshark while maintaining a low system footprint. Its real-time log file output and optional continuous monitoring make it a reliable companion for live production systems.

**Key Features**
- Captures and logs live TCP state changes using eBPF.  
- Provides detailed context including PID, command name, IPs, and ports.  
- Lightweight and efficient compared to packet capture utilities.  
- Real-time console and log file output for operational visibility.  

---

## email/mail-audit.py – Domain & Mail Flow Auditor

`mail-audit.py` is a comprehensive auditing tool for email infrastructure, designed to analyze every layer of mail delivery and domain configuration. It checks DNS records, SPF/DMARC/DKIM authentication, TLS encryption quality, MX record hygiene, blacklist status, and client exposure. The tool outputs both machine-friendly JSON and clear human-readable reports, making it suitable for automation pipelines or one-off audits.

This tool is invaluable for system operators, security professionals, and auditors looking to assess mail delivery reliability and compliance. By scoring domains across authentication, transport, hygiene, and client surface exposure, it not only identifies misconfigurations but also provides actionable remediation steps. Its safety features, such as query throttling, make it safe to run in production environments.

**Key Features**
- Deep DNS and resolver audits with DNSSEC and hygiene checks.  
- Full SPF, DKIM, and DMARC policy validation with detailed parsing.  
- TLS and STARTTLS testing with cipher, version, and certificate analysis.  
- Domain scoring with JSON and text reporting, including remediation guidance.  

---

## diagnostics/diagnostics.sh – System Diagnostic Reporter

`debian-diagnostics.sh` is a one-stop diagnostic script that generates a detailed Markdown report (`diagnostic.md`) covering networking, system health, security posture, and package states. Designed for incident response and day-to-day troubleshooting, it collects vital data such as routing tables, DNS resolution, system logs, authentication failures, and package integrity checks in a single run.

The script is structured into six sections: Networking, System & Logs, Security & Firewall, APT Package Audit, Common Services, and Performance. By consolidating this data, it saves administrators significant time during outages, postmortems, and audits. It gracefully degrades when optional tools are missing, ensuring portability across environments while maximizing insights where possible.

**Key Features**
- Captures full networking snapshot (interfaces, routing, DNS, sockets).  
- Scans logs, failed units, disk usage, and security events.  
- Audits APT repositories, keys, package states, and upgrade status.  
- Collects system performance metrics and hardware health (e.g., SMART).  

---
