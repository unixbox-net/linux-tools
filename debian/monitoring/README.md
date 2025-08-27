# Socket Snoop - Realtime Socket Monitoring, @OR(ϵ)SOURCES

## Overview

The Socket Monitoring Tool is a powerful and lightweight solution designed for system administrators who need real-time insights into socket-level network activity on their systems. By leveraging eBPF, this tool provides detailed logs of connection states, including source and destination IP addresses, ports, process IDs (PIDs), and associated commands (COMM), as well as TCP state transitions.

```plaintext
**FEATURES:**
- Captures TCP state changes (inet_sock_set_state tracepoint).
- Monitors key TCP connection states like SYN_SENT, FIN_WAIT, and TIME_WAIT.
- Tracks TCP retransmissions (tcp_retransmit_skb tracepoint), a key indicator of network issues.
- Logs the process ID (PID) and command name (COMM) associated with each connection.
- Logs connection details (source/destination IP and port, process ID, and state) to /var/log/socket_monitor.log.
- Skips noisy or invalid entries, like connections with IP 0.0.0.0.
- Maps TCP states to human-readable descriptions.
- Formats IP addresses for readability.
- Uses perf_buffer for real-time event handling.
- Can run continuously and provide live updates via the console and log file.
- Real-Time Logging: Captures and logs socket connections as they occur.
- Detailed Insights: Provides source and destination IP addresses, ports, PIDs, command names, and TCP states.
- Formatted Output: Logs are time-stamped and categorized (e.g., Opened Connection, Closed Connection, Established Connection).
- Lightweight and Efficient: Runs efficiently using eBPF without significant performance overhead.

**BENEFITS:**
- Simplifies network monitoring by highlighting key details often buried in more complex tools.
- Reduces the need for deep packet analysis with tools like tcpdump or wireshark.
- Enhances operational awareness for system administrators managing critical infrastructure.

**LIMITATIONS:**
- IP4 only (wip)
- Need to add Dynamic Filters / pid/ip/ports
- Enhance Error Handling
- Perfomance Tuning
```
## Use Cases

Security Monitoring: Detect suspicious or unauthorized network activity.
Performance Debugging: Identify network latency or dropped connections by observing TCP states.
Audit Logging: Maintain a comprehensive record of all socket-level network interactions.
Real-Time Monitoring: Observe live network activity without the complexity of tools like tcpdump or wireshark. In addition, no network frames are captured so it's perfect for high security networks.

## Install
For the script version simply ensure you have python 3.11+
```plaintext
pip install bcc
python3 /root/scripts/socket-snoop.py
```
or as a service 
```plaintext
cat <<EOF > /etc/systemd/system/sockets-monitor.service
[Unit]
Description=Socket Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /root/scripts/sockets.py  #edit to taste
Restart=on-failure
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=sockets-monitor
WorkingDirectory=/root/scripts/  #edit to taste
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
```
and
```plaintext
systemctl daemon-reload
systemctl enable sockets-monitor
systemctl start sockets-monitor
systemctl status sockets-monitor
```

### Log Examples

Sample: /var/log/socket_monitor.log
```plaintext
Dec 30 2024 22:05:25.454 State Change: SRC=10.100.10.150:39134 DST=10.100.10.202:8000 PID=30512 COMM=audacious STATE=Connection Closing (FIN_WAIT1)
Dec 30 2024 22:05:25.455 State Change: SRC=10.100.10.150:39134 DST=10.100.10.202:8000 PID=30512 COMM=audacious STATE=Connection Closed
Dec 30 2024 22:05:25.455 State Change: SRC=10.100.10.150:0 DST=10.100.10.202:8000 PID=30512 COMM=audacious STATE=Connection Opening (SYN_SENT)
Dec 30 2024 22:05:25.455 State Change: SRC=10.100.10.150:39136 DST=10.100.10.202:8000 PID=0 COMM=swapper/4 STATE=Connection Established
Dec 30 2024 22:05:25.836 State Change: SRC=10.100.10.150:39136 DST=10.100.10.202:8000 PID=30512 COMM=audacious STATE=Connection Closing (FIN_WAIT1)
Dec 30 2024 22:05:25.836 State Change: SRC=10.100.10.150:39136 DST=10.100.10.202:8000 PID=30512 COMM=audacious STATE=Connection Closed
Dec 30 2024 22:05:25.836 State Change: SRC=10.100.10.150:0 DST=10.100.10.202:8000 PID=30512 COMM=audacious STATE=Connection Opening (SYN_SENT)
Dec 30 2024 22:05:25.836 State Change: SRC=10.100.10.150:39148 DST=10.100.10.202:8000 PID=0 COMM=swapper/6 STATE=Connection Established
Dec 30 2024 22:05:28.180 State Change: SRC=10.100.10.150:39148 DST=10.100.10.202:8000 PID=30512 COMM=audacious STATE=Connection Closing (FIN_WAIT1)
Dec 30 2024 22:05:28.180 State Change: SRC=10.100.10.150:39148 DST=10.100.10.202:8000 PID=30512 COMM=audacious STATE=Connection Closed
Dec 30 2024 22:05:28.180 State Change: SRC=10.100.10.150:0 DST=10.100.10.202:8000 PID=30512 COMM=audacious STATE=Connection Opening (SYN_SENT)
Dec 30 2024 22:05:28.180 State Change: SRC=10.100.10.150:41994 DST=10.100.10.202:8000 PID=0 COMM=swapper/7 STATE=Connection Established
Dec 30 2024 22:05:28.315 State Change: SRC=10.100.10.150:0 DST=10.100.10.202:8000 PID=30512 COMM=pool-audacious STATE=Connection Opening (SYN_SENT)
Dec 30 2024 22:05:28.316 State Change: SRC=10.100.10.150:42006 DST=10.100.10.202:8000 PID=0 COMM=swapper/5 STATE=Connection Established
Dec 30 2024 22:05:28.592 State Change: SRC=10.100.10.150:42006 DST=10.100.10.202:8000 PID=30512 COMM=pool-audacious STATE=Connection Closing (FIN_WAIT1)
Dec 30 2024 22:05:28.592 State Change: SRC=10.100.10.150:42006 DST=10.100.10.202:8000 PID=30512 COMM=pool-audacious STATE=Connection Closed
Dec 30 2024 22:05:32.526 State Change: SRC=10.100.10.150:53046 DST=185.199.108.133:443 PID=3678 COMM=Chrome_ChildIOT STATE=Connection Closing (FIN_WAIT1)
Dec 30 2024 22:05:32.526 State Change: SRC=10.100.10.150:34984 DST=185.199.108.154:443 PID=3678 COMM=Chrome_ChildIOT STATE=Connection Closing (FIN_WAIT1)
Dec 30 2024 22:05:32.526 State Change: SRC=10.100.10.150:34994 DST=185.199.108.154:443 PID=3678 COMM=Chrome_ChildIOT STATE=Connection Closing (FIN_WAIT1)

```

### Breakdown's

Example 1:
```plaintext
Dec 30 2024 13:44:03.309 Connection Established: SRC=10.100.10.150:59660 DST=104.18.34.222:443 PID=0 COMM=swapper/7
```

*  Timestamp: Dec 30 2024 13:44:03.309
*  Event Type: Connection Established
*  Source (SRC): 10.100.10.150 (source IP) and 59660 (source port)
*  Destination (DST): 104.18.34.222 (destination IP) and 443 (destination port)
*  Process ID (PID): 0 (kernel-managed thread)
*  Command Name (COMM): swapper/7 (kernel idle thread for CPU core 7)

Example 2:
```plaintext
Dec 30 2024 13:44:03.345 Connection Opening (SYN_SENT): SRC=10.100.10.150:0 DST=35.244.154.8:443 PID=3382 COMM=Chrome_ChildIOT
```

*  Timestamp: Dec 30 2024 13:44:03.345
*  Event Type: Connection Opening (SYN_SENT)
*  Source (SRC): 10.100.10.150 (source IP) and 0 (port not yet assigned as connection is opening)
*  Destination (DST): 35.244.154.8 (destination IP) and 443 (destination port)
*  Process ID (PID): 3382 (user-space process ID)
*  Command Name (COMM): Chrome_ChildIOT (child process of Chrome browser)

Example 3:
```plaintext
Monitoring socket connections with enhanced metrics. Logs will be written to /var/log/socket_monitor.log
Dec 30 2024 22:00:46.334 State Change: SRC=10.100.10.150:22 DST=10.100.10.197:62382 PID=0 COMM=swapper/0 STATE=Connection Closing (CLOSE_WAIT)
Dec 30 2024 22:00:46.337 State Change: SRC=10.100.10.150:22 DST=10.100.10.197:62382 PID=43190 COMM=sshd-session STATE=Connection Closing (LAST_ACK)
Dec 30 2024 22:00:46.350 State Change: SRC=10.100.10.150:22 DST=10.100.10.197:62382 PID=0 COMM=swapper/0 STATE=Connection Closed
Dec 30 2024 22:00:46.372 State Change: SRC=10.100.10.150:22 DST=10.100.10.197:62383 PID=0 COMM=swapper/3 STATE=Connection Closing (CLOSE_WAIT)
Dec 30 2024 22:00:46.375 State Change: SRC=10.100.10.150:22 DST=10.100.10.197:62383 PID=43194 COMM=sshd-session STATE=Connection Closing (LAST_ACK)
Dec 30 2024 22:00:46.377 State Change: SRC=10.100.10.150:22 DST=10.100.10.197:62383 PID=0 COMM=swapper/3 STATE=Connection Closed
Dec 30 2024 22:00:47.799 State Change: SRC=10.100.10.150:22 DST=10.100.10.197:62407 PID=0 COMM=swapper/5 STATE=Connection Established
Dec 30 2024 22:00:47.929 State Change: SRC=10.100.10.150:22 DST=10.100.10.197:62408 PID=0 COMM=swapper/7 STATE=Connection Established
^C
```

Connection Report:
```plaintext
Stopping monitoring...

Connection Lifecycles:
Connection: 10.100.10.150:22 -> 10.100.10.197:62382
  Dec 30 2024 22:00:46.334: Connection Closing (CLOSE_WAIT)
  Dec 30 2024 22:00:46.337: Connection Closing (LAST_ACK)
  Dec 30 2024 22:00:46.350: Connection Closed
Connection: 10.100.10.150:22 -> 10.100.10.197:62383
  Dec 30 2024 22:00:46.372: Connection Closing (CLOSE_WAIT)
  Dec 30 2024 22:00:46.375: Connection Closing (LAST_ACK)
  Dec 30 2024 22:00:46.377: Connection Closed
Connection: 10.100.10.150:22 -> 10.100.10.197:62407
  Dec 30 2024 22:00:47.799: Connection Established
Connection: 10.100.10.150:22 -> 10.100.10.197:62408
  Dec 30 2024 22:00:47.929: Connection Established
```
The following is an example output of the tool monitoring SSH connections (SRC=10.100.10.150:22) between a server and a client (DST=10.100.10.197):

A connection lifecycle starts with an Established state, 
transitions through CLOSE_WAIT, 
and eventually reaches Closed.
Each state change is associated with the process managing it (e.g., sshd-session or swapper).
