<img width="1177" height="569" alt="image" src="https://github.com/user-attachments/assets/907a3fd5-7aa5-41df-8d59-21919848572f" />

## LogHog (lh)

The ultimate log ferensics tool that ANYONE can use.

## "modes"

**TAIL**  *Default*
Automatically stitches logs together by timestamp, enabling real-time event monitoring. This mode makes 
it easy to follow and investigate incidents like authentication failures, permission denials, and SQL 
injections. **Press `CTRL+C`** to quit.

**LESS**  *Secondary*
Buffers are sent directly to **less** for further editing and in-depth review, searches, and complex log 
analysis.  
**Press `h` for help** or **`q` to quit to menu**.


**(A)uth** Fine Every Authentication error instantly
**(E)rrors** Identify ALL system errors effortlessly
**(L)ive All** This special version of "tail" seemlessly "Stitches" logs together from ALL sources and appends them by timestamp to esnure they are in order.
**(N)etwork** Rips apart anything to do with netwroking protocols.
**(R)egEX** Simplified (or complex) rgular expression parcer.. no need for complex regular expressions simply seperate your key words error|fail|warn|ect
**(I)P Search** Searched for ip addresses
**(S)et Log Paths**
**(J)SON Export**
**(H)elp**


**Remote Operation**
Changing paths also accepts network shares / mounts and devices, allowing for consumption of logs from ANY TARGET local or remote.


## Other key features include:
  
**Regex Search**: Allows powerful searches across all logs using regular expressions, making it simple to detect 
patterns like IP addresses, error messages, and unauthorized access attempts. 

**Network Protocol Filter**: Filters logs by protocol (HTTP, FTP, SSH, etc.) to quickly identify network-related 
issues.

**Error Filtering**: Isolates error-related events like failures, critical warnings, and socket timeouts for faster 
troubleshooting.

**Stupid FAST!**: Witten in C lh will instantly rip through your logs.

**

# Install.

  this bootstrap installer should work for yum/dnf/apt based package installers, tested on rocky 8.9
  
  ```bash
  sudo su -
  curl -sL https://github.com/unixbox-net/lh/raw/main/install.sh | sudo bash
  lh
  ```

  Output files can be found
  ```bash
  ~/lh/rpmbuild/BUILD/lh-1.0.0/lh (compiled binary)
  ~/lh/rpmbuild/RPMS/x86_64/lh-1.0.0-1.el8.x86_64.rpm (package)
  etc
  ```
   
  Depedicies
  ```bash
  json-c readline

  dnf install json-c-devel
  dnf install readline-devel
  clang lh.c -o lh -lreadline -ljson-c
  ```

FreeBSD
clang -I/usr/local/include -L/usr/local/lib -ljson-c -lreadline -lncurses lh.c -o lh

