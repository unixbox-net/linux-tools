# aws-meta.py – AWS EC2 Metadata Inspector

The **AWS Metadata Inspector** is a lightweight Python utility that queries the **AWS EC2 Instance Metadata Service (IMDS)** to provide a clean, human-friendly view of an instance’s identity and environment.  

It supports both **IMDSv2 (token-based, recommended)** and **IMDSv1 (fallback)**, and presents results in either **Markdown** or **JSON**, making it equally suitable for human troubleshooting or machine automation.

---

## Features
- **Summary mode**  
  Get the essentials at a glance: Instance ID, type, region, zone, account ID, public/private IPs, hostname, and IAM role (if any).

- **Full mode**  
  Dump the entire metadata tree in JSON (with **redaction of sensitive fields** like keys, tokens, secrets).

- **IMDSv2-first**  
  Secure by default: requests an IMDSv2 session token, falling back to IMDSv1 only if necessary (with a clear note in output).

- **Multiple output formats**  
  Choose **Markdown** for easy human reading, or **JSON** for automation.

- **Robust HTTP client**  
  Built-in retries, timeouts, and urllib3 v1/v2 compatibility.

---

## Usage

```bash
# Summary (Markdown)
./aws-meta.py

# Summary (JSON)
./aws-meta.py --format json

# Full metadata dump (JSON, redacted)
./aws-meta.py --full > full.json

# Full dump (Markdown-wrapped JSON)
./aws-meta.py --full --format md

# Verbose mode (debug HTTP traffic)
./aws-meta.py -v

```

---
## Example
`full.json`

```json
{
  "dynamic": {
    "instance-identity": {
      "document": {
        "accountId": "252144205993",
        "architecture": "x86_64",
        "availabilityZone": "ca-central-1a",
        "billingProducts": null,
        "devpayProductCodes": null,
        "imageId": "ami-0ca3fe9992272540b",
        "instanceId": "i-075916e4f9e35a39e",
        "instanceType": "t3.micro",
        "kernelId": null,
        "marketplaceProductCodes": null,
        "pendingTime": "2025-08-28T03:13:12Z",
        "privateIp": "172.31.28.114",
        "ramdiskId": null,
        "region": "ca-central-1",
        "version": "2017-09-30"
      }
    }
  },
  "meta-data": {
    "hostname": "ip-172-31-28-114.ca-central-1.compute.internal",
    "instance-id": "i-075916e4f9e35a39e",
    "instance-type": "t3.micro",
    "local-ipv4": "172.31.28.114",
    "placement": {
      "availability-zone": "ca-central-1a"
    },
    "public-ipv4": "3.96.194.31"
  },
  "notes": []
}
```
