# AttackSurfaceAudit-Tool 
### - is a lightweight, read-only Linux security baseline auditing tool designed for system administrators, DevOps engineers, and blue teams. It inspects common misconfigurations and attack surfaces that attackers routinely abuse — without exploiting, modifying, or disrupting the system.

Lightweight Linux Security Baseline Auditor for Blue Teams
> Auditing ≠ hacking.
_This tool performs safe configuration checks only._

# Why AttackSurfaceAudit Tool?
Most real-world compromises don’t start with zero-days.
They start with:
> Weak authentication
> Misconfigured sudo
> World-writable files
> Forgotten services
> Poor logging
> Excessive privileges

# AttackSurfaceAudit focuses on high-impact, attacker-relevant weaknesses and explains:
> What was found
> Why it matters
> What an admin should do next
> Key Features
> Read-only and safe for production systems
> Single Bash script (no dependencies)
> Clear severity levels: [OK], [WARN], [CRITICAL]
> Lists exact files, users, services, and paths
> Explains attacker relevance and remediation
> Severity-based exit codes (CI/CD friendly)
> Designed for learning, audits, and baselining

# What Does It Check?
## 1. Authentication & Access Control

> SSH root login status
> SSH password authentication
> Multiple UID 0 accounts
> Empty-password users
> Privileged group membership

### Why it matters:
_Weak authentication is the fastest path to compromise._

## 2. Privilege Escalation Exposure

> NOPASSWD sudo rules
> Users in sudo, wheel, docker
> Writable files owned by root
> SUID / SGID binaries
> Writable cron directories

### Why it matters:
_Misconfigured privileges = instant root._

## 3. File System & Permission Weaknesses

> World-writable files and directories
> World-writable files owned by root
> Writable system paths
> Hidden files in temporary directories
> Startup scripts and persistence locations

### Why it matters:
_Persistence lives in the filesystem._

## 4. Network Exposure & Services

> Listening ports and owning processes
> Services bound to all interfaces
> Legacy/insecure services (Telnet, FTP, rsh)
> Firewall status
> Docker-exposed ports

### Why it matters:
_Every open port expands the attack surface._

## 5. Kernel & System Hardening

> Kernel version awareness
> ASLR status
> IP forwarding
> Unsafe sysctl values

### Why it matters:
_Kernel weaknesses lead to full system compromise._

## 6. Logging & Monitoring Gaps

> auditd status
> Syslog availability
> Log directory permissions
> Log rotation configuration

### Why it matters:
_No logs = invisible attacker._

## 7. Persistence Indicators (Safe Checks)

> System and user cron jobs
> Systemd timers
> SSH authorized_keys permissions
> Shell startup file ownership

### Why it matters:
_Persistence survives reboots._


# *Installation*
'''
git clone https://github.com/yourusername/AttackSurfaceAudit.git
cd AttackSurfaceAudit
chmod +x AttackSurfaceAudit.sh
'''

# *Usage*
'sudo ./AttackSurfaceAudit.sh'

Some checks require root to read system files safely.

## How This Differs from Lynis and Similar Tools

> Single Bash script
> Minimal & readable
> Attacker-centric focus
> Educational output
> Safe by design

## Who Should Use This?

> System administrators
> DevOps / SRE teams
> Blue teams
> Incident responders
> Security learners and homelabs

## Contributing

_Contributions are welcome:_


__ This tool is provided for defensive security auditing only.
Use responsibly and only on systems you own or are authorized to audit.__
