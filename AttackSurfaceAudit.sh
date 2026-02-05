#!/usr/bin/env bash

# ================================================================
# SECUREAUDIT - Interactive Security Baseline Assessment
# Version: 1.0.0
# Author: cyberacademytz
# License: MIT
# ================================================================

set -o nounset -o pipefail
shopt -s nocasematch

# ================================================================
# CONFIGURATION & CONSTANTS
# ================================================================

# ANSI Color Codes with bold enhancement
readonly RED='\033[1;31m'
readonly YELLOW='\033[1;33m'
readonly GREEN='\033[1;32m'
readonly BLUE='\033[1;34m'
readonly MAGENTA='\033[1;35m'
readonly CYAN='\033[1;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly RESET='\033[0m'
readonly DIM='\033[2m'

# Security thresholds
readonly MAX_FAILED_LOGINS=10
readonly OLD_KERNEL_DAYS=365
readonly WARN_UPDATE_DAYS=7
readonly CRIT_UPDATE_DAYS=30

# Output formatting
readonly SEPARATOR="================================================================"
readonly SUBSEPARATOR="----------------------------------------------------------------"

# ================================================================
# GLOBALS
# ================================================================

declare -i CRITICAL=0 WARNINGS=0 PASSED=0
declare OUTPUT_FILE=""
declare VERBOSE=false
declare QUICK_SCAN=false
declare SELECTED_CHECKS=()

# Print functions with consistent formatting
print_critical() { 
    echo -e "${RED}✗ [CRITICAL]${RESET} $1"
    CRITICAL=$((CRITICAL + 1))
    [[ -n "$OUTPUT_FILE" ]] && echo "[CRITICAL] $1" >> "$OUTPUT_FILE"
}

print_warning() { 
    echo -e "${YELLOW}⚠ [WARNING]${RESET} $1"
    WARNINGS=$((WARNINGS + 1))
    [[ -n "$OUTPUT_FILE" ]] && echo "[WARNING] $1" >> "$OUTPUT_FILE"
}

print_ok() { 
    echo -e "${GREEN}✓ [OK]${RESET} $1"
    PASSED=$((PASSED + 1))
    [[ -n "$OUTPUT_FILE" ]] && echo "[OK] $1" >> "$OUTPUT_FILE"
}

print_info() { 
    echo -e "${BLUE}ℹ [INFO]${RESET} $1"
    [[ -n "$OUTPUT_FILE" ]] && echo "[INFO] $1" >> "$OUTPUT_FILE"
}

print_header() {
    echo -e "\n${CYAN}${BOLD}$SEPARATOR${RESET}"
    echo -e "${WHITE}${BOLD}$1${RESET}"
    echo -e "${CYAN}${BOLD}$SEPARATOR${RESET}\n"
}

# ================================================================
# UTILITY FUNCTIONS
# ================================================================

is_root() { [[ $EUID -eq 0 ]]; }
command_exists() { command -v "$1" &>/dev/null; }
file_readable() { [[ -r "$1" ]]; }

safe_grep() {
    local file="$1"
    local pattern="$2"
    [[ -f "$file" ]] && grep -q "$pattern" "$file" 2>/dev/null
}

# Fix for the problematic safe_find function
safe_find() {
    local path="$1"
    local args="$2"
    [[ -d "$path" ]] && find "$path" $args 2>/dev/null | head -20
}

days_since() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local now modtime
        now=$(date +%s)
        modtime=$(stat -c %Y "$file" 2>/dev/null || echo 0)
        echo $(( (now - modtime) / 86400 ))
    else
        echo 9999
    fi
}

# ================================================================
# CHECK FUNCTIONS (Fixed)
# ================================================================

check_authentication() {
    print_header "1. AUTHENTICATION & ACCESS CONTROL"
    print_info "Attack vector: Weak authentication = instant compromise"
    
    # SSH Configuration
    local sshd_cfg="/etc/ssh/sshd_config"
    
    # SSH-001: PermitRootLogin disabled
    if safe_grep "$sshd_cfg" "^PermitRootLogin.*no"; then
        print_ok "SSH root login disabled (Prevents direct root access)"
    else
        print_critical "SSH root login enabled"
        echo "    ${DIM}Remediation: Set 'PermitRootLogin no' in $sshd_cfg${RESET}"
    fi
    
    # SSH-002: PasswordAuthentication disabled
    if safe_grep "$sshd_cfg" "^PasswordAuthentication.*no"; then
        print_ok "SSH password auth disabled (Enforces key-based auth)"
    else
        print_warning "SSH password authentication enabled"
        echo "    ${DIM}Remediation: Set 'PasswordAuthentication no', use SSH keys${RESET}"
    fi
    
    # SSH-003: Protocol version 2 only
    if safe_grep "$sshd_cfg" "^Protocol.*2"; then
        print_ok "SSH Protocol 2 enforced (SSHv1 is insecure)"
    else
        print_critical "SSH may allow Protocol 1 (deprecated and vulnerable)"
    fi
    
    # SSH-004: Additional hardening
    for setting in "MaxAuthTries 3" "ClientAliveInterval 300" "X11Forwarding no"; do
        local key="${setting%% *}"
        if ! safe_grep "$sshd_cfg" "^$key"; then
            print_warning "SSH hardening missing: $key"
        fi
    done
    
    # USR-001: Empty password accounts
    local empty_passwords
    if file_readable "/etc/shadow"; then
        empty_passwords=$(awk -F: '($2=="!"||$2=="*"||$2==""){print $1}' /etc/shadow 2>/dev/null)
        if [[ -z "$empty_passwords" ]]; then
            print_ok "No empty password accounts found"
        else
            print_critical "Accounts with empty/disabled passwords: $empty_passwords"
            echo "    ${DIM}Remediation: Lock accounts or set secure passwords${RESET}"
        fi
    else
        print_warning "Cannot read /etc/shadow (run as root for complete check)"
    fi
    
    # USR-002: Multiple UID 0 accounts
    local uid0_users
    uid0_users=$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)
    if [[ "$uid0_users" == "root" ]] || [[ -z "$uid0_users" ]]; then
        print_ok "Only root has UID 0 (Prevents privilege confusion)"
    else
        print_critical "Multiple UID 0 users: $uid0_users"
        echo "    ${DIM}Remediation: Change UID of non-root accounts with UID 0${RESET}"
    fi
    
    # USR-003: Login shells without passwords - FIXED
    if file_readable "/etc/shadow"; then
        local shell_users
        shell_users=$(awk -F: '$7!="/bin/false" && $7!="/usr/sbin/nologin"{print $1}' /etc/passwd 2>/dev/null)
        local no_passwords=""
        for user in $shell_users; do
            local pass_entry
            pass_entry=$(grep "^$user:" /etc/shadow 2>/dev/null)
            if [[ "$pass_entry" =~ ^$user:(!:|\*:) ]]; then
                no_passwords="$no_passwords $user"
            fi
        done
        
        if [[ -z "$no_passwords" ]]; then
            print_ok "All login shell accounts have password requirements"
        else
            print_critical "Login shell accounts with disabled passwords: $no_passwords"
        fi
    fi
}

check_privilege_escalation() {
    print_header "2. PRIVILEGE ESCALATION EXPOSURE"
    print_info "Attack vector: Misconfigured sudo = instant root access"
    
    # SUDO-001: NOPASSWD rules
    local nopasswd_rules
    nopasswd_rules=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d 2>/dev/null | head -10)
    if [[ -z "$nopasswd_rules" ]]; then
        print_ok "No NOPASSWD sudo rules found (Requires password for privilege)"
    else
        print_critical "NOPASSWD sudo rules detected (Password bypass):"
        echo "$nopasswd_rules" | while read -r line; do
            echo "    ${DIM}$line${RESET}"
        done
        echo "    ${DIM}Remediation: Remove NOPASSWD or require authentication${RESET}"
    fi
    
    # SUDO-002: Privileged group members
    echo -e "${WHITE}Privileged group memberships:${RESET}"
    for group in sudo wheel docker; do
        if getent group "$group" &>/dev/null; then
            local members
            members=$(getent group "$group" | cut -d: -f4)
            if [[ -n "$members" ]]; then
                print_warning "$group group members: $members"
                echo "    ${DIM}Review: Ensure all members require these privileges${RESET}"
            fi
        fi
    done
    
    # FS-001: Writable root-owned files - FIXED
    local writable_root_files
    writable_root_files=$(find / -type f -perm -0002 -user root 2>/dev/null | grep -v "^/proc" | grep -v "^/sys" | head -20)
    if [[ -z "$writable_root_files" ]]; then
        print_ok "No world-writable files owned by root"
    else
        print_critical "World-writable files owned by root (Privilege escalation risk):"
        # Store first file for remediation example
        local first_file=""
        while read -r file; do
            if [[ -z "$first_file" ]]; then
                first_file="$file"
            fi
            echo "    ${DIM}$file${RESET}"
        done <<< "$writable_root_files"
        
        if [[ -n "$first_file" ]]; then
            echo "    ${DIM}Remediation: chmod o-w '$first_file' or change ownership${RESET}"
        else
            echo "    ${DIM}Remediation: chmod o-w on these files or change ownership${RESET}"
        fi
    fi
}

check_filesystem_permissions() {
    print_header "3. FILE SYSTEM PERMISSIONS"
    print_info "Attack vector: Writable system paths = persistence & backdoors"
    
    # FS-002: World-writable files
    local ww_count
    ww_count=$(find / -type f -perm -0002 2>/dev/null | grep -v "^/proc" | grep -v "^/sys" | wc -l)
    if [[ $ww_count -eq 0 ]]; then
        print_ok "No world-writable files found"
    else
        print_warning "$ww_count world-writable files found (Limited exposure)"
        echo "    ${DIM}Remediation: chmod o-w on non-essential files${RESET}"
    fi
    
    # FS-003: /tmp security
    if [[ -d "/tmp" ]]; then
        local tmp_mode
        tmp_mode=$(stat -c %a /tmp 2>/dev/null || echo "000")
        if [[ "$tmp_mode" == "1777" ]]; then
            print_ok "/tmp has sticky bit set (Prevents file deletion by others)"
        else
            print_warning "/tmp missing sticky bit (Mode: $tmp_mode)"
        fi
    fi
}

check_network_exposure() {
    print_header "4. NETWORK EXPOSURE & SERVICES"
    print_info "Attack vector: Every open port is a potential entry point"
    
    # NET-001: Listening services
    if command_exists "ss"; then
        local listen_count
        listen_count=$(ss -tuln 2>/dev/null | grep -c "LISTEN")
        print_info "$listen_count listening ports detected"
    fi
    
    # NET-002: Legacy/insecure services
    local legacy_ports=":21 :23 :512 :513 :514 :1099 :2049 :6000"
    local legacy_detected=""
    
    if command_exists "ss"; then
        for port in $legacy_ports; do
            if ss -tuln 2>/dev/null | grep -q "$port"; then
                legacy_detected="$legacy_detected $port"
            fi
        done
    fi
    
    if [[ -n "$legacy_detected" ]]; then
        print_critical "Legacy/insecure services detected on:$legacy_detected"
        echo "    ${DIM}Risk: FTP, Telnet, rsh are unencrypted and vulnerable${RESET}"
    else
        print_ok "No legacy insecure services detected"
    fi
    
    # NET-003: Firewall status
    local firewall_active=false
    
    if command_exists "ufw"; then
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            print_ok "UFW firewall active"
            firewall_active=true
        fi
    elif command_exists "firewall-cmd"; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            print_ok "firewalld active"
            firewall_active=true
        fi
    elif command_exists "iptables"; then
        if iptables -L INPUT -n 2>/dev/null | grep -q "DROP\|REJECT"; then
            print_ok "iptables has restrictive rules"
            firewall_active=true
        fi
    fi
    
    if [[ "$firewall_active" == false ]]; then
        print_critical "No active firewall detected"
        echo "    ${DIM}Remediation: Enable and configure a host firewall${RESET}"
    fi
}

check_kernel_hardening() {
    print_header "5. KERNEL & SYSTEM HARDENING"
    print_info "Attack vector: Kernel vulnerabilities = full system compromise"
    
    # KERN-001: Kernel version age
    local kernel_version
    kernel_version=$(uname -r)
    print_info "Kernel: $kernel_version"
    
    # KERN-002: ASLR status
    if [[ -f "/proc/sys/kernel/randomize_va_space" ]]; then
        local aslr_value
        aslr_value=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "0")
        case $aslr_value in
            2) print_ok "ASLR fully enabled (Mitigates memory corruption attacks)" ;;
            1) print_warning "ASLR partially enabled (Limited protection)" ;;
            0) print_critical "ASLR disabled (Memory attacks more effective)" ;;
            *) print_warning "ASLR status unknown" ;;
        esac
    fi
    
    # KERN-003: IP forwarding
    if [[ -f "/proc/sys/net/ipv4/ip_forward" ]]; then
        local ip_forward
        ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
        if [[ "$ip_forward" == "0" ]]; then
            print_ok "IP forwarding disabled (Unless this system is a router)"
        else
            print_warning "IP forwarding enabled"
            echo "    ${DIM}Investigation: Verify if this system acts as a router${RESET}"
        fi
    fi
}

check_package_hygiene() {
    print_header "6. PACKAGE & UPDATE HYGIENE"
    print_info "Attack vector: Unpatched software = known exploit target"
    
    # PKG-001: Package manager last update
    local last_update_days=999
    
    if [[ -f "/var/lib/apt/periodic/update-success-stamp" ]]; then
        last_update_days=$(days_since "/var/lib/apt/periodic/update-success-stamp")
    fi
    
    if [[ $last_update_days -lt $WARN_UPDATE_DAYS ]]; then
        print_ok "Recent package updates ($last_update_days days ago)"
    elif [[ $last_update_days -lt $CRIT_UPDATE_DAYS ]]; then
        print_warning "Package updates $last_update_days days old"
    else
        print_critical "No package updates for $last_update_days+ days"
        echo "    ${DIM}Remediation: Run 'apt update && apt upgrade' or equivalent${RESET}"
    fi
}

check_logging_monitoring() {
    print_header "7. LOGGING & MONITORING"
    print_info "Attack vector: Disabled logs = undetected breaches"
    
    # LOG-001: Syslog/rsyslog status
    if systemctl is-active rsyslog &>/dev/null; then
        print_ok "rsyslog service running"
    elif systemctl is-active syslog-ng &>/dev/null; then
        print_ok "syslog-ng service running"
    else
        print_critical "No syslog service running"
        echo "    ${DIM}Remediation: Enable rsyslog or syslog-ng service${RESET}"
    fi
    
    # LOG-002: Auditd status
    if systemctl is-active auditd &>/dev/null; then
        print_ok "auditd service running (Advanced auditing)"
    else
        print_warning "auditd not running (Limited audit capabilities)"
        echo "    ${DIM}Remediation: Install and configure auditd${RESET}"
    fi
}

# ================================================================
# INTERACTIVE MENU SYSTEM
# ================================================================

show_banner() {
    clear
    echo -e "${CYAN}"
    echo '    ╔═══════════════════════════════════════════════════════════╗'
    echo '    ║                                                           ║'
    echo '    ║   ███████╗ ███████╗  ██████╗ ██╗   ██╗ ██████╗ ███████╗   ║'
    echo '    ║   ██╔════╝ ██╔════╝ ██╔════╝ ██║   ██║ ██╔══██╗██╔════╝   ║'
    echo '    ║   ███████╗ █████╗   ██║      ██║   ██║ ██████╔╝█████╗     ║'
    echo '    ║   ╚════██║ ██╔══╝   ██║      ██║   ██║ ██╔══██╗██╔══╝     ║'
    echo '    ║   ███████║ ███████╗ ╚██████╗ ╚██████╔╝ ██║  ██║███████╗   ║'
    echo '    ║   ╚══════╝ ╚══════╝  ╚═════╝  ╚═════╝  ╚═╝  ╚═╝╚══════╝   ║'
    echo '    ║                                                           ║'
    echo '    ║           SECURITY-AttackSurfaceAudit Tool                ║'
    echo '    ║            v1.0.0  |  www.tca.ac.tc                       ║'
    echo '    ║                                                           ║'
    echo '    ╚═══════════════════════════════════════════════════════════╝'
    echo -e "${RESET}"
}

show_menu() {
    local choice
    clear
    show_banner
    
    echo -e "${CYAN}${BOLD}MAIN MENU${RESET}"
    echo -e "${WHITE}${BOLD}$SEPARATOR${RESET}"
    echo -e "${GREEN}1.${RESET} Authentication & Access Control"
    echo -e "${GREEN}2.${RESET} Privilege Escalation Exposure"
    echo -e "${GREEN}3.${RESET} Filesystem & Permissions"
    echo -e "${GREEN}4.${RESET} Network Exposure & Services"
    echo -e "${GREEN}5.${RESET} Kernel & System Hardening"
    echo -e "${GREEN}6.${RESET} Package & Update Hygiene"
    echo -e "${GREEN}7.${RESET} Logging & Monitoring"
    echo -e "${GREEN}8.${RESET} Run ALL Checks"
    echo -e "${GREEN}9.${RESET} Custom Selection"
    echo -e "${GREEN}0.${RESET} Exit"
    echo -e "${WHITE}${BOLD}$SEPARATOR${RESET}"
    
    read -p "Select option [0-9]: " choice
    
    case $choice in
        1) 
            reset_counters
            check_authentication
            show_results
            pause_and_return
            ;;
        2)
            reset_counters
            check_privilege_escalation
            show_results
            pause_and_return
            ;;
        3)
            reset_counters
            check_filesystem_permissions
            show_results
            pause_and_return
            ;;
        4)
            reset_counters
            check_network_exposure
            show_results
            pause_and_return
            ;;
        5)
            reset_counters
            check_kernel_hardening
            show_results
            pause_and_return
            ;;
        6)
            reset_counters
            check_package_hygiene
            show_results
            pause_and_return
            ;;
        7)
            reset_counters
            check_logging_monitoring
            show_results
            pause_and_return
            ;;
        8)
            reset_counters
            run_all_checks
            show_results
            pause_and_return
            ;;
        9)
            custom_selection_menu
            ;;
        0)
            echo -e "\n${GREEN}Thank you for using Security Audit Tool!${RESET}"
            exit 0
            ;;
        *)
            echo -e "\n${RED}Invalid option. Please try again.${RESET}"
            sleep 2
            show_menu
            ;;
    esac
}

custom_selection_menu() {
    local choices=()
    clear
    show_banner
    
    echo -e "${CYAN}${BOLD}CUSTOM CHECK SELECTION${RESET}"
    echo -e "${WHITE}${BOLD}$SEPARATOR${RESET}"
    echo "Select checks to run (space to select, enter when done):"
    echo
    
    # Define check options
    local options=(
        "1. Authentication & Access Control"
        "2. Privilege Escalation Exposure" 
        "3. Filesystem & Permissions"
        "4. Network Exposure & Services"
        "5. Kernel & System Hardening"
        "6. Package & Update Hygiene"
        "7. Logging & Monitoring"
    )
    
    # Display options
    for i in "${!options[@]}"; do
        echo -e "${GREEN}[ ]${RESET} ${options[$i]}"
    done
    
    echo -e "\n${YELLOW}Note:${RESET} Use spacebar to toggle selection, enter to run selected checks"
    echo -e "${WHITE}${BOLD}$SEPARATOR${RESET}"
    
    # Simple selection (for bash without select)
    echo -e "\n${CYAN}Enter numbers separated by spaces (e.g., 1 3 5):${RESET}"
    read -p "Your selection: " -a choices
    
    if [[ ${#choices[@]} -eq 0 ]]; then
        echo -e "\n${YELLOW}No checks selected. Returning to main menu.${RESET}"
        sleep 2
        show_menu
        return
    fi
    
    # Run selected checks
    reset_counters
    for choice in "${choices[@]}"; do
        case $choice in
            1) check_authentication ;;
            2) check_privilege_escalation ;;
            3) check_filesystem_permissions ;;
            4) check_network_exposure ;;
            5) check_kernel_hardening ;;
            6) check_package_hygiene ;;
            7) check_logging_monitoring ;;
            *) echo -e "${YELLOW}Skipping invalid option: $choice${RESET}" ;;
        esac
    done
    
    show_results
    pause_and_return
}

reset_counters() {
    CRITICAL=0
    WARNINGS=0
    PASSED=0
}

show_results() {
    print_header "CHECK COMPLETED"
    
    echo -e "${WHITE}${BOLD}Results Summary:${RESET}"
    echo -e "  ${GREEN}✓ Passed:${RESET}  $PASSED"
    echo -e "  ${YELLOW}⚠ Warnings:${RESET} $WARNINGS"
    echo -e "  ${RED}✗ Critical:${RESET} $CRITICAL"
    echo
    
    if [[ $CRITICAL -gt 0 ]]; then
        echo -e "${RED}${BOLD}ACTION REQUIRED: Critical issues found!${RESET}"
    elif [[ $WARNINGS -gt 0 ]]; then
        echo -e "${YELLOW}${BOLD}Review recommended: Warnings found.${RESET}"
    else
        echo -e "${GREEN}${BOLD}All checks passed!${RESET}"
    fi
}

pause_and_return() {
    echo -e "\n${DIM}Press Enter to return to main menu...${RESET}"
    read -r
    show_menu
}

run_all_checks() {
    check_authentication
    check_privilege_escalation
    check_filesystem_permissions
    check_network_exposure
    check_kernel_hardening
    check_package_hygiene
    check_logging_monitoring
}

# ================================================================
# MAIN EXECUTION
# ================================================================

main() {
    # Parse command line arguments first
    while [[ $# -gt 0 ]]; do
        case $1 in
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --output|-o)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo
                echo "Interactive security audit tool for Linux systems"
                echo
                echo "Options:"
                echo "  --verbose, -v    Show detailed information"
                echo "  --output, -o FILE Write output to file"
                echo "  --help, -h       Show this help message"
                echo
                echo "Features:"
                echo "  - Interactive menu system"
                echo "  - Selective checking"
                echo "  - Detailed remediation guidance"
                echo
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Start with interactive menu
    show_menu
}

# Error handling
trap 'echo -e "${RED}Error occurred at line $LINENO${RESET}"; sleep 2; show_menu' ERR

# Run main function
main "$@"