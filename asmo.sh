#!/bin/bash

# ASMODEUS - A script to report basic system information in a table format.

# Configuration
OUTPUT_FILE=""
COLOR_OUTPUT=true 

OS_TYPE=$(uname -s)

if [ -t 1 ] && [ "$COLOR_OUTPUT" = true ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    PURPLE=''
    CYAN=''
    NC=''
fi

OS_NAME=""
KERNEL_VERSION=""
ARCHITECTURE=""
HOSTNAME_VAL=""
UPTIME_VAL=""
CURRENT_USER=""
INTERNAL_IP=""
EXTERNAL_IP=""
CPU_USAGE=""
MEMORY_USAGE=""
DISK_USAGE=""

OPEN_PORTS=""
ACTIVE_CONNECTIONS=""
ROUTING_TABLE=""
DNS_SERVERS=""

LOGGED_IN_USERS=""
LAST_LOGIN=""
SUDO_USERS=""
PASS_MAX_DAYS=""
PASS_MIN_LEN=""

RUNNING_SERVICES=""
INSTALLED_PACKAGES=""
WEB_SERVER_VERSION=""
DB_SERVER_VERSION=""

FIREWALL_STATUS=""
SSH_ROOT_LOGIN=""
SSH_PASS_AUTH=""
SELINUX_STATUS=""
APPARMOR_STATUS=""

LAST_ACCEPTED_LOGIN=""
BASH_HISTORY_SIZE=""
ZSH_HISTORY_SIZE=""

display_intro() {
    clear
    echo -e "${CYAN}" 
    cat << "EOF"
                                   _                
     /\                           | |               
    /  \   ___ _ __ ___   ___   __| | ___ _   _ ___ 
   / /\ \ / __| '_ ` _ \ / _ \ / _` |/ _ \ | | / __|
  / ____ \\__ \ | | | | | (_) | (_| |  __/ |_| \__ \
 /_/    \_\___/_| |_| |_|\___/ \__,_|\___|\__,_|___/
                                                    
EOF
    echo -e "${NC}" 
    echo ""
    sleep 2
}

loading_animation() {
    local duration=5
    local interval=0.1
    local frames=("." ".." "..." "    ")
    local frame_count=${#frames[@]}
    local elapsed_time=0

    echo -n "Loading system data "
    while (( $(echo "$elapsed_time < $duration" | bc -l) )); do
        for (( i=0; i<frame_count; i++ )); do
            echo -en "\rLoading system data ${frames[$i]}"
            sleep $interval
            elapsed_time=$(echo "$elapsed_time + $interval" | bc -l)
            if (( $(echo "$elapsed_time >= $duration" | bc -l) )); then
                break
            fi
        done
    done
    echo -e "\rLoading system data ... Done!   "
    sleep 1
    clear
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "ASMODEUS: A powerful reconnaissance and system auditing tool."
    echo ""
    echo "Options:"
    echo "  -o, --output <file>    Save the report to a specified file."
    echo "  -n, --no-color         Disable colorized output."
    echo "  -h, --help             Display this help message and exit."
    echo ""
    echo "Examples:"
    echo "  $0"
    echo "  $0 -o asmodeus_report.txt"
    echo "  $0 --no-color"
    exit 0
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

get_system_info() {
    if [ "$OS_TYPE" == "Darwin" ]; then 
        OS_NAME="$(sw_vers -productName) $(sw_vers -productVersion) $(sw_vers -buildVersion)"
    else 
        OS_NAME="$(lsb_release -ds 2>/dev/null || cat /etc/*release 2>/dev/null | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"' || echo "Unknown OS")"
    fi
    KERNEL_VERSION="$(uname -r)"
    ARCHITECTURE="$(uname -m)"
    HOSTNAME_VAL="$(hostname)"
    UPTIME_VAL="$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}' | sed 's/,//')"
    CURRENT_USER="$(whoami)"
}

get_network_details() {
    if command_exists ip; then 
        INTERNAL_IP="$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1 || echo "N/A")"
    elif command_exists ifconfig; then 
        INTERNAL_IP="$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | awk '{print $2}' | head -n 1 || echo "N/A")"
    else
        INTERNAL_IP="N/A (Neither 'ip' nor 'ifconfig' found)"
    fi

    if command_exists curl; then
        EXTERNAL_IP="$(curl -s ifconfig.me 2>/dev/null || echo "N/A")"
    elif command_exists wget; then
        EXTERNAL_IP="$(wget -qO- ifconfig.me 2>/dev/null || echo "N/A")"
    else
        EXTERNAL_IP="N/A (Neither 'curl' nor 'wget' found)"
    fi

    if [ "$OS_TYPE" == "Darwin" ]; then
        if command_exists lsof; then
            OPEN_PORTS="$(lsof -i -P -n | grep LISTEN | awk '{print $9}' | sort -u | tr '\n' ' ' 2>/dev/null | sed 's/ *$//' || echo "N/A (May require root)")"
        elif command_exists netstat; then
            OPEN_PORTS="$(netstat -anp tcp | grep LISTEN | awk '{print $4}' | cut -d'.' -f5 | sort -u | tr '\n' ' ' 2>/dev/null | sed 's/ *$//' || echo "N/A (May require root)")"
        else
            OPEN_PORTS="N/A (Neither 'lsof' nor 'netstat' found)"
        fi
    else 
        if command_exists ss; then
            OPEN_PORTS="$(ss -tulnp 2>/dev/null | awk 'NR>1 {print $5}' | cut -d':' -f2 | sort -u | tr '\n' ' ' 2>/dev/null | sed 's/ *$//' || echo "N/A (May require root)")"
        elif command_exists netstat; then
            OPEN_PORTS="$(netstat -tulnp 2>/dev/null | awk 'NR>1 {print $4}' | cut -d':' -f2 | sort -u | tr '\n' ' ' 2>/dev/null | sed 's/ *$//' || echo "N/A (May require root)")"
        else
            OPEN_PORTS="N/A (Neither 'ss' nor 'netstat' found)"
        fi
    fi

    if [ "$OS_TYPE" == "Darwin" ]; then
        if command_exists netstat; then
            ACTIVE_CONNECTIONS="$(netstat -an 2>/dev/null | awk '/ESTABLISHED|CLOSE_WAIT|SYN_SENT/ {print $NF}' | sort | uniq -c | sed 's/^ *//' | tr '\n' '; ' 2>/dev/null | sed 's/; *$//' || echo "N/A (May require root)")"
        else
            ACTIVE_CONNECTIONS="N/A ('netstat' not found)"
        fi
    else 
        if command_exists ss; then
            ACTIVE_CONNECTIONS="$(ss -an 2>/dev/null | awk '/ESTAB|CLOSE-WAIT|SYN-SENT/ {print $NF}' | sort | uniq -c | sed 's/^ *//' | tr '\n' '; ' 2>/dev/null | sed 's/; *$//' || echo "N/A (May require root)")"
        elif command_exists netstat; then
            ACTIVE_CONNECTIONS="$(netstat -an 2>/dev/null | awk '/ESTABLISHED|CLOSE_WAIT|SYN_SENT/ {print $NF}' | sort | uniq -c | sed 's/^ *//' | tr '\n' '; ' 2>/dev/null | sed 's/; *$//' || echo "N/A (May require root)")"
        else
            ACTIVE_CONNECTIONS="N/A (Neither 'ss' nor 'netstat' found)"
        fi
    fi

    if command_exists ip; then 
        ROUTING_TABLE="$(ip r | head -n 3 | tr '\n' '; ' | sed 's/; *$//' || echo "N/A")"
    elif command_exists netstat; then 
        ROUTING_TABLE="$(netstat -rn | head -n 3 | tr '\n' '; ' | sed 's/; *$//' || echo "N/A")"
    else
        ROUTING_TABLE="N/A (Neither 'ip' nor 'netstat' found)"
    fi

    if [ -f "/etc/resolv.conf" ]; then
        DNS_SERVERS="$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ' | sed 's/ *$//' || echo "N/A")"
    elif [ "$OS_TYPE" == "Darwin" ] && command_exists scutil; then
        DNS_SERVERS="$(scutil --dns | grep 'nameserver\[[0-9]*\]' | awk '{print $2}' | tr '\n' ' ' | sed 's/ *$//' || echo "N/A")"
    else
        DNS_SERVERS="N/A (Cannot determine DNS servers)"
    fi
}

get_user_privilege_info() {
    LOGGED_IN_USERS="$(who | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/ *$//' || echo "N/A")"

    if command_exists last; then
        LAST_LOGIN="$(last -n 1 | head -n 1 | awk '{$1=$1;print}' | tr '\n' '; ' | sed 's/; *$//' || echo "N/A")"
    else
        LAST_LOGIN="N/A ('last' command not found)"
    fi

    if [ "$OS_TYPE" == "Darwin" ]; then
        SUDO_USERS="$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | awk '{for(i=2;i<=NF;i++) print $i}' | tr '\n' ' ' | sed 's/ *$//' || echo "N/A (May require root)")"
    else 
        if command_exists getent; then
            SUDO_USERS="$(getent group sudo | cut -d: -f4 | tr ',' ' ' | sed 's/ *$//' || echo "N/A (May require root)")"
        elif [ -f "/etc/group" ]; then
            SUDO_USERS="$(grep -Po '^sudo.+:\K.*$' /etc/group | tr ',' ' ' | sed 's/ *$//' || echo "N/A (May require root)")"
        else
            SUDO_USERS="N/A (Cannot determine sudo users without root)"
        fi
    fi

    if [ "$OS_TYPE" != "Darwin" ] && [ -f "/etc/login.defs" ]; then 
        PASS_MAX_DAYS="$(grep -E '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}' || echo "N/A")"
        PASS_MIN_LEN="$(grep -E '^PASS_MIN_LEN' /etc/login.defs | awk '{print $2}' || echo "N/A")"
    else
        PASS_MAX_DAYS="N/A (Linux specific)"
        PASS_MIN_LEN="N/A (Linux specific)"
    fi
}

get_software_services_info() {
    if [ "$OS_TYPE" == "Darwin" ]; then
        if command_exists launchctl; then
            RUNNING_SERVICES="$(launchctl list 2>/dev/null | grep -v '^-' | awk '{print $3}' | head -n 5 | tr '\n' '; ' | sed 's/; *$//' || echo "N/A (May require root)")"
        else
            RUNNING_SERVICES="N/A ('launchctl' not found)"
        fi
    else 
        if command_exists systemctl; then
            RUNNING_SERVICES="$(systemctl list-units --type=service --state=running 2>/dev/null | grep ".service" | awk '{print $1}' | head -n 5 | tr '\n' '; ' | sed 's/; *$//' || echo "N/A (May require root)")"
        elif command_exists service; then
            RUNNING_SERVICES="$(service --status-all 2>/dev/null | grep '+' | awk '{print $4}' | head -n 5 | tr '\n' '; ' | sed 's/; *$//' || echo "N/A (May require root)")"
        else
            RUNNING_SERVICES="N/A (Neither 'systemctl' nor 'service' found)"
        fi
    fi

    if [ "$OS_TYPE" != "Darwin" ]; then
        if command_exists dpkg; then
            INSTALLED_PACKAGES="$(dpkg -l 2>/dev/null | awk 'NR>5 {print $2}' | head -n 5 | tr '\n' ' ' | sed 's/ *$//' || echo "N/A (May require root)")"
        elif command_exists rpm; then
            INSTALLED_PACKAGES="$(rpm -qa 2>/dev/null | head -n 5 | tr '\n' ' ' | sed 's/ *$//' || echo "N/A (May require root)")"
        elif command_exists pacman; then
            INSTALLED_PACKAGES="$(pacman -Q 2>/dev/null | head -n 5 | tr '\n' ' ' | sed 's/ *$//' || echo "N/A (May require root)")"
        else
            INSTALLED_PACKAGES="N/A (No common package manager found)"
        fi
    else
        INSTALLED_PACKAGES="N/A (Linux specific)"
    fi

    if command_exists apache2; then
        WEB_SERVER_VERSION="$(apache2 -v 2>/dev/null | grep "Server version" | cut -d' ' -f3 | tr '\n' ' ' | sed 's/ *$//' || echo "N/A")"
    elif command_exists nginx; then
        WEB_SERVER_VERSION="$(nginx -v 2>&1 | grep "nginx version" | cut -d'/' -f2 | tr '\n' ' ' | sed 's/ *$//' || echo "N/A")"
    else
        WEB_SERVER_VERSION="N/A (Apache/Nginx not found)"
    fi

    if command_exists mysql; then
        DB_SERVER_VERSION="$(mysql --version 2>/dev/null | grep "Ver " | head -n 1 | awk '{print $5}' | tr '\n' ' ' | sed 's/ *$//' || echo "N/A")"
    elif command_exists psql; then
        DB_SERVER_VERSION="$(psql --version 2>/dev/null | grep "psql (PostgreSQL)" | awk '{print $3}' | tr '\n' ' ' | sed 's/ *$//' || echo "N/A")"
    else
        DB_SERVER_VERSION="N/A (MySQL/PostgreSQL not found)"
    fi
}

get_security_config_info() {
    if [ "$OS_TYPE" == "Darwin" ]; then
        if command_exists pfctl; then
            FIREWALL_STATUS="$(pfctl -s info 2>/dev/null | grep "Status" | awk '{print $2}' || echo "N/A (May require root)")"
        else
            FIREWALL_STATUS="N/A ('pfctl' not found)"
        fi
    else 
        if command_exists ufw; then
            FIREWALL_STATUS="$(ufw status 2>/dev/null | head -n 1 | awk '{print $2}' || echo "N/A (May require root)")"
        elif command_exists firewall-cmd; then
            FIREWALL_STATUS="$(firewall-cmd --state 2>/dev/null || echo "N/A (May require root)")"
        else
            FIREWALL_STATUS="N/A (Neither 'ufw' nor 'firewall-cmd' found)"
        fi
    fi

    if [ -f "/etc/ssh/sshd_config" ]; then
        SSH_ROOT_LOGIN="$(grep -E 'PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}' | head -n 1 || echo "N/A")"
        SSH_PASS_AUTH="$(grep -E 'PasswordAuthentication' /etc/ssh/sshd_config | awk '{print $2}' | head -n 1 || echo "N/A")"
    else
        SSH_ROOT_LOGIN="N/A ('sshd_config' not found)"
        SSH_PASS_AUTH="N/A ('sshd_config' not found)"
    fi

    if [ "$OS_TYPE" != "Darwin" ]; then
        if command_exists sestatus; then
            SELINUX_STATUS="$(sestatus 2>/dev/null | grep "SELinux status:" | awk '{print $3}' || echo "N/A")"
        else
            SELINUX_STATUS="N/A ('sestatus' not found)"
        fi

        if command_exists aa-status; then
            APPARMOR_STATUS="$(aa-status 2>/dev/null | grep "AppArmor status:" | awk '{print $3}' || echo "N/A")"
        else
            APPARMOR_STATUS="N/A ('aa-status' not found)"
        fi
    else
        SELINUX_STATUS="N/A (Linux specific)"
        APPARMOR_STATUS="N/A (Linux specific)"
    fi
}

get_log_history_info() {
    if [ -f "/var/log/auth.log" ]; then
        LAST_ACCEPTED_LOGIN="$(grep "Accepted password for" /var/log/auth.log 2>/dev/null | tail -n 1 | awk '{$1=$1;print}' | tr '\n' '; ' | sed 's/; *$//' || echo "N/A (Requires root)")"
    elif [ -f "/var/log/secure" ]; then 
        LAST_ACCEPTED_LOGIN="$(grep "Accepted password for" /var/log/secure 2>/dev/null | tail -n 1 | awk '{$1=$1;print}' | tr '\n' '; ' | sed 's/; *$//' || echo "N/A (Requires root)")"
    else
        LAST_ACCEPTED_LOGIN="N/A (Auth log not found or requires root)"
    fi

    if [ -f "$HOME/.bash_history" ]; then
        BASH_HISTORY_SIZE="$(ls -lh "$HOME/.bash_history" | awk '{print $5}' || echo "N/A")"
    else
        BASH_HISTORY_SIZE="N/A (Bash history not found)"
    fi

    if [ -f "$HOME/.zsh_history" ]; then
        ZSH_HISTORY_SIZE="$(ls -lh "$HOME/.zsh_history" | awk '{print $5}' || echo "N/A")"
    else
        ZSH_HISTORY_SIZE="N/A (Zsh history not found)"
    fi
}

print_report_table() {
    local max_key_len=25
    local max_val_len=60
    local total_width=$((max_key_len + max_val_len + 7))
    local separator_line=$(printf '%*s' "$total_width" '' | tr ' ' '-')

    local local_warning_bg_red='\033[41m'
    local local_warning_text_white='\033[1;37m'
    if [ "$COLOR_OUTPUT" = false ]; then
        local_warning_bg_red=''
        local_warning_text_white=''
    fi

    echo -e "${CYAN}"
    cat << "EOF"
                                   _                
     /\                           | |               
    /  \   ___ _ __ ___   ___   __| | ___ _   _ ___ 
   / /\ \ / __| '_ ` _ \ / _ \ / _` |/ _ \ | | / __|
  / ____ \\__ \ | | | | | (_) | (_| |  __/ |_| \__ \
 /_/    \_\___/_| |_| |_|\___/ \__,_|\___|\__,_|___/
                                                    
EOF
    echo -e "${NC}"
    echo ""

    echo -e "${BLUE}--- About Me / Author: Yash Raghuvanshi ---${NC}"
    echo "$separator_line"
    printf "${GREEN}%-${max_key_len}s ${NC}| %-${max_val_len}s\n" "Author" "Yash Raghuvanshi"
    echo "$separator_line"
    echo ""

    local warning_line1="WARNING: This tool gathers sensitive system information."
    local warning_line2="Use it responsibly and only on systems you are authorized to assess."
    
    local box_content_width=$((total_width - 4))
    local pad1_left=$(( (box_content_width - ${#warning_line1}) / 2 ))
    local pad1_right=$(( box_content_width - ${#warning_line1} - pad1_left ))
    local pad2_left=$(( (box_content_width - ${#warning_line2}) / 2 ))
    local pad2_right=$(( box_content_width - ${#warning_line2} - pad2_left ))

    printf "${local_warning_bg_red}${local_warning_text_white}%-${total_width}s${NC}\n" ""
    printf "${local_warning_bg_red}${local_warning_text_white}  %*s%s%*s  ${NC}\n" $pad1_left "" "$warning_line1" $pad1_right ""
    printf "${local_warning_bg_red}${local_warning_text_white}  %*s%s%*s  ${NC}\n" $pad2_left "" "$warning_line2" $pad2_right ""
    printf "${local_warning_bg_red}${local_warning_text_white}%-${total_width}s${NC}\n" ""
    echo ""

    echo -e "${BLUE}--- System Information Report ---${NC}"
    echo "$separator_line"
    printf "${GREEN}%-${max_key_len}s ${NC}| ${GREEN}%-${max_val_len}s${NC}\n" "Category" "Value"
    echo "$separator_line"

    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Operating System" "$OS_NAME"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Kernel Version" "$KERNEL_VERSION"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Architecture" "$ARCHITECTURE"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Hostname" "$HOSTNAME_VAL"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Uptime" "$UPTIME_VAL"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Current User" "$CURRENT_USER"
    echo "$separator_line"

    printf "${PURPLE}%-${max_key_len}s ${NC}| ${PURPLE}%-${max_val_len}s${NC}\n" "Network Information" ""
    echo "$separator_line"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Internal IP" "$INTERNAL_IP"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "External IP" "$EXTERNAL_IP"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Open Ports (LISTEN)" "$OPEN_PORTS"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Active Connections (ESTAB)" "$ACTIVE_CONNECTIONS"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Routing Table (first 3 lines)" "$ROUTING_TABLE"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "DNS Servers" "$DNS_SERVERS"
    echo "$separator_line"

    printf "${PURPLE}%-${max_key_len}s ${NC}| ${PURPLE}%-${max_val_len}s${NC}\n" "User & Privilege Information" ""
    echo "$separator_line"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Logged-in Users" "$LOGGED_IN_USERS"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Last 1 Login" "$LAST_LOGIN"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Users with SUDO Privileges" "$SUDO_USERS"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Password Max Days (Linux)" "$PASS_MAX_DAYS"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Password Min Length (Linux)" "$PASS_MIN_LEN"
    echo "$separator_line"

    printf "${PURPLE}%-${max_key_len}s ${NC}| ${PURPLE}%-${max_val_len}s${NC}\n" "Software & Services" ""
    echo "$separator_line"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Running Services (first 5)" "$RUNNING_SERVICES"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Installed Packages (first 5)" "$INSTALLED_PACKAGES"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Web Server Version" "$WEB_SERVER_VERSION"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Database Server Version" "$DB_SERVER_VERSION"
    echo "$separator_line"

    printf "${PURPLE}%-${max_key_len}s ${NC}| ${PURPLE}%-${max_val_len}s${NC}\n" "Security Configurations" ""
    echo "$separator_line"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Firewall Status" "$FIREWALL_STATUS"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "SSH Permit Root Login" "$SSH_ROOT_LOGIN"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "SSH Password Auth" "$SSH_PASS_AUTH"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "SELinux Status (Linux)" "$SELINUX_STATUS"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "AppArmor Status (Linux)" "$APPARMOR_STATUS"
    echo "$separator_line"

    printf "${PURPLE}%-${max_key_len}s ${NC}| ${PURPLE}%-${max_val_len}s${NC}\n" "Logs & History" ""
    echo "$separator_line"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Last 1 Accepted Login" "$LAST_ACCEPTED_LOGIN"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Bash History Size" "$BASH_HISTORY_SIZE"
    printf "%-${max_key_len}s | %-${max_val_len}s\n" "Zsh History Size" "$ZSH_HISTORY_SIZE"
    echo "$separator_line"

    REPORT_DATE=$(date)
    echo -e "${YELLOW}Report generated on ${REPORT_DATE}${NC}"
    echo ""
}

# Argument Parsing
HELP_REQUESTED=false

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -o|--output)
            if [ -n "$2" ] && [[ ! "$2" =~ ^- ]]; then
                OUTPUT_FILE="$2"
                shift
            else
                echo -e "${RED}Error: -o/--output requires a filename argument.${NC}" >&2
                show_help
            fi
            ;;
        -n|--no-color)
            COLOR_OUTPUT=false
            ;;
        -h|--help)
            HELP_REQUESTED=true
            ;;
        *)
            echo -e "${RED}Error: Unknown option '$1'.${NC}" >&2
            show_help
            ;;
    esac
    shift
done

# Ensure COLOR_OUTPUT is false if redirecting, regardless of -n flag
if [ -n "$OUTPUT_FILE" ]; then
    COLOR_OUTPUT=false
fi

# Re-evaluate color variables based on final COLOR_OUTPUT value
if [ -t 1 ] && [ "$COLOR_OUTPUT" = true ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    PURPLE=''
    CYAN=''
    NC=''
fi

# Pre-Report Effects (only if not asking for help and not redirecting)
if [ "$HELP_REQUESTED" = false ] && [ -z "$OUTPUT_FILE" ]; then
    display_intro
    loading_animation
elif [ "$HELP_REQUESTED" = true ]; then
    show_help
fi

# Data Collection - Only collect if not showing help
if [ "$HELP_REQUESTED" = false ]; then
    get_system_info
    get_network_details
    get_user_privilege_info
    get_software_services_info
    get_security_config_info
    get_log_history_info
    get_resource_info
fi

# Main Report Logic
if [ -n "$OUTPUT_FILE" ]; then
    exec > "$OUTPUT_FILE" 2>&1
fi

if [ "$HELP_REQUESTED" = false ]; then
    print_report_table
fi