#!/usr/bin/env bash

# VPS Security & Health Audit
# Improved fork-compatible edition based on nuver-labs/vps-audit.
# Read-only by design: it does not modify SSH, firewall, Fail2Ban, packages,
# systemd units, or application configuration. It only creates a local report.

VPS_AUDIT_VERSION="0.3.3"

# Force stable command output where possible. This avoids parsing failures on
# non-English systems.
export LC_ALL=C
export LANG=C

# Reports can contain IP addresses, ports, service names, and security state.
umask 077

# -----------------------------------------
# Colors
# -----------------------------------------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# -----------------------------------------
# Configuration
# -----------------------------------------
OS_RELEASE_FILE="/etc/os-release"
REBOOT_REQUIRED_FILE="/var/run/reboot-required"
SSH_CONFIG_FILE="/etc/ssh/sshd_config"
AUTH_LOG_FILE="/var/log/auth.log"
FAIL2BAN_CONFIG_DIR="/etc/fail2ban"

# Health thresholds. These are health indicators only, not security findings.
RESOURCE_WARN=70
RESOURCE_FAIL=90

# Failed authentication attempts. A large count alone is not considered a
# compromise; severity is correlated with SSH password auth and IPS state.
LOGINS_WARN=50
LOGINS_HIGH=500
FAILED_LOGIN_WINDOW="24 hours ago"

# Password policy guidance.
PASSWORD_MINLEN=12

# APT list freshness. No `apt update` is run because the audit is read-only.
APT_CACHE_WARN_HOURS=48

# Optional external lookup. This contacts api.ipify.org and sends only the
# normal network metadata inherent to an HTTPS request.
ENABLE_PUBLIC_IP_LOOKUP=true
PUBLIC_IP_URL="https://api.ipify.org"

# Report output.
DEFAULT_REPORT_DIR="."
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILENAME="vps-audit-report-${TIMESTAMP}.txt"
REPORT_FILE="${DEFAULT_REPORT_DIR}/${REPORT_FILENAME}"

# Optional ownership adjustment. Disabled by default.
ENABLE_CHOWN=false
CHOWN_USER="${SUDO_USER:-$(id -un 2>/dev/null || printf 'root')}"
REPORT_CHOWN_OWNER="${CHOWN_USER}:$(id -gn "$CHOWN_USER" 2>/dev/null || id -gn 2>/dev/null || printf 'root')"

# -----------------------------------------
# Helpers
# -----------------------------------------
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

safe_count() {
    local value="${1:-0}"
    value=$(printf '%s' "$value" | tr -cd '0-9')
    printf '%s' "${value:-0}"
}

# Check whether dpkg owns a path, including the historical aliases retained on
# merged-/usr Debian/Ubuntu systems. For example, dpkg may record
# /bin/fusermount3 while the filesystem scan returns /usr/bin/fusermount3.
dpkg_path_is_owned() {
    local path="$1" real_path="" alias_path="" merged_target=""

    command_exists dpkg-query || return 1

    if dpkg-query -S "$path" >/dev/null 2>&1; then
        return 0
    fi

    real_path=$(readlink -f -- "$path" 2>/dev/null || true)
    if [ -n "$real_path" ] && [ "$real_path" != "$path" ] && \
       dpkg-query -S "$real_path" >/dev/null 2>&1; then
        return 0
    fi

    case "$path" in
        /usr/bin/*)
            merged_target=$(readlink -f /bin 2>/dev/null || true)
            [ "$merged_target" = "/usr/bin" ] && alias_path="/bin/${path#/usr/bin/}"
            ;;
        /usr/sbin/*)
            merged_target=$(readlink -f /sbin 2>/dev/null || true)
            [ "$merged_target" = "/usr/sbin" ] && alias_path="/sbin/${path#/usr/sbin/}"
            ;;
        /usr/lib64/*)
            merged_target=$(readlink -f /lib64 2>/dev/null || true)
            [ "$merged_target" = "/usr/lib64" ] && alias_path="/lib64/${path#/usr/lib64/}"
            ;;
        /usr/lib/*)
            merged_target=$(readlink -f /lib 2>/dev/null || true)
            [ "$merged_target" = "/usr/lib" ] && alias_path="/lib/${path#/usr/lib/}"
            ;;
        /bin/*)
            merged_target=$(readlink -f /bin 2>/dev/null || true)
            [ "$merged_target" = "/usr/bin" ] && alias_path="/usr/bin/${path#/bin/}"
            ;;
        /sbin/*)
            merged_target=$(readlink -f /sbin 2>/dev/null || true)
            [ "$merged_target" = "/usr/sbin" ] && alias_path="/usr/sbin/${path#/sbin/}"
            ;;
        /lib64/*)
            merged_target=$(readlink -f /lib64 2>/dev/null || true)
            [ "$merged_target" = "/usr/lib64" ] && alias_path="/usr/lib64/${path#/lib64/}"
            ;;
        /lib/*)
            merged_target=$(readlink -f /lib 2>/dev/null || true)
            [ "$merged_target" = "/usr/lib" ] && alias_path="/usr/lib/${path#/lib/}"
            ;;
    esac

    [ -n "$alias_path" ] && dpkg-query -S "$alias_path" >/dev/null 2>&1
}

translate_header() {
    case "$1" in
        "System Information") printf '%s' "Информация о системе" ;;
        "Security Audit Results") printf '%s' "Результаты аудита безопасности" ;;
        "System Health") printf '%s' "Состояние системы" ;;
        *) printf '%s' "" ;;
    esac
}

translate_label() {
    case "$1" in
        "Hostname") printf '%s' "Имя хоста" ;;
        "Operating System") printf '%s' "Операционная система" ;;
        "Kernel Version") printf '%s' "Версия ядра" ;;
        "Uptime") printf '%s' "Время работы" ;;
        "CPU Model") printf '%s' "Модель процессора" ;;
        "CPU Cores") printf '%s' "Ядра процессора" ;;
        "Total Memory") printf '%s' "Общий объём памяти" ;;
        "Root Filesystem Size") printf '%s' "Размер корневой файловой системы" ;;
        "Public IPv4") printf '%s' "Публичный IPv4" ;;
        "Load Average (1/5/15m)") printf '%s' "Средняя нагрузка (1/5/15 мин)" ;;
        *) printf '%s' "" ;;
    esac
}

translate_test() {
    case "$1" in
        "Privileges") printf '%s' "Права доступа" ;;
        "System Restart") printf '%s' "Перезагрузка системы" ;;
        "SSH Root Login") printf '%s' "Вход root по SSH" ;;
        "SSH Password Authentication") printf '%s' "Парольная аутентификация SSH" ;;
        "SSH Public Key Authentication") printf '%s' "Аутентификация SSH по ключу" ;;
        "SSH Port") printf '%s' "Порт SSH" ;;
        "SSH Effective Configuration") printf '%s' "Эффективная конфигурация SSH" ;;
        "Firewall") printf '%s' "Межсетевой экран" ;;
        "Automatic Security Updates") printf '%s' "Автоматические обновления безопасности" ;;
        "APT Metadata Freshness") printf '%s' "Актуальность метаданных APT" ;;
        "Pending Package Updates") printf '%s' "Ожидающие обновления пакетов" ;;
        "Intrusion Prevention") printf '%s' "Защита от вторжений" ;;
        "Fail2Ban SSH Jail") printf '%s' "SSH jail Fail2Ban" ;;
        "Fail2Ban SSH Port Alignment") printf '%s' "Соответствие SSH-порта в Fail2Ban" ;;
        "Failed SSH Logins") printf '%s' "Неудачные входы по SSH" ;;
        "Listening Sockets") printf '%s' "Прослушиваемые сокеты" ;;
        "TCP Listening Sockets") printf '%s' "Прослушиваемые TCP-сокеты" ;;
        "TCP Wildcard Listeners") printf '%s' "TCP-сокеты на всех адресах" ;;
        "UDP Bound Sockets") printf '%s' "Привязанные UDP-сокеты" ;;
        "UDP Wildcard Sockets") printf '%s' "UDP-сокеты на всех адресах" ;;
        "Wildcard Listeners") printf '%s' "Сокеты на всех адресах" ;;
        "Docker Port Publishing") printf '%s' "Публикация портов Docker" ;;
        "Docker Firewall Integration") printf '%s' "Интеграция Docker с firewall" ;;
        "Sudo Logging") printf '%s' "Журналирование sudo" ;;
        "Password Policy") printf '%s' "Политика паролей" ;;
        "SUID Files") printf '%s' "SUID-файлы" ;;
        "Root Filesystem Usage") printf '%s' "Использование корневой файловой системы" ;;
        "Memory Pressure") printf '%s' "Использование памяти" ;;
        "CPU Usage") printf '%s' "Использование процессора" ;;
        "Running Services") printf '%s' "Запущенные службы" ;;
        "Failed Services") printf '%s' "Службы с ошибками" ;;
        "Established TCP Connections") printf '%s' "Установленные TCP-соединения" ;;
        *) printf '%s' "" ;;
    esac
}

translate_status() {
    case "$1" in
        PASS) printf '%s' "НОРМА" ;;
        INFO) printf '%s' "ИНФО" ;;
        WARN) printf '%s' "ВНИМАНИЕ" ;;
        FAIL) printf '%s' "ОШИБКА" ;;
        *) printf '%s' "ИНФО" ;;
    esac
}

translate_block_title() {
    case "$1" in
        "Containerized intrusion-prevention services") printf '%s' "Контейнерные службы защиты от вторжений" ;;
        "Fail2Ban active jail list") printf '%s' "Список активных jail Fail2Ban" ;;
        "Network-bound listeners") printf '%s' "Сокеты, доступные через сетевые интерфейсы" ;;
        "Loopback-only listeners") printf '%s' "Сокеты только на loopback" ;;
        "Network-bound TCP listeners") printf '%s' "TCP-сокеты, привязанные к сетевым интерфейсам" ;;
        "Loopback-only TCP listeners") printf '%s' "TCP-сокеты только на loopback" ;;
        "Network-bound UDP sockets") printf '%s' "UDP-сокеты, привязанные к сетевым интерфейсам" ;;
        "Loopback-only UDP sockets") printf '%s' "UDP-сокеты только на loopback" ;;
        "Docker published ports") printf '%s' "Опубликованные порты Docker" ;;
        "Docker host-published ports") printf '%s' "Порты Docker, опубликованные на хосте" ;;
        "SUID files on root filesystem") printf '%s' "SUID-файлы в корневой файловой системе" ;;
        "SUID files not owned by a Debian package") printf '%s' "SUID-файлы, не принадлежащие пакетам Debian" ;;
        "Failed systemd services") printf '%s' "Службы systemd с ошибками" ;;
        *) printf '%s' "" ;;
    esac
}

ensure_report_dir() {
    if [ ! -d "$DEFAULT_REPORT_DIR" ]; then
        if ! mkdir -p "$DEFAULT_REPORT_DIR"; then
            printf '%b\n' "${RED}[ERROR]${NC} Cannot create ${DEFAULT_REPORT_DIR}; using current directory." >&2
            DEFAULT_REPORT_DIR="."
            REPORT_FILE="./${REPORT_FILENAME}"
            ENABLE_CHOWN=false
            return
        fi
        if [ "$ENABLE_CHOWN" = true ]; then
            chown "$REPORT_CHOWN_OWNER" "$DEFAULT_REPORT_DIR" 2>/dev/null || true
        fi
    fi
}

print_header() {
    local header="$1" ru_header
    ru_header=$(translate_header "$header")
    if [ -n "$ru_header" ]; then
        printf '\n%b%s (%s)%b\n' "${BLUE}${BOLD}" "$header" "$ru_header" "$NC"
        printf '\n%s (%s)\n================================\n' "$header" "$ru_header" >> "$REPORT_FILE"
    else
        printf '\n%b%s%b\n' "${BLUE}${BOLD}" "$header" "$NC"
        printf '\n%s\n================================\n' "$header" >> "$REPORT_FILE"
    fi
}

print_info() {
    local label="$1" value="$2" ru_label
    ru_label=$(translate_label "$label")
    if [ -n "$ru_label" ]; then
        printf '%b%s (%s):%b %s\n' "$BOLD" "$label" "$ru_label" "$NC" "$value"
        printf '%s (%s): %s\n' "$label" "$ru_label" "$value" >> "$REPORT_FILE"
    else
        printf '%b%s:%b %s\n' "$BOLD" "$label" "$NC" "$value"
        printf '%s: %s\n' "$label" "$value" >> "$REPORT_FILE"
    fi
}

report_result() {
    local test_name="$1" status="$2" message="$3" ru_message="${4:-}"
    local color="$GRAY" ru_test ru_status

    case "$status" in
        PASS) color="$GREEN" ;;
        INFO) color="$CYAN" ;;
        WARN) color="$YELLOW" ;;
        FAIL) color="$RED" ;;
        *) status="INFO"; color="$CYAN" ;;
    esac

    ru_test=$(translate_test "$test_name")
    ru_status=$(translate_status "$status")

    if [ -n "$ru_test" ] && [ -n "$ru_message" ]; then
        printf '%b[%s]%b (%s) %s (%s) %b- %s (%s)%b\n' "$color" "$status" "$NC" "$ru_status" "$test_name" "$ru_test" "$GRAY" "$message" "$ru_message" "$NC"
        printf '[%s] (%s) %s (%s) - %s (%s)\n\n' "$status" "$ru_status" "$test_name" "$ru_test" "$message" "$ru_message" >> "$REPORT_FILE"
    elif [ -n "$ru_test" ]; then
        printf '%b[%s]%b (%s) %s (%s) %b- %s%b\n' "$color" "$status" "$NC" "$ru_status" "$test_name" "$ru_test" "$GRAY" "$message" "$NC"
        printf '[%s] (%s) %s (%s) - %s\n\n' "$status" "$ru_status" "$test_name" "$ru_test" "$message" >> "$REPORT_FILE"
    else
        printf '%b[%s]%b (%s) %s %b- %s%b\n' "$color" "$status" "$NC" "$ru_status" "$test_name" "$GRAY" "$message" "$NC"
        printf '[%s] (%s) %s - %s\n\n' "$status" "$ru_status" "$test_name" "$message" >> "$REPORT_FILE"
    fi
}

append_report_block() {
    local title="$1" ru_title
    shift
    ru_title=$(translate_block_title "$title")
    {
        if [ -n "$ru_title" ]; then
            printf '\n%s (%s)\n' "$title" "$ru_title"
        else
            printf '\n%s\n' "$title"
        fi
        printf '%s\n' "--------------------------------"
        printf '%s\n' "$@"
    } >> "$REPORT_FILE"
}

# Parse the local endpoint printed by `ss` into address + port.
endpoint_address() {
    local endpoint="$1"
    if [[ "$endpoint" =~ ^\[(.*)\]:([^:]*)$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    else
        printf '%s' "${endpoint%:*}"
    fi
}

endpoint_port() {
    local endpoint="$1"
    if [[ "$endpoint" =~ ^\[(.*)\]:([^:]*)$ ]]; then
        printf '%s' "${BASH_REMATCH[2]}"
    else
        printf '%s' "${endpoint##*:}"
    fi
}

is_loopback_address() {
    local addr="${1%%%*}" # strip IPv6 zone suffix if present
    case "$addr" in
        127.*|::1) return 0 ;;
        *) return 1 ;;
    esac
}

is_wildcard_address() {
    local addr="${1%%%*}"
    case "$addr" in
        0.0.0.0|::|\*) return 0 ;;
        *) return 1 ;;
    esac
}

# Summarize numeric endpoint lists by address and collapse consecutive ports.
# Example: udp/50000..udp/50100 @ 0.0.0.0 becomes udp/50000-50100 @ 0.0.0.0.
summarize_endpoint_ranges() {
    local proto="$1"
    shift
    [ "$#" -gt 0 ] || return 0

    printf '%s\n' "$@" \
        | awk -v wanted="$proto" '
            {
                split($1, pp, "/")
                if (pp[1] == wanted && pp[2] ~ /^[0-9]+$/ && $2 == "@") {
                    print $3 "\t" pp[2]
                }
            }
        ' \
        | sort -t $'\t' -k1,1 -k2,2n -u \
        | awk -F '\t' -v proto="$proto" '
            function emit(addr, start, last,    range) {
                if (addr == "") return
                range = (start == last ? start : start "-" last)
                if (out[addr] == "") out[addr] = range
                else out[addr] = out[addr] "," range
            }
            {
                addr=$1
                port=$2+0
                if (addr != current_addr) {
                    if (current_addr != "") emit(current_addr, start, last)
                    current_addr=addr
                    start=port
                    last=port
                    next
                }
                if (port == last + 1) {
                    last=port
                } else if (port != last) {
                    emit(current_addr, start, last)
                    start=port
                    last=port
                }
            }
            END {
                if (current_addr != "") emit(current_addr, start, last)
                for (addr in out) print proto "/" out[addr] " @ " addr
            }
        ' \
        | sort
}

read_sshd_value() {
    local key="$1"
    [ -n "${SSHD_EFFECTIVE:-}" ] || return 1
    printf '%s\n' "$SSHD_EFFECTIVE" | awk -v k="$key" '$1 == k {print $2; exit}'
}

# Resolve service names (ssh, http, etc.) to a numeric TCP port when possible.
resolve_port_token() {
    local token="$1"
    if [[ "$token" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$token"
    else
        getent services "$token" 2>/dev/null | head -1 | awk '{print $2}' | cut -d/ -f1
    fi
}

port_list_contains() {
    local list="$1" target="$2" token start end resolved
    local IFS=','
    for token in $list; do
        token="${token//[[:space:]]/}"
        [ -z "$token" ] && continue
        if [[ "$token" == *:* ]]; then
            start=$(resolve_port_token "${token%%:*}")
            end=$(resolve_port_token "${token##*:}")
            if [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]]; then
                [ "$target" -ge "$start" ] && [ "$target" -le "$end" ] && return 0
            fi
        else
            resolved=$(resolve_port_token "$token")
            [ "$resolved" = "$target" ] && return 0
        fi
    done
    return 1
}

# Read a Fail2Ban option while respecting the common config precedence.
get_jail_option() {
    local section="$1" option="$2" file value result=""
    local files=(
        "$FAIL2BAN_CONFIG_DIR/jail.conf"
        "$FAIL2BAN_CONFIG_DIR"/jail.d/*.conf
        "$FAIL2BAN_CONFIG_DIR/jail.local"
        "$FAIL2BAN_CONFIG_DIR"/jail.d/*.local
    )

    for file in "${files[@]}"; do
        [ -f "$file" ] || continue
        value=$(awk -v sect="$section" -v opt="$option" '
            /^[[:space:]]*\[/ {
                line=$0
                gsub(/^[[:space:]]*\[/, "", line)
                gsub(/\][[:space:]]*$/, "", line)
                in_sect=(line == sect)
                next
            }
            in_sect && $0 ~ "^[[:space:]]*" opt "[[:space:]]*=" {
                sub(/^[^=]*=[[:space:]]*/, "")
                sub(/[[:space:]]+$/, "")
                val=$0
            }
            END { if (val != "") print val }
        ' "$file" 2>/dev/null)
        [ -n "$value" ] && result="$value"
    done
    printf '%s\n' "$result"
}

get_cpu_usage_percent() {
    local cpu user nice system idle iowait irq softirq steal guest guest_nice
    local total1 idle1 total2 idle2 diff_total diff_idle

    read -r cpu user nice system idle iowait irq softirq steal guest guest_nice < /proc/stat || return 1
    total1=$((user + nice + system + idle + iowait + irq + softirq + steal))
    idle1=$((idle + iowait))
    sleep 1
    read -r cpu user nice system idle iowait irq softirq steal guest guest_nice < /proc/stat || return 1
    total2=$((user + nice + system + idle + iowait + irq + softirq + steal))
    idle2=$((idle + iowait))

    diff_total=$((total2 - total1))
    diff_idle=$((idle2 - idle1))
    [ "$diff_total" -gt 0 ] || return 1
    printf '%s\n' $(( (100 * (diff_total - diff_idle) + diff_total / 2) / diff_total ))
}

ensure_report_dir

# -----------------------------------------
# Start audit
# -----------------------------------------
printf '%bVPS Security & Health Audit (Аудит безопасности и состояния VPS) v%s%b\n' "${BLUE}${BOLD}" "$VPS_AUDIT_VERSION" "$NC"
printf '%bRead-only audit; report permissions default to 0600. (Аудит только для чтения; права отчёта по умолчанию 0600.)%b\n' "$GRAY" "$NC"
printf '%bStarting audit at %s (Начало аудита)%b\n\n' "$GRAY" "$(date)" "$NC"

{
    printf 'VPS Security & Health Audit (Аудит безопасности и состояния VPS) v%s\n' "$VPS_AUDIT_VERSION"
    printf 'Starting audit at %s (Начало аудита)\n' "$(date)"
    printf 'Report permissions: private (umask 077) (Права отчёта: приватные)\n'
    printf '================================\n'
} > "$REPORT_FILE"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    report_result "Privileges" "WARN" "Not running as root. The audit will continue, but firewall, Fail2Ban, process, and log checks may be incomplete." "Скрипт запущен не от root. Аудит продолжится, но проверки firewall, Fail2Ban, процессов и журналов могут быть неполными."
else
    report_result "Privileges" "PASS" "Running as root; all read-only checks should have sufficient access." "Скрипт запущен от root; для всех проверок только на чтение должно быть достаточно прав."
fi

# -----------------------------------------
# System information
# -----------------------------------------
print_header "System Information"

OS_INFO="Unknown"
if [ -r "$OS_RELEASE_FILE" ]; then
    OS_INFO=$(awk -F= '$1=="PRETTY_NAME" {gsub(/^"|"$/, "", $2); print $2; exit}' "$OS_RELEASE_FILE")
fi
KERNEL_VERSION=$(uname -r 2>/dev/null || printf 'Unknown')
HOST_NAME=$(hostname 2>/dev/null || printf 'Unknown')
UPTIME=$(uptime -p 2>/dev/null || printf 'Unknown')
UPTIME_SINCE=$(uptime -s 2>/dev/null || printf 'Unknown')
CPU_INFO=$(lscpu 2>/dev/null | awk -F: '/Model name/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}')
CPU_CORES=$(nproc 2>/dev/null || printf 'Unknown')
TOTAL_MEM=$(free -h 2>/dev/null | awk '/^Mem:/ {print $2}')
TOTAL_DISK=$(df -hP / 2>/dev/null | awk 'NR==2 {print $2}')
LOAD_AVERAGE=$(awk '{print $1", "$2", "$3}' /proc/loadavg 2>/dev/null || printf 'Unknown')

PUBLIC_IP="Disabled"
if [ "$ENABLE_PUBLIC_IP_LOOKUP" = true ]; then
    if command_exists curl; then
        PUBLIC_IP=$(curl -4 -fsS --max-time 5 "$PUBLIC_IP_URL" 2>/dev/null || printf 'Unavailable')
    else
        PUBLIC_IP="Unavailable (curl not installed)"
    fi
fi

print_info "Hostname" "$HOST_NAME"
print_info "Operating System" "${OS_INFO:-Unknown}"
print_info "Kernel Version" "$KERNEL_VERSION"
print_info "Uptime" "$UPTIME (since $UPTIME_SINCE)"
print_info "CPU Model" "${CPU_INFO:-Unknown}"
print_info "CPU Cores" "$CPU_CORES"
print_info "Total Memory" "${TOTAL_MEM:-Unknown}"
print_info "Root Filesystem Size" "${TOTAL_DISK:-Unknown}"
print_info "Public IPv4" "$PUBLIC_IP"
print_info "Load Average (1/5/15m)" "$LOAD_AVERAGE"

# -----------------------------------------
# Security checks
# -----------------------------------------
print_header "Security Audit Results"

# Reboot required
if [ -f "$REBOOT_REQUIRED_FILE" ]; then
    report_result "System Restart" "WARN" "A reboot is required to finish applying installed updates." "Для завершения установки обновлений требуется перезагрузка."
else
    report_result "System Restart" "PASS" "No reboot-required marker is present." "Признак необходимости перезагрузки не обнаружен."
fi

# SSH effective configuration
SSHD_EFFECTIVE=""
SSH_PORT="22"
SSH_PASSWORD="unknown"
SSH_ROOT="unknown"
SSH_PUBKEY="unknown"

if command_exists sshd; then
    SSHD_EFFECTIVE=$(sshd -T 2>/dev/null || true)
fi

if [ -n "$SSHD_EFFECTIVE" ]; then
    SSH_PORT=$(read_sshd_value port)
    SSH_PASSWORD=$(read_sshd_value passwordauthentication)
    SSH_ROOT=$(read_sshd_value permitrootlogin)
    SSH_PUBKEY=$(read_sshd_value pubkeyauthentication)

    [ -n "$SSH_PORT" ] || SSH_PORT="22"
    [ -n "$SSH_PASSWORD" ] || SSH_PASSWORD="unknown"
    [ -n "$SSH_ROOT" ] || SSH_ROOT="unknown"
    [ -n "$SSH_PUBKEY" ] || SSH_PUBKEY="unknown"

    case "$SSH_ROOT" in
        no) report_result "SSH Root Login" "PASS" "Effective sshd configuration has PermitRootLogin=no." "В эффективной конфигурации sshd установлено PermitRootLogin=no." ;;
        prohibit-password|without-password|forced-commands-only)
            report_result "SSH Root Login" "WARN" "Root SSH login is restricted but still possible with non-password authentication (PermitRootLogin=$SSH_ROOT)." "Вход root по SSH ограничен, но всё ещё возможен без пароля (PermitRootLogin=$SSH_ROOT)."
            ;;
        yes) report_result "SSH Root Login" "FAIL" "Effective sshd configuration permits unrestricted root login." "Эффективная конфигурация sshd разрешает неограниченный вход root." ;;
        *) report_result "SSH Root Login" "WARN" "Could not classify effective PermitRootLogin value: $SSH_ROOT." "Не удалось классифицировать эффективное значение PermitRootLogin: $SSH_ROOT." ;;
    esac

    case "$SSH_PASSWORD" in
        no) report_result "SSH Password Authentication" "PASS" "PasswordAuthentication=no; SSH is not accepting normal password authentication." "PasswordAuthentication=no; SSH не принимает обычную парольную аутентификацию." ;;
        yes) report_result "SSH Password Authentication" "WARN" "PasswordAuthentication=yes. Prefer key-based authentication for Internet-facing servers." "PasswordAuthentication=yes. Для серверов, доступных из Интернета, предпочтительна аутентификация по ключам." ;;
        *) report_result "SSH Password Authentication" "WARN" "Could not determine effective PasswordAuthentication state." "Не удалось определить эффективное состояние PasswordAuthentication." ;;
    esac

    if [ "$SSH_PUBKEY" = "yes" ]; then
        report_result "SSH Public Key Authentication" "PASS" "PubkeyAuthentication=yes." "PubkeyAuthentication=yes; аутентификация по SSH-ключам включена."
    else
        report_result "SSH Public Key Authentication" "WARN" "Public-key authentication is not confirmed (value: $SSH_PUBKEY)." "Аутентификация по открытому ключу не подтверждена (значение: $SSH_PUBKEY)."
    fi

    if [ "$SSH_PORT" = "22" ]; then
        report_result "SSH Port" "INFO" "SSH uses the standard TCP port 22. Changing the port can reduce scanner noise but is not a primary security control." "SSH использует стандартный TCP-порт 22. Смена порта может уменьшить шум от сканеров, но не является основной мерой защиты."
    else
        report_result "SSH Port" "INFO" "SSH listens on TCP port $SSH_PORT. Non-standard ports reduce scanner noise but do not replace authentication or firewall controls." "SSH слушает TCP-порт $SSH_PORT. Нестандартный порт уменьшает шум от сканеров, но не заменяет надёжную аутентификацию и firewall."
    fi
else
    report_result "SSH Effective Configuration" "WARN" "Could not obtain effective sshd configuration via sshd -T. SSH findings may be incomplete." "Не удалось получить эффективную конфигурацию sshd через sshd -T. Результаты проверки SSH могут быть неполными."
    if [ -r "$SSH_CONFIG_FILE" ]; then
        SSH_PORT=$(awk 'tolower($1)=="port" {print $2; exit}' "$SSH_CONFIG_FILE")
        [ -n "$SSH_PORT" ] || SSH_PORT="22"
    fi
fi

# Firewall detection. Do not equate an installed binary with protection.
FIREWALL_ACTIVE=0
UFW_ACTIVE=0
FIREWALL_DETAILS=()

if command_exists ufw; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1 || true)
    if printf '%s' "$UFW_STATUS" | grep -q 'Status: active'; then
        UFW_ACTIVE=1
        FIREWALL_ACTIVE=1
        FIREWALL_DETAILS+=("UFW active")
    else
        FIREWALL_DETAILS+=("UFW installed but inactive")
    fi
fi

if command_exists firewall-cmd; then
    if firewall-cmd --state 2>/dev/null | grep -qx 'running'; then
        FIREWALL_ACTIVE=1
        FIREWALL_DETAILS+=("firewalld running")
    else
        FIREWALL_DETAILS+=("firewalld installed but not running")
    fi
fi

NFT_HAS_INPUT=0
NFT_RESTRICTIVE=0
if command_exists nft; then
    NFT_RULESET=$(nft list ruleset 2>/dev/null || true)
    if [ -n "$NFT_RULESET" ]; then
        # Inspect only base chains that actually hook into INPUT. Do not accept a
        # DROP policy from an unrelated forward/output chain as proof of inbound
        # filtering.
        NFT_INPUT_SUMMARY=$(printf '%s\n' "$NFT_RULESET" | awk '
            /^[[:space:]]*chain[[:space:]]+/ {
                in_chain=1
                block=$0 "\n"
                next
            }
            in_chain {
                block=block $0 "\n"
                if ($0 ~ /^[[:space:]]*}/) {
                    if (block ~ /hook[[:space:]]+input/) {
                        printf "%s", block
                        print "---CHAIN-END---"
                    }
                    in_chain=0
                    block=""
                }
            }
        ')
        if [ -n "$NFT_INPUT_SUMMARY" ]; then
            NFT_HAS_INPUT=1
            if printf '%s\n' "$NFT_INPUT_SUMMARY" | grep -Eq 'policy[[:space:]]+(drop|reject)'; then
                NFT_RESTRICTIVE=1
                FIREWALL_ACTIVE=1
                FIREWALL_DETAILS+=("nftables INPUT base chain has restrictive default policy")
            elif printf '%s\n' "$NFT_INPUT_SUMMARY" | grep -Eq '(^|[[:space:]])(drop|reject)([[:space:]]|$|;)'; then
                FIREWALL_DETAILS+=("nftables INPUT chain contains drop/reject rules but default policy is not confirmed restrictive")
            else
                FIREWALL_DETAILS+=("nftables INPUT hook present without a confirmed restrictive policy")
            fi
        fi
    fi
fi

IPT_RESTRICTIVE=0
if command_exists iptables; then
    IPT_INPUT=$(iptables -S INPUT 2>/dev/null || true)
    if printf '%s\n' "$IPT_INPUT" | grep -Eq '^-P INPUT (DROP|REJECT)$'; then
        IPT_RESTRICTIVE=1
        FIREWALL_ACTIVE=1
        FIREWALL_DETAILS+=("iptables INPUT default policy is restrictive")
    elif printf '%s\n' "$IPT_INPUT" | grep -Eq '^-A INPUT .* -j (DROP|REJECT)( |$)'; then
        FIREWALL_DETAILS+=("iptables has INPUT drop/reject rules but default policy is not restrictive")
    fi
fi

if [ "$FIREWALL_ACTIVE" -eq 1 ]; then
    report_result "Firewall" "PASS" "At least one active/restrictive firewall control was detected: ${FIREWALL_DETAILS[*]}." "Обнаружен как минимум один активный или ограничивающий механизм firewall: ${FIREWALL_DETAILS[*]}."
elif [ "$NFT_HAS_INPUT" -eq 1 ] || [ -n "${IPT_INPUT:-}" ]; then
    report_result "Firewall" "WARN" "Firewall rules exist, but this audit could not confirm a restrictive inbound policy: ${FIREWALL_DETAILS[*]:-manual review required}." "Правила firewall существуют, но аудит не смог подтвердить ограничивающую политику входящего трафика: ${FIREWALL_DETAILS[*]:-требуется ручная проверка}."
else
    report_result "Firewall" "FAIL" "No active inbound firewall control was confirmed. Verify provider firewall/security groups as well as the host firewall." "Активная фильтрация входящего трафика не подтверждена. Проверьте firewall/security groups провайдера и firewall на самом сервере."
fi

# Automatic security updates
if command_exists dpkg-query && dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q '^install ok installed$'; then
    UAU_CONFIG=0
    if command_exists apt-config; then
        APT_DUMP=$(apt-config dump 2>/dev/null || true)
        if printf '%s\n' "$APT_DUMP" | grep -Eq 'APT::Periodic::Unattended-Upgrade[[:space:]]+"?1"?;'; then
            UAU_CONFIG=1
        fi
    fi

    APT_TIMER=0
    if command_exists systemctl; then
        if systemctl is-enabled --quiet apt-daily-upgrade.timer 2>/dev/null || systemctl is-active --quiet apt-daily-upgrade.timer 2>/dev/null; then
            APT_TIMER=1
        fi
    fi

    if [ "$UAU_CONFIG" -eq 1 ] && [ "$APT_TIMER" -eq 1 ]; then
        report_result "Automatic Security Updates" "PASS" "unattended-upgrades is installed, periodic unattended upgrades are enabled, and apt-daily-upgrade.timer is enabled/active." "unattended-upgrades установлен, периодические автоматические обновления включены, apt-daily-upgrade.timer включён/активен."
    elif [ "$UAU_CONFIG" -eq 1 ] || [ "$APT_TIMER" -eq 1 ]; then
        report_result "Automatic Security Updates" "WARN" "unattended-upgrades is installed but only part of the expected automatic-update configuration was confirmed (periodic=$UAU_CONFIG, timer=$APT_TIMER)." "unattended-upgrades установлен, но подтверждена только часть ожидаемой конфигурации автообновлений (periodic=$UAU_CONFIG, timer=$APT_TIMER)."
    else
        report_result "Automatic Security Updates" "FAIL" "unattended-upgrades is installed, but automatic execution was not confirmed." "unattended-upgrades установлен, но автоматический запуск не подтверждён."
    fi
else
    report_result "Automatic Security Updates" "FAIL" "unattended-upgrades is not installed." "unattended-upgrades не установлен."
fi

# APT cache freshness and pending updates. We deliberately do not run apt update.
if command_exists apt-get; then
    APT_LIST_TS=$(find /var/lib/apt/lists -maxdepth 1 -type f -printf '%T@\n' 2>/dev/null | sort -nr | head -1 | cut -d. -f1)
    NOW_TS=$(date +%s)
    if [[ "$APT_LIST_TS" =~ ^[0-9]+$ ]] && [ "$APT_LIST_TS" -gt 0 ]; then
        APT_AGE_HOURS=$(( (NOW_TS - APT_LIST_TS) / 3600 ))
        if [ "$APT_AGE_HOURS" -gt "$APT_CACHE_WARN_HOURS" ]; then
            report_result "APT Metadata Freshness" "WARN" "Package metadata is approximately ${APT_AGE_HOURS}h old. Pending-update results may be stale; run apt update during maintenance." "Метаданным пакетов примерно ${APT_AGE_HOURS} ч. Результаты проверки обновлений могут быть устаревшими; выполните apt update во время обслуживания."
        else
            report_result "APT Metadata Freshness" "PASS" "Package metadata is approximately ${APT_AGE_HOURS}h old." "Метаданным пакетов примерно ${APT_AGE_HOURS} ч."
        fi
    else
        report_result "APT Metadata Freshness" "WARN" "Could not determine the age of APT package metadata." "Не удалось определить возраст метаданных пакетов APT."
    fi

    APT_SIM=$(apt-get -s upgrade 2>/dev/null || true)
    PENDING_TOTAL=$(printf '%s\n' "$APT_SIM" | grep -c '^Inst ' || true)
    PENDING_SECURITY=$(printf '%s\n' "$APT_SIM" | grep '^Inst ' | grep -Eic 'security|Debian-Security' || true)
    PENDING_TOTAL=$(safe_count "$PENDING_TOTAL")
    PENDING_SECURITY=$(safe_count "$PENDING_SECURITY")

    if [ "$PENDING_TOTAL" -eq 0 ]; then
        report_result "Pending Package Updates" "PASS" "No upgrades are visible in the current local APT metadata." "В текущих локальных метаданных APT доступных обновлений не обнаружено."
    elif [ "$PENDING_SECURITY" -gt 0 ]; then
        report_result "Pending Package Updates" "WARN" "$PENDING_TOTAL package upgrade(s) are visible, including approximately $PENDING_SECURITY security-origin upgrade(s)." "Доступно обновлений пакетов: $PENDING_TOTAL, из них примерно $PENDING_SECURITY относятся к источникам security."
    else
        report_result "Pending Package Updates" "INFO" "$PENDING_TOTAL package upgrade(s) are visible; none were identified as security-origin updates from the simulation output." "Доступно обновлений пакетов: $PENDING_TOTAL; по выводу симуляции ни одно не было определено как обновление из security-репозитория."
    fi
else
    report_result "Pending Package Updates" "INFO" "apt-get is unavailable; Debian/Ubuntu package-update check skipped." "apt-get недоступен; проверка обновлений пакетов Debian/Ubuntu пропущена."
fi

# Intrusion prevention: Fail2Ban, CrowdSec, SSHGuard (host services plus common Docker names).
IPS_INSTALLED=0
IPS_ACTIVE=0
IPS_NAMES=()

if command_exists fail2ban-client || (command_exists dpkg-query && dpkg-query -W -f='${Status}' fail2ban 2>/dev/null | grep -q '^install ok installed$'); then
    IPS_INSTALLED=1
    IPS_NAMES+=("Fail2Ban")
    if command_exists systemctl && systemctl is-active --quiet fail2ban 2>/dev/null; then
        IPS_ACTIVE=1
    fi
fi

if command_exists crowdsec || (command_exists dpkg-query && dpkg-query -W -f='${Status}' crowdsec 2>/dev/null | grep -q '^install ok installed$'); then
    IPS_INSTALLED=1
    IPS_NAMES+=("CrowdSec")
    if command_exists systemctl && systemctl is-active --quiet crowdsec 2>/dev/null; then
        IPS_ACTIVE=1
    fi
fi

if command_exists sshguard || (command_exists dpkg-query && dpkg-query -W -f='${Status}' sshguard 2>/dev/null | grep -q '^install ok installed$'); then
    IPS_INSTALLED=1
    IPS_NAMES+=("SSHGuard")
    if command_exists systemctl && systemctl is-active --quiet sshguard 2>/dev/null; then
        IPS_ACTIVE=1
    fi
fi

if command_exists docker && command_exists systemctl && systemctl is-active --quiet docker 2>/dev/null; then
    DOCKER_IPS=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -Ei 'fail2ban|crowdsec|sshguard' || true)
    if [ -n "$DOCKER_IPS" ]; then
        IPS_INSTALLED=1
        IPS_ACTIVE=1
        IPS_NAMES+=("containerized IPS")
        append_report_block "Containerized intrusion-prevention services" "$DOCKER_IPS"
    fi
fi

if [ "$IPS_ACTIVE" -eq 1 ]; then
    report_result "Intrusion Prevention" "PASS" "Active intrusion-prevention tooling detected (${IPS_NAMES[*]})." "Обнаружена активная защита от вторжений (${IPS_NAMES[*]})."
elif [ "$IPS_INSTALLED" -eq 1 ]; then
    report_result "Intrusion Prevention" "WARN" "Intrusion-prevention tooling is installed (${IPS_NAMES[*]}) but no active instance was confirmed." "Средства защиты от вторжений установлены (${IPS_NAMES[*]}), но активный экземпляр не подтверждён."
else
    report_result "Intrusion Prevention" "INFO" "No Fail2Ban, CrowdSec, or SSHGuard installation was detected. This is not mandatory if SSH is otherwise tightly restricted." "Fail2Ban, CrowdSec или SSHGuard не обнаружены. Это не обязательно является проблемой, если SSH иначе жёстко ограничен."
fi

# Fail2Ban SSH port alignment
if command_exists fail2ban-client && [ -d "$FAIL2BAN_CONFIG_DIR" ]; then
    F2B_STATUS=$(fail2ban-client status 2>/dev/null || true)
    if [ -n "$F2B_STATUS" ]; then
        F2B_JAILS=$(printf '%s\n' "$F2B_STATUS" | awk -F: '/Jail list/ {gsub(/^[[:space:]]+/, "", $2); print $2}')
        [ -n "$F2B_JAILS" ] && append_report_block "Fail2Ban active jail list" "$F2B_JAILS"
    fi

    F2B_SSH_ENABLED=$(get_jail_option "sshd" "enabled")
    F2B_SSH_PORT=$(get_jail_option "sshd" "port")
    F2B_BANACTION=$(get_jail_option "sshd" "banaction")
    [ -n "$F2B_BANACTION" ] || F2B_BANACTION=$(get_jail_option "DEFAULT" "banaction")
    [ -n "$F2B_SSH_PORT" ] || F2B_SSH_PORT="ssh"

    SSH_JAIL_ACTIVE=0
    if printf '%s' ",${F2B_JAILS:-}," | tr -d ' ' | grep -q ',sshd,'; then
        SSH_JAIL_ACTIVE=1
    elif [ "$F2B_SSH_ENABLED" = "true" ]; then
        SSH_JAIL_ACTIVE=1
    fi

    if [ "$SSH_JAIL_ACTIVE" -eq 0 ]; then
        report_result "Fail2Ban SSH Jail" "WARN" "Fail2Ban is present, but an active/enabled sshd jail was not confirmed." "Fail2Ban присутствует, но активный/включённый jail sshd не подтверждён."
    elif [[ "$F2B_BANACTION" == *allports* ]]; then
        report_result "Fail2Ban SSH Port Alignment" "PASS" "The sshd jail uses an all-ports banaction, so SSH port $SSH_PORT is covered." "Jail sshd использует блокировку всех портов, поэтому SSH-порт $SSH_PORT защищён."
    elif [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && port_list_contains "$F2B_SSH_PORT" "$SSH_PORT"; then
        report_result "Fail2Ban SSH Port Alignment" "PASS" "The sshd jail port setting '$F2B_SSH_PORT' covers effective SSH port $SSH_PORT." "Настройка порта jail sshd '$F2B_SSH_PORT' охватывает эффективный SSH-порт $SSH_PORT."
    elif [[ "$SSH_PORT" =~ ^[0-9]+$ ]]; then
        report_result "Fail2Ban SSH Port Alignment" "FAIL" "The sshd jail targets '$F2B_SSH_PORT' but SSH listens on $SSH_PORT. Bans may not protect the actual SSH port." "Jail sshd блокирует '$F2B_SSH_PORT', но SSH слушает $SSH_PORT. Блокировки могут не защищать фактический SSH-порт."
    else
        report_result "Fail2Ban SSH Port Alignment" "WARN" "Could not compare the sshd jail port with the effective SSH port." "Не удалось сравнить порт jail sshd с эффективным SSH-портом."
    fi
fi

# Failed SSH authentication attempts, consistently scoped to a time window when journald is available.
FAILED_LOGINS=0
FAILED_LOGIN_SCOPE=""
if command_exists journalctl; then
    SSH_LOGS=$(journalctl -u ssh.service -u sshd.service --since "$FAILED_LOGIN_WINDOW" --no-pager 2>/dev/null || true)
    FAILED_LOGINS=$(printf '%s\n' "$SSH_LOGS" | grep -Ec 'Failed password|Failed publickey|maximum authentication attempts exceeded' || true)
    FAILED_LOGIN_SCOPE="last 24 hours (journald)"
elif [ -r "$AUTH_LOG_FILE" ]; then
    FAILED_LOGINS=$(grep -Ec 'Failed password|Failed publickey|maximum authentication attempts exceeded' "$AUTH_LOG_FILE" 2>/dev/null || true)
    FAILED_LOGIN_SCOPE="current auth.log file (time window unavailable)"
else
    report_result "Failed SSH Logins" "INFO" "No readable SSH authentication log source was found." "Не найден доступный для чтения источник журнала аутентификации SSH."
fi
FAILED_LOGINS=$(safe_count "$FAILED_LOGINS")

if [ -n "$FAILED_LOGIN_SCOPE" ]; then
    if [ "$FAILED_LOGINS" -lt "$LOGINS_WARN" ]; then
        report_result "Failed SSH Logins" "PASS" "$FAILED_LOGINS failed SSH authentication event(s) detected in the $FAILED_LOGIN_SCOPE." "Обнаружено неудачных событий аутентификации SSH: $FAILED_LOGINS за период: $FAILED_LOGIN_SCOPE."
    elif [ "$FAILED_LOGINS" -ge "$LOGINS_HIGH" ] && [ "$IPS_ACTIVE" -eq 0 ] && [ "$SSH_PASSWORD" = "yes" ]; then
        report_result "Failed SSH Logins" "FAIL" "$FAILED_LOGINS failed SSH authentication events detected in the $FAILED_LOGIN_SCOPE while password auth is enabled and no active IPS was confirmed." "Обнаружено $FAILED_LOGINS неудачных попыток SSH за период $FAILED_LOGIN_SCOPE при включённой парольной аутентификации и без подтверждённой активной IPS-защиты."
    else
        report_result "Failed SSH Logins" "WARN" "$FAILED_LOGINS failed SSH authentication event(s) detected in the $FAILED_LOGIN_SCOPE. This indicates attack/scanner activity, not necessarily compromise." "Обнаружено $FAILED_LOGINS неудачных событий аутентификации SSH за период $FAILED_LOGIN_SCOPE. Это указывает на активность сканеров/атакующих, но не обязательно на компрометацию."
    fi
fi

# Listening sockets: inventory TCP listeners separately from UDP bound sockets.
# Large UDP ranges (for example WebRTC media ports) should not inflate the TCP
# attack-surface count or be presented as hundreds of independent services.
if command_exists ss; then
    SS_SOCKETS=$(ss -H -lntu 2>/dev/null || true)

    TCP_LOOPBACK_ENDPOINTS=()
    TCP_NETWORK_ENDPOINTS=()
    TCP_WILDCARD_ENDPOINTS=()
    UDP_LOOPBACK_ENDPOINTS=()
    UDP_NETWORK_ENDPOINTS=()
    UDP_WILDCARD_ENDPOINTS=()

    while read -r proto state recvq sendq local peer rest; do
        [ -n "${local:-}" ] || continue
        addr=$(endpoint_address "$local")
        port=$(endpoint_port "$local")
        endpoint="${proto}/${port} @ ${addr}"

        case "$proto" in
            tcp)
                if is_loopback_address "$addr"; then
                    TCP_LOOPBACK_ENDPOINTS+=("$endpoint")
                elif is_wildcard_address "$addr"; then
                    TCP_WILDCARD_ENDPOINTS+=("$endpoint")
                    TCP_NETWORK_ENDPOINTS+=("$endpoint")
                else
                    TCP_NETWORK_ENDPOINTS+=("$endpoint")
                fi
                ;;
            udp)
                if is_loopback_address "$addr"; then
                    UDP_LOOPBACK_ENDPOINTS+=("$endpoint")
                elif is_wildcard_address "$addr"; then
                    UDP_WILDCARD_ENDPOINTS+=("$endpoint")
                    UDP_NETWORK_ENDPOINTS+=("$endpoint")
                else
                    UDP_NETWORK_ENDPOINTS+=("$endpoint")
                fi
                ;;
        esac
    done <<< "$SS_SOCKETS"

    TCP_LOOPBACK_COUNT=${#TCP_LOOPBACK_ENDPOINTS[@]}
    TCP_NETWORK_COUNT=${#TCP_NETWORK_ENDPOINTS[@]}
    TCP_WILDCARD_COUNT=${#TCP_WILDCARD_ENDPOINTS[@]}
    UDP_LOOPBACK_COUNT=${#UDP_LOOPBACK_ENDPOINTS[@]}
    UDP_NETWORK_COUNT=${#UDP_NETWORK_ENDPOINTS[@]}
    UDP_WILDCARD_COUNT=${#UDP_WILDCARD_ENDPOINTS[@]}

    report_result "TCP Listening Sockets" "INFO" "$TCP_NETWORK_COUNT network-bound TCP listener(s), including $TCP_WILDCARD_COUNT wildcard listener(s), plus $TCP_LOOPBACK_COUNT loopback-only listener(s)." "TCP listeners на сетевых интерфейсах: $TCP_NETWORK_COUNT, из них на всех адресах: $TCP_WILDCARD_COUNT; только loopback: $TCP_LOOPBACK_COUNT."

    if [ "$TCP_NETWORK_COUNT" -gt 0 ]; then
        append_report_block "Network-bound TCP listeners" "$(summarize_endpoint_ranges tcp "${TCP_NETWORK_ENDPOINTS[@]}")"
    fi
    if [ "$TCP_LOOPBACK_COUNT" -gt 0 ]; then
        append_report_block "Loopback-only TCP listeners" "$(summarize_endpoint_ranges tcp "${TCP_LOOPBACK_ENDPOINTS[@]}")"
    fi

    if [ "$TCP_WILDCARD_COUNT" -gt 0 ]; then
        if [ "${FIREWALL_ACTIVE:-0}" -eq 1 ]; then
            report_result "TCP Wildcard Listeners" "INFO" "$TCP_WILDCARD_COUNT TCP listener(s) bind to all local addresses. An active/restrictive firewall was detected; verify intended allowed ports rather than treating wildcard bind as exposure by itself." "$TCP_WILDCARD_COUNT TCP listener(s) привязаны ко всем локальным адресам. Обнаружен активный/ограничивающий firewall; проверьте разрешённые порты, не считая wildcard-привязку сама по себе внешней доступностью."
        else
            report_result "TCP Wildcard Listeners" "WARN" "$TCP_WILDCARD_COUNT TCP listener(s) bind to all local addresses and no restrictive firewall was confirmed." "$TCP_WILDCARD_COUNT TCP listener(s) привязаны ко всем локальным адресам, при этом ограничивающий firewall не подтверждён."
        fi
    else
        report_result "TCP Wildcard Listeners" "PASS" "No wildcard TCP listening sockets were detected." "TCP-сокеты, слушающие на всех адресах, не обнаружены."
    fi

    report_result "UDP Bound Sockets" "INFO" "$UDP_NETWORK_COUNT network-bound UDP socket(s), including $UDP_WILDCARD_COUNT wildcard socket(s), plus $UDP_LOOPBACK_COUNT loopback-only socket(s). UDP counts can be large for WebRTC/VPN/media port ranges and are reported separately from TCP listeners." "UDP-сокетов на сетевых интерфейсах: $UDP_NETWORK_COUNT, из них на всех адресах: $UDP_WILDCARD_COUNT; только loopback: $UDP_LOOPBACK_COUNT. Для WebRTC/VPN/медиа диапазонов число UDP-сокетов может быть большим, поэтому они учитываются отдельно от TCP listeners."

    if [ "$UDP_NETWORK_COUNT" -gt 0 ]; then
        append_report_block "Network-bound UDP sockets" "$(summarize_endpoint_ranges udp "${UDP_NETWORK_ENDPOINTS[@]}")"
    fi
    if [ "$UDP_LOOPBACK_COUNT" -gt 0 ]; then
        append_report_block "Loopback-only UDP sockets" "$(summarize_endpoint_ranges udp "${UDP_LOOPBACK_ENDPOINTS[@]}")"
    fi

    if [ "$UDP_WILDCARD_COUNT" -gt 0 ] && [ "${FIREWALL_ACTIVE:-0}" -ne 1 ]; then
        report_result "UDP Wildcard Sockets" "WARN" "$UDP_WILDCARD_COUNT UDP socket(s) bind to all local addresses and no restrictive firewall was confirmed." "$UDP_WILDCARD_COUNT UDP-сокет(ов) привязаны ко всем локальным адресам, при этом ограничивающий firewall не подтверждён."
    elif [ "$UDP_WILDCARD_COUNT" -gt 0 ]; then
        report_result "UDP Wildcard Sockets" "INFO" "$UDP_WILDCARD_COUNT UDP socket(s) bind to all local addresses. Review intended firewall/NAT exposure, especially large media port ranges." "$UDP_WILDCARD_COUNT UDP-сокет(ов) привязаны ко всем локальным адресам. Проверьте ожидаемую доступность через firewall/NAT, особенно для больших диапазонов медиапортов."
    else
        report_result "UDP Wildcard Sockets" "PASS" "No wildcard UDP sockets were detected." "UDP-сокеты, привязанные ко всем адресам, не обнаружены."
    fi
else
    report_result "Listening Sockets" "WARN" "The ss utility is unavailable; socket exposure could not be inventoried." "Утилита ss недоступна; инвентаризация прослушиваемых сокетов не выполнена."
fi

# Docker host-published ports, if Docker is active. Docker's formatted Ports
# field also lists container-only EXPOSE metadata; only entries containing `->`
# are actual host publications and should be treated as host attack surface.
if command_exists docker && command_exists systemctl && systemctl is-active --quiet docker 2>/dev/null; then
    DOCKER_PORT_ROWS=$(docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null | awk -F'\t' '$2 != "" {print}' || true)
    # Keep only comma-separated port entries that contain an actual host mapping.
    # This prevents container-only EXPOSE metadata from leaking into the detailed
    # "host-published" report block when the same container also has one mapping.
    DOCKER_PUBLISHED=$(printf '%s\n' "$DOCKER_PORT_ROWS" | awk -F'\t' '
        {
            count = split($2, ports, /,[[:space:]]*/)
            published = ""
            for (i = 1; i <= count; i++) {
                if (ports[i] ~ /->/) {
                    published = published (published == "" ? "" : ", ") ports[i]
                }
            }
            if (published != "") {
                print $1 "\t" published
            }
        }
    ' || true)

    if [ -n "$DOCKER_PUBLISHED" ]; then
        append_report_block "Docker host-published ports" "$DOCKER_PUBLISHED"

        DOCKER_WILDCARD=$(printf '%s\n' "$DOCKER_PUBLISHED" | grep -Ec '(^|[[:space:],])0\.0\.0\.0:|(^|[[:space:],])\[::\]:' || true)
        DOCKER_LOOPBACK=$(printf '%s\n' "$DOCKER_PUBLISHED" | grep -Ec '(^|[[:space:],])127\.[0-9]+\.[0-9]+\.[0-9]+:|(^|[[:space:],])\[::1\]:' || true)
        DOCKER_WILDCARD=$(safe_count "$DOCKER_WILDCARD")
        DOCKER_LOOPBACK=$(safe_count "$DOCKER_LOOPBACK")

        if [ "$DOCKER_WILDCARD" -gt 0 ]; then
            report_result "Docker Port Publishing" "WARN" "$DOCKER_WILDCARD running container(s) include host ports published on wildcard addresses (0.0.0.0/[::]). Verify that each publication is intentionally reachable beyond localhost." "$DOCKER_WILDCARD запущенных контейнер(а/ов) содержат host-порты, опубликованные на всех адресах (0.0.0.0/[::]). Проверьте, что каждый такой порт действительно должен быть доступен не только через localhost."
        elif [ "$DOCKER_LOOPBACK" -gt 0 ]; then
            report_result "Docker Port Publishing" "PASS" "Host-published Docker ports are bound to loopback addresses only in the recognized output." "Распознанные опубликованные Docker-порты привязаны только к loopback-адресам."
        else
            report_result "Docker Port Publishing" "INFO" "Docker publishes host ports on explicit non-wildcard addresses. Verify that those interface bindings are intentional." "Docker публикует host-порты на явно указанных не-wildcard адресах. Проверьте, что такие привязки к интерфейсам ожидаемы."
        fi

        # Docker-managed forwarding can occur before the normal UFW INPUT path.
        # If the classic DOCKER-USER chain exists but has no user rules, do not
        # assume that `ufw status` alone restricts wildcard-published ports.
        if command_exists iptables; then
            DOCKER_USER_RULESET=$(iptables -S DOCKER-USER 2>/dev/null || true)
            if printf '%s\n' "$DOCKER_USER_RULESET" | grep -q '^-N DOCKER-USER$'; then
                DOCKER_USER_RULE_COUNT=$(printf '%s\n' "$DOCKER_USER_RULESET" | grep '^-A DOCKER-USER ' | grep -vcE ' -j RETURN$' || true)
                DOCKER_USER_RULE_COUNT=$(safe_count "$DOCKER_USER_RULE_COUNT")
                if [ "$DOCKER_WILDCARD" -gt 0 ] && [ "$UFW_ACTIVE" -eq 1 ] && [ "$DOCKER_USER_RULE_COUNT" -eq 0 ]; then
                    report_result "Docker Firewall Integration" "WARN" "UFW is active and Docker has wildcard-published ports, but DOCKER-USER contains no user filtering rules. Do not assume UFW INPUT rules alone restrict these Docker publications; validate Docker forwarding/firewall policy explicitly." "UFW активен и у Docker есть wildcard-публикации, но в DOCKER-USER нет пользовательских правил фильтрации. Не считайте, что одни правила UFW INPUT гарантированно ограничивают эти Docker-порты; отдельно проверьте forwarding/firewall Docker."
                elif [ "$DOCKER_USER_RULE_COUNT" -gt 0 ]; then
                    report_result "Docker Firewall Integration" "INFO" "DOCKER-USER contains $DOCKER_USER_RULE_COUNT user rule(s). Review them together with UFW/nftables and provider firewall policy." "В DOCKER-USER обнаружено пользовательских правил: $DOCKER_USER_RULE_COUNT. Проверьте их совместно с UFW/nftables и firewall провайдера."
                elif [ "$DOCKER_WILDCARD" -eq 0 ]; then
                    report_result "Docker Firewall Integration" "PASS" "No wildcard Docker host publication was recognized, so an empty DOCKER-USER chain is not an immediate exposure finding." "Wildcard-публикации Docker на хосте не обнаружены, поэтому пустая цепочка DOCKER-USER сама по себе не является признаком внешней доступности."
                else
                    report_result "Docker Firewall Integration" "INFO" "DOCKER-USER exists without user rules. Review Docker forwarding policy if host-published ports should be restricted." "DOCKER-USER существует без пользовательских правил. Проверьте forwarding-политику Docker, если опубликованные host-порты должны быть ограничены."
                fi
            else
                report_result "Docker Firewall Integration" "INFO" "The classic iptables DOCKER-USER chain was not detected. Docker may be using a different firewall backend; validate published-port filtering manually." "Классическая iptables-цепочка DOCKER-USER не обнаружена. Docker может использовать другой backend firewall; фильтрацию опубликованных портов нужно проверить вручную."
            fi
        fi
    else
        report_result "Docker Port Publishing" "PASS" "Docker is active and no running container publishes a host port. Container-only EXPOSE entries are not counted as host publications." "Docker активен; ни один запущенный контейнер не публикует host-порт. Внутренние EXPOSE-порты контейнеров не считаются публикацией на хосте."
    fi
fi

# Sudo logging. Classic sudo normally logs via syslog/journald even without a
# dedicated logfile. sudo-rs also logs to the system journal by default.
if command_exists sudo; then
    SUDO_VERSION=$(sudo --version 2>/dev/null | head -1 || true)
    if printf '%s' "$SUDO_VERSION" | grep -qi 'sudo-rs'; then
        report_result "Sudo Logging" "PASS" "sudo-rs detected; commands are expected to be logged through the system logging stack by default." "Обнаружен sudo-rs; команды по умолчанию должны журналироваться через системный стек логирования."
    elif grep -rqsE '^[[:space:]]*Defaults([^#]*,)?[[:space:]]*logfile[[:space:]]*=' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
        report_result "Sudo Logging" "PASS" "A dedicated sudo logfile is configured in /etc/sudoers or /etc/sudoers.d." "Отдельный журнал sudo настроен в /etc/sudoers или /etc/sudoers.d."
    elif command_exists journalctl && journalctl -t sudo -n 1 --no-pager 2>/dev/null | grep -q .; then
        report_result "Sudo Logging" "PASS" "Recent sudo journal entries are present; system logging is working." "В журнале есть недавние записи sudo; системное журналирование работает."
    else
        report_result "Sudo Logging" "INFO" "No dedicated sudo logfile or recent sudo journal entry was confirmed. Classic sudo normally logs via syslog/journald; verify manually if audit-grade command logging is required." "Отдельный журнал sudo или недавние записи sudo не подтверждены. Классический sudo обычно пишет в syslog/journald; при необходимости аудиторского уровня журналирования проверьте вручную."
    fi
else
    report_result "Sudo Logging" "INFO" "sudo is not installed. This can be normal on root-managed minimal Debian systems." "sudo не установлен. Для минимальных Debian-систем, администрируемых напрямую от root, это может быть нормально."
fi

# Password policy. Do not claim the host "accepts weak passwords" solely because
# pwquality.conf is absent; PAM or passwordless/key-only administration may apply.
PW_MINLEN=""
PW_SOURCE=""
if [ -r /etc/security/pwquality.conf ]; then
    PW_MINLEN=$(awk -F= '/^[[:space:]]*minlen[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); val=$2} END{print val}' /etc/security/pwquality.conf)
    [ -n "$PW_MINLEN" ] && PW_SOURCE="pwquality.conf"
fi
if [ -z "$PW_MINLEN" ] && [ -r /etc/pam.d/common-password ]; then
    PW_MINLEN=$(grep -E '^[[:space:]]*password.*pam_pwquality\.so' /etc/pam.d/common-password 2>/dev/null | tail -1 | grep -oE 'minlen=[0-9]+' | cut -d= -f2)
    [ -n "$PW_MINLEN" ] && PW_SOURCE="PAM pam_pwquality"
fi

if [[ "$PW_MINLEN" =~ ^[0-9]+$ ]]; then
    if [ "$PW_MINLEN" -ge "$PASSWORD_MINLEN" ]; then
        report_result "Password Policy" "PASS" "Explicit minimum password length is $PW_MINLEN via $PW_SOURCE." "Явно заданная минимальная длина пароля: $PW_MINLEN через $PW_SOURCE."
    else
        report_result "Password Policy" "WARN" "Explicit minimum password length is $PW_MINLEN via $PW_SOURCE, below the audit guidance of $PASSWORD_MINLEN." "Явно заданная минимальная длина пароля: $PW_MINLEN через $PW_SOURCE, что ниже рекомендации аудита $PASSWORD_MINLEN."
    fi
elif [ "$SSH_PASSWORD" = "no" ]; then
    report_result "Password Policy" "INFO" "No explicit pwquality minimum length was found, but SSH password authentication is disabled. Review local-account policy if interactive local passwords are used." "Явная минимальная длина pwquality не найдена, но парольная аутентификация SSH отключена. Проверьте политику локальных учётных записей, если используются интерактивные локальные пароли."
else
    report_result "Password Policy" "WARN" "No explicit pwquality minimum length was found while SSH password authentication is not confirmed disabled. Review PAM/password policy." "Явная минимальная длина pwquality не найдена, а отключение парольной аутентификации SSH не подтверждено. Проверьте PAM и политику паролей."
fi

# SUID files: stay on the host root filesystem and prune common container/image
# storage. Files inside Docker/containerd/Snap image stores are not host executables
# and otherwise create large false-positive sets when checked with host dpkg-query.
if command_exists find; then
    mapfile -t SUID_FILES < <(
        find / -xdev \
            \( -path /var/lib/docker -o -path '/var/lib/docker/*' \
               -o -path /var/lib/containerd -o -path '/var/lib/containerd/*' \
               -o -path /var/lib/containers -o -path '/var/lib/containers/*' \
               -o -path /var/lib/lxc -o -path '/var/lib/lxc/*' \
               -o -path /var/lib/snapd -o -path '/var/lib/snapd/*' \
               -o -path /snap -o -path '/snap/*' \) -prune -o \
            -type f -perm -4000 -print 2>/dev/null
    )
    SUID_TOTAL=${#SUID_FILES[@]}
    SUID_UNOWNED=()

    if command_exists dpkg-query; then
        for suid_file in "${SUID_FILES[@]}"; do
            if ! dpkg_path_is_owned "$suid_file"; then
                SUID_UNOWNED+=("$suid_file")
            fi
        done
    fi

    append_report_block "SUID files on root filesystem" "$(printf '%s\n' "${SUID_FILES[@]:-None}")"
    if [ "${#SUID_UNOWNED[@]}" -eq 0 ]; then
        report_result "SUID Files" "PASS" "$SUID_TOTAL SUID file(s) found on the root filesystem; none were identified as unowned by installed Debian packages." "В корневой файловой системе найдено SUID-файлов: $SUID_TOTAL; все они принадлежат установленным пакетам Debian."
    else
        append_report_block "SUID files not owned by a Debian package" "$(printf '%s\n' "${SUID_UNOWNED[@]}")"
        report_result "SUID Files" "WARN" "${#SUID_UNOWNED[@]} of $SUID_TOTAL SUID file(s) are not owned by an installed Debian package. Verify whether they are intentional." "${#SUID_UNOWNED[@]} из $SUID_TOTAL SUID-файлов не принадлежат установленным пакетам Debian. Проверьте, являются ли они ожидаемыми."
    fi
else
    report_result "SUID Files" "INFO" "find is unavailable; SUID inventory skipped." "Утилита find недоступна; инвентаризация SUID-файлов пропущена."
fi

# -----------------------------------------
# Health checks (not security scoring)
# -----------------------------------------
print_header "System Health"

# Disk
DISK_TOTAL=$(df -hP / 2>/dev/null | awk 'NR==2 {print $2}')
DISK_USED=$(df -hP / 2>/dev/null | awk 'NR==2 {print $3}')
DISK_AVAIL=$(df -hP / 2>/dev/null | awk 'NR==2 {print $4}')
DISK_USAGE=$(df -P / 2>/dev/null | awk 'NR==2 {gsub(/%/, "", $5); print $5}')
DISK_USAGE=$(safe_count "$DISK_USAGE")
if [ "$DISK_USAGE" -ge "$RESOURCE_FAIL" ]; then
    report_result "Root Filesystem Usage" "FAIL" "${DISK_USAGE}% used (${DISK_USED:-?}/${DISK_TOTAL:-?}, ${DISK_AVAIL:-?} available). This is an availability risk, not a direct security finding." "Использовано ${DISK_USAGE}% (${DISK_USED:-?}/${DISK_TOTAL:-?}, доступно ${DISK_AVAIL:-?}). Это риск доступности, а не прямой результат проверки безопасности."
elif [ "$DISK_USAGE" -ge "$RESOURCE_WARN" ]; then
    report_result "Root Filesystem Usage" "WARN" "${DISK_USAGE}% used (${DISK_USED:-?}/${DISK_TOTAL:-?}, ${DISK_AVAIL:-?} available)." "Использовано ${DISK_USAGE}% (${DISK_USED:-?}/${DISK_TOTAL:-?}, доступно ${DISK_AVAIL:-?})."
else
    report_result "Root Filesystem Usage" "PASS" "${DISK_USAGE}% used (${DISK_USED:-?}/${DISK_TOTAL:-?}, ${DISK_AVAIL:-?} available)." "Использовано ${DISK_USAGE}% (${DISK_USED:-?}/${DISK_TOTAL:-?}, доступно ${DISK_AVAIL:-?})."
fi

# Memory: use MemAvailable, which accounts for reclaimable cache.
if [ -r /proc/meminfo ]; then
    MEM_TOTAL_KB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    MEM_AVAIL_KB=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
    if [[ "$MEM_TOTAL_KB" =~ ^[0-9]+$ && "$MEM_AVAIL_KB" =~ ^[0-9]+$ && "$MEM_TOTAL_KB" -gt 0 ]]; then
        MEM_USAGE=$((100 - (100 * MEM_AVAIL_KB / MEM_TOTAL_KB)))
        MEM_DESC=$(free -h 2>/dev/null | awk '/^Mem:/ {print $3" used, "$7" available of "$2}')
        if [ "$MEM_USAGE" -ge "$RESOURCE_FAIL" ]; then
            report_result "Memory Pressure" "FAIL" "Approximately ${MEM_USAGE}% non-available memory ($MEM_DESC)." "Примерно ${MEM_USAGE}% памяти недоступно для новых задач ($MEM_DESC)."
        elif [ "$MEM_USAGE" -ge "$RESOURCE_WARN" ]; then
            report_result "Memory Pressure" "WARN" "Approximately ${MEM_USAGE}% non-available memory ($MEM_DESC)." "Примерно ${MEM_USAGE}% памяти недоступно для новых задач ($MEM_DESC)."
        else
            report_result "Memory Pressure" "PASS" "Approximately ${MEM_USAGE}% non-available memory ($MEM_DESC)." "Примерно ${MEM_USAGE}% памяти недоступно для новых задач ($MEM_DESC)."
        fi
    fi
fi

CPU_USAGE=$(get_cpu_usage_percent 2>/dev/null || printf '')
if [[ "$CPU_USAGE" =~ ^[0-9]+$ ]]; then
    if [ "$CPU_USAGE" -ge "$RESOURCE_FAIL" ]; then
        report_result "CPU Usage" "FAIL" "Approximately ${CPU_USAGE}% CPU utilization during a 1-second sample." "Примерно ${CPU_USAGE}% загрузки CPU по выборке длительностью 1 секунду."
    elif [ "$CPU_USAGE" -ge "$RESOURCE_WARN" ]; then
        report_result "CPU Usage" "WARN" "Approximately ${CPU_USAGE}% CPU utilization during a 1-second sample." "Примерно ${CPU_USAGE}% загрузки CPU по выборке длительностью 1 секунду."
    else
        report_result "CPU Usage" "PASS" "Approximately ${CPU_USAGE}% CPU utilization during a 1-second sample." "Примерно ${CPU_USAGE}% загрузки CPU по выборке длительностью 1 секунду."
    fi
else
    report_result "CPU Usage" "INFO" "CPU utilization sample could not be calculated." "Не удалось рассчитать загрузку CPU."
fi

# Running/failed services: counts are informational; failed units are actionable.
if command_exists systemctl; then
    RUNNING_SERVICES=$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | grep -c '\.service' || true)
    RUNNING_SERVICES=$(safe_count "$RUNNING_SERVICES")
    report_result "Running Services" "INFO" "$RUNNING_SERVICES systemd service(s) are currently running. Service count alone is not a security score." "Сейчас запущено служб systemd: $RUNNING_SERVICES. Само количество служб не является оценкой безопасности."

    FAILED_UNITS=$(systemctl --failed --type=service --no-legend --no-pager 2>/dev/null || true)
    FAILED_UNIT_COUNT=$(printf '%s\n' "$FAILED_UNITS" | grep -c '\.service' || true)
    FAILED_UNIT_COUNT=$(safe_count "$FAILED_UNIT_COUNT")
    if [ "$FAILED_UNIT_COUNT" -eq 0 ]; then
        report_result "Failed Services" "PASS" "No failed systemd services detected." "Службы systemd в состоянии failed не обнаружены."
    else
        append_report_block "Failed systemd services" "$FAILED_UNITS"
        report_result "Failed Services" "WARN" "$FAILED_UNIT_COUNT failed systemd service(s) detected." "Обнаружено служб systemd в состоянии failed: $FAILED_UNIT_COUNT."
    fi
fi

if command_exists ss; then
    ESTABLISHED=$(ss -H -tn state established 2>/dev/null | wc -l)
    ESTABLISHED=$(safe_count "$ESTABLISHED")
    report_result "Established TCP Connections" "INFO" "$ESTABLISHED established TCP connection(s) at audit time." "На момент аудита установлено TCP-соединений: $ESTABLISHED."
fi

# -----------------------------------------
# End report
# -----------------------------------------
{
    printf '\n================================\n'
    printf 'End of VPS Audit Report (Конец отчёта аудита VPS)\n'
    printf 'Completed at %s (Завершено)\n' "$(date)"
    printf 'Notes (Примечания):\n'
    printf -- '- WARN/FAIL findings should be validated in context before changing production configuration. (Результаты WARN/FAIL нужно проверять в контексте перед изменением production-конфигурации.)\n'
    printf -- '- Network-bound or wildcard listeners are not automatically Internet-accessible; provider firewalls, NAT, and host rules matter. (Сетевые/wildcard listeners не обязательно доступны из Интернета; важны firewall провайдера, NAT и правила хоста.)\n'
    printf -- '- The script intentionally does not run apt update or modify system state. (Скрипт намеренно не выполняет apt update и не изменяет состояние системы.)\n'
} >> "$REPORT_FILE"

chmod 600 "$REPORT_FILE" 2>/dev/null || true
if [ "$ENABLE_CHOWN" = true ]; then
    chown "$REPORT_CHOWN_OWNER" "$REPORT_FILE" 2>/dev/null || true
fi

printf '\n%bAudit complete (Аудит завершён).%b Report (Отчёт): %s\n' "${GREEN}${BOLD}" "$NC" "$REPORT_FILE"
printf '%bNo server configuration was changed. (Конфигурация сервера не изменялась.)%b\n' "$GRAY" "$NC"
