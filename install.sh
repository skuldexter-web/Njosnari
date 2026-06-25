#!/usr/bin/env bash
# =============================================================================
#  ███╗   ██╗     ██╗ ██████╗ ███████╗███╗   ██╗ █████╗ ██████╗ ██╗
#  ████╗  ██║     ██║██╔═══██╗██╔════╝████╗  ██║██╔══██╗██╔══██╗██║
#  ██╔██╗ ██║     ██║██║   ██║███████╗██╔██╗ ██║███████║██████╔╝██║
#  ██║╚██╗██║██   ██║██║   ██║╚════██║██║╚██╗██║██╔══██║██╔══██╗██║
#  ██║ ╚████║╚█████╔╝╚██████╔╝███████║██║ ╚████║██║  ██║██║  ██║██║
#  ╚═╝  ╚═══╝ ╚════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
#
#   Njosnari - The Recon Viking | Installer v1.0.0
#   Author  : @s.k.7.l.d  (SⱩUⱠÐ / SK7LD)
#   GitHub  : https://github.com/skuldexter-web
#   Target  : Debian / Kali / Ubuntu (x86_64 & ARM64)
#   License : MIT
# =============================================================================
#!/usr/bin/env bash
# =============================================================================
#  ███╗   ██╗     ██╗ ██████╗ ███████╗███╗   ██╗ █████╗ ██████╗ ██╗
#  ████╗  ██║     ██║██╔═══██╗██╔════╝████╗  ██║██╔══██╗██╔══██╗██║
#  ██╔██╗ ██║     ██║██║   ██║███████╗██╔██╗ ██║███████║██████╔╝██║
#  ██║╚██╗██║██   ██║██║   ██║╚════██║██║╚██╗██║██╔══██║██╔══██╗██║
#  ██║ ╚████║╚█████╔╝╚██████╔╝███████║██║ ╚████║██║  ██║██║  ██║██║
#  ╚═╝  ╚═══╝ ╚════╝  ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
#
#   Njosnari - The Recon Viking | Installer v1.0.0
#   Author  : @s.k.7.l.d  (SⱩUⱠÐ / SK7LD)
#   GitHub  : https://github.com/skuldexter-web
#   Target  : Debian / Kali / Ubuntu (x86_64 & ARM64)
#   License : MIT
# =============================================================================

set -euo pipefail

# ── Colour palette ────────────────────────────────────────────────────────────
RED='\033[0;31m'
BLOOD='\033[1;31m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Constants ─────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/njosnari"
VENV_DIR="${INSTALL_DIR}/venv"
SCRIPT_NAME="njosnari.py"
OLLAMA_MODEL="qwen2.5:3b"
LOG_FILE="/tmp/njosnari_install.log"
ARCH=$(uname -m)

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
    echo -e "${BLOOD}"
    cat << 'EOF'
  ██╗   ██╗██╗██╗  ██╗██╗███╗   ██╗ ██████╗ ██████╗
  ██║   ██║██║██║ ██╔╝██║████╗  ██║██╔════╝ ╚════██╗
  ██║   ██║██║█████╔╝ ██║██╔██╗ ██║██║  ███╗ █████╔╝
  ╚██╗ ██╔╝██║██╔═██╗ ██║██║╚██╗██║██║   ██║ ╚═══██╗
   ╚████╔╝ ██║██║  ██╗██║██║ ╚████║╚██████╔╝██████╔╝
    ╚═══╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝

          ⚔  N J Ó S N A R I  —  T H E  R E C O N  V I K I N G  ⚔
              Installer  |  @s.k.7.l.d  |  SK7LD Security Tools
EOF
    echo -e "${RESET}"
}

# ── Helpers ───────────────────────────────────────────────────────────────────
log()     { echo -e "${DIM}[$(date '+%H:%M:%S')]${RESET} $*" | tee -a "$LOG_FILE"; }
info()    { echo -e "${CYAN}[*]${RESET} $*" | tee -a "$LOG_FILE"; }
ok()      { echo -e "${GREEN}[✓]${RESET} $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$LOG_FILE"; }
err()     { echo -e "${BLOOD}[✗]${RESET} $*" | tee -a "$LOG_FILE"; }
section() { echo -e "\n${BOLD}${RED}━━━  $*  ━━━${RESET}\n" | tee -a "$LOG_FILE"; }
die()     { err "$*"; exit 1; }

cmd_exists() { command -v "$1" &>/dev/null; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "Njosnari installer must run as root.  Use: sudo bash install.sh"
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO="${ID}"
        DISTRO_VERSION="${VERSION_ID:-unknown}"
    else
        DISTRO="unknown"
        DISTRO_VERSION="unknown"
    fi

    case "$DISTRO" in
        kali|debian|ubuntu|parrot|linuxmint) : ;;
        *)
            warn "Detected distro '${DISTRO}' — this installer targets Debian/Kali/Ubuntu."
            warn "Proceeding anyway; some packages may differ."
            ;;
    esac
    info "Distro: ${DISTRO} ${DISTRO_VERSION} | Arch: ${ARCH}"
}

# ── Phase 0: Pre-flight ───────────────────────────────────────────────────────
preflight() {
    section "Phase 0 — Pre-flight Checks"
    require_root
    detect_distro

    info "Initialising log → ${LOG_FILE}"
    : > "$LOG_FILE"

    # Check internet connectivity
    if ! ping -c1 -W3 8.8.8.8 &>/dev/null; then
        warn "No internet detected — some downloads may fail."
    else
        ok "Network connectivity confirmed."
    fi
}

# ── Phase 1: System Update ────────────────────────────────────────────────────
system_update() {
    section "Phase 1 — System Update"
    info "Running apt update..."
    apt-get update -qq 2>&1 | tee -a "$LOG_FILE"
    ok "apt update complete."
}

# ── Phase 2: System Dependencies ─────────────────────────────────────────────
install_system_deps() {
    section "Phase 2 — System Dependencies"

    local pkgs=(
        # Core build tools
        build-essential git curl wget unzip tar ca-certificates gnupg lsb-release
        # Python
        python3 python3-pip python3-venv python3-dev
        # Network recon tools
        nmap dnsutils whois netcat-traditional openssl
        # SSL/TLS tools
        sslscan
        # Port scanning
        masscan
        # DNS/subdomain
        dnsrecon
        # WAF & web tools
        nikto dirb gobuster
        # Metasploit dependencies
        postgresql libpq-dev ruby ruby-dev ruby-bundler
        # Misc utilities
        jq htop tmux net-tools iputils-ping procps
    )

    local to_install=()
    for pkg in "${pkgs[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null 2>&1; then
            to_install+=("$pkg")
        else
            log "  already installed: ${pkg}"
        fi
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        info "Installing ${#to_install[@]} package(s): ${to_install[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            "${to_install[@]}" 2>&1 | tee -a "$LOG_FILE"
        ok "System packages installed."
    else
        ok "All system packages already present."
    fi
}

# ── Phase 3: Metasploit Framework ────────────────────────────────────────────
install_metasploit() {
    section "Phase 3 — Metasploit Framework"

    if cmd_exists msfconsole; then
        ok "Metasploit Framework already installed at $(command -v msfconsole)."
        return 0
    fi

    # Kali ships Metasploit natively
    if [[ "$DISTRO" == "kali" ]]; then
        info "Kali detected — installing metasploit-framework via apt..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y metasploit-framework 2>&1 | tee -a "$LOG_FILE"
    else
        # Official Rapid7 installer for Ubuntu/Debian
        info "Downloading Rapid7 Metasploit installer..."
        local msf_installer="/tmp/msfinstall.sh"
        curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
            -o "$msf_installer" 2>&1 | tee -a "$LOG_FILE" \
        || {
            # Fallback: apt package on Debian/Ubuntu
            warn "Rapid7 installer download failed. Attempting apt fallback..."
            curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key \
                | gpg --dearmor > /usr/share/keyrings/metasploit-framework.gpg
            echo "deb [signed-by=/usr/share/keyrings/metasploit-framework.gpg] \
https://apt.metasploit.com/ $(lsb_release -cs) main" \
                > /etc/apt/sources.list.d/metasploit-framework.list
            apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y metasploit-framework
            msf_installer=""
        }
        if [[ -n "${msf_installer:-}" && -f "$msf_installer" ]]; then
            chmod +x "$msf_installer"
            bash "$msf_installer" 2>&1 | tee -a "$LOG_FILE"
        fi
    fi

    if cmd_exists msfconsole; then
        ok "Metasploit Framework installed successfully."
    else
        warn "msfconsole not found in PATH after install — check ${LOG_FILE}."
    fi

    # Initialise the MSF database (PostgreSQL)
    info "Initialising Metasploit PostgreSQL database..."
    systemctl enable postgresql --quiet 2>/dev/null || true
    systemctl start postgresql --quiet 2>/dev/null || true
    if cmd_exists msfdb; then
        msfdb init 2>&1 | tee -a "$LOG_FILE" || warn "msfdb init returned non-zero (may already be initialised)."
        ok "Metasploit database ready."
    fi
}

# ── Phase 4: Ollama LLM Engine ───────────────────────────────────────────────
install_ollama() {
    section "Phase 4 — Ollama LLM Engine"

    if cmd_exists ollama; then
        ok "Ollama already installed at $(command -v ollama)."
    else
        info "Fetching official Ollama install script..."
        curl -fsSL https://ollama.com/install.sh | bash 2>&1 | tee -a "$LOG_FILE"

        if cmd_exists ollama; then
            ok "Ollama installed successfully."
        else
            die "Ollama installation failed. Check ${LOG_FILE} for details."
        fi
    fi

    # Start Ollama daemon if not running
    info "Starting Ollama daemon..."
    if systemctl is-active --quiet ollama 2>/dev/null; then
        ok "Ollama service already running."
    else
        # Try systemd first, fall back to background process
        systemctl enable ollama --quiet 2>/dev/null && systemctl start ollama --quiet 2>/dev/null \
        || {
            warn "systemd start failed — launching ollama serve in background..."
            nohup ollama serve >> "$LOG_FILE" 2>&1 &
            sleep 3
        }
    fi

    # Wait for Ollama API to be reachable (max 30 s)
    info "Waiting for Ollama API at http://localhost:11434 ..."
    local retries=30
    until curl -sf http://localhost:11434/ &>/dev/null || [[ $retries -eq 0 ]]; do
        sleep 1
        (( retries-- ))
    done

    if [[ $retries -eq 0 ]]; then
        warn "Ollama API did not respond in time — model pull may fail."
    else
        ok "Ollama API is live."
    fi

    # Pull the lightweight model
    pull_ollama_model
}

pull_ollama_model() {
    info "Checking for model: ${OLLAMA_MODEL} ..."

    # Check if model already present
    if ollama list 2>/dev/null | grep -q "${OLLAMA_MODEL}"; then
        ok "Model '${OLLAMA_MODEL}' already pulled."
        return 0
    fi

    info "Pulling '${OLLAMA_MODEL}' — this may take a few minutes (~2 GB)..."
    if ollama pull "${OLLAMA_MODEL}" 2>&1 | tee -a "$LOG_FILE"; then
        ok "Model '${OLLAMA_MODEL}' ready."
    else
        warn "Model pull returned non-zero — verify manually with: ollama pull ${OLLAMA_MODEL}"
    fi
}

# ── Phase 5: Python Environment ───────────────────────────────────────────────
setup_python_env() {
    section "Phase 5 — Python Virtual Environment"

    info "Creating install directory: ${INSTALL_DIR}"
    mkdir -p "${INSTALL_DIR}"

    if [[ -d "${VENV_DIR}" ]]; then
        ok "Virtual environment already exists at ${VENV_DIR}."
    else
        info "Creating Python venv..."
        python3 -m venv "${VENV_DIR}" 2>&1 | tee -a "$LOG_FILE"
        ok "Venv created."
    fi

    info "Upgrading pip inside venv..."
    "${VENV_DIR}/bin/pip" install --quiet --upgrade pip 2>&1 | tee -a "$LOG_FILE"

    info "Installing Python dependencies..."
    local py_pkgs=(
        requests
        urllib3
        dnspython
        cryptography
        pyOpenSSL
        colorama
        rich
        python-whois
        tqdm
        aiohttp
        aiofiles
    )

    "${VENV_DIR}/bin/pip" install --quiet "${py_pkgs[@]}" 2>&1 | tee -a "$LOG_FILE"
    ok "Python dependencies installed."
}

# ── Phase 6: Deploy Njosnari Script ──────────────────────────────────────────
deploy_script() {
    section "Phase 6 — Deploy Njosnari"

    local script_src
    script_src="$(dirname "$(realpath "$0")")/${SCRIPT_NAME}"

    if [[ ! -f "$script_src" ]]; then
        warn "${SCRIPT_NAME} not found next to install.sh — skipping script copy."
        warn "Place '${SCRIPT_NAME}' in ${INSTALL_DIR} manually."
        return 0
    fi

    cp -f "$script_src" "${INSTALL_DIR}/${SCRIPT_NAME}"
    chmod 750 "${INSTALL_DIR}/${SCRIPT_NAME}"
    ok "Deployed ${SCRIPT_NAME} → ${INSTALL_DIR}/${SCRIPT_NAME}"

    # Create global launcher
    cat > /usr/local/bin/njosnari << LAUNCHER
#!/usr/bin/env bash
# Njosnari global launcher — generated by install.sh
exec "${VENV_DIR}/bin/python3" "${INSTALL_DIR}/${SCRIPT_NAME}" "\$@"
LAUNCHER
    chmod 755 /usr/local/bin/njosnari
    ok "Global launcher created: /usr/local/bin/njosnari"
}

# ── Phase 7: Post-install System Upgrade ──────────────────────────────────────
post_upgrade() {
    section "Phase 7 — Post-Install System Upgrade"
    info "Running apt upgrade -y (this may take a while)..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
        2>&1 | tee -a "$LOG_FILE"
    ok "System fully upgraded."

    info "Cleaning apt cache..."
    apt-get autoremove -y --purge -qq 2>&1 | tee -a "$LOG_FILE"
    apt-get clean -qq 2>&1 | tee -a "$LOG_FILE"
    ok "Cache cleaned."
}

# ── Phase 8: Verify Installation ─────────────────────────────────────────────
verify_install() {
    section "Phase 8 — Verification"

    local all_ok=true
    check_tool() {
        local name="$1"
        local check_cmd="$2"
        if eval "$check_cmd" &>/dev/null; then
            ok "  ${name}"
        else
            warn "  ${name} — NOT FOUND (non-fatal)"
            all_ok=false
        fi
    }

    check_tool "python3"         "command -v python3"
    check_tool "nmap"            "command -v nmap"
    check_tool "sslscan"         "command -v sslscan"
    check_tool "dnsrecon"        "command -v dnsrecon"
    check_tool "nikto"           "command -v nikto"
    check_tool "gobuster"        "command -v gobuster"
    check_tool "ollama"          "command -v ollama"
    check_tool "ollama daemon"   "curl -sf http://localhost:11434/"
    check_tool "model: ${OLLAMA_MODEL}" "ollama list | grep -q '${OLLAMA_MODEL}'"
    check_tool "msfconsole"      "command -v msfconsole"
    check_tool "njosnari script" "test -f ${INSTALL_DIR}/${SCRIPT_NAME}"
    check_tool "njosnari cmd"    "test -f /usr/local/bin/njosnari"

    echo
    if $all_ok; then
        ok "All checks passed."
    else
        warn "Some optional components had warnings — see ${LOG_FILE} for details."
    fi
}

# ── Completion Banner ─────────────────────────────────────────────────────────
completion_banner() {
    echo -e "\n${BLOOD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${GREEN}  ⚔  Njosnari installation complete.  ⚔${RESET}"
    echo -e "${BLOOD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo
    echo -e "  ${CYAN}Run:${RESET}     ${BOLD}njosnari${RESET}   (or)   ${BOLD}sudo njosnari${RESET}"
    echo -e "  ${CYAN}Direct:${RESET}  ${BOLD}sudo ${VENV_DIR}/bin/python3 ${INSTALL_DIR}/${SCRIPT_NAME}${RESET}"
    echo -e "  ${CYAN}Log:${RESET}     ${LOG_FILE}"
    echo -e "  ${CYAN}LLM:${RESET}     ollama run ${OLLAMA_MODEL}"
    echo
    echo -e "  ${DIM}\"The ravens fly. The raid begins.\"  — @s.k.7.l.d${RESET}"
    echo
}

# ── Entrypoint ────────────────────────────────────────────────────────────────
main() {
    print_banner
    preflight
    system_update
    install_system_deps
    install_metasploit
    install_ollama
    setup_python_env
    deploy_script
    post_upgrade
    verify_install
    completion_banner
}

main "$@"

set -euo pipefail

# ── Colour palette ────────────────────────────────────────────────────────────
RED='\033[0;31m'
BLOOD='\033[1;31m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Constants ─────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/njosnari"
VENV_DIR="${INSTALL_DIR}/venv"
SCRIPT_NAME="njosnari.py"
OLLAMA_MODEL="qwen2.5:3b"
LOG_FILE="/tmp/njosnari_install.log"
ARCH=$(uname -m)

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
    echo -e "${BLOOD}"
    cat << 'EOF'
  ██╗   ██╗██╗██╗  ██╗██╗███╗   ██╗ ██████╗ ██████╗
  ██║   ██║██║██║ ██╔╝██║████╗  ██║██╔════╝ ╚════██╗
  ██║   ██║██║█████╔╝ ██║██╔██╗ ██║██║  ███╗ █████╔╝
  ╚██╗ ██╔╝██║██╔═██╗ ██║██║╚██╗██║██║   ██║ ╚═══██╗
   ╚████╔╝ ██║██║  ██╗██║██║ ╚████║╚██████╔╝██████╔╝
    ╚═══╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝

          ⚔  N J Ó S N A R I  —  T H E  R E C O N  V I K I N G  ⚔
              Installer  |  @s.k.7.l.d  |  SK7LD Security Tools
EOF
    echo -e "${RESET}"
}

# ── Helpers ───────────────────────────────────────────────────────────────────
log()     { echo -e "${DIM}[$(date '+%H:%M:%S')]${RESET} $*" | tee -a "$LOG_FILE"; }
info()    { echo -e "${CYAN}[*]${RESET} $*" | tee -a "$LOG_FILE"; }
ok()      { echo -e "${GREEN}[✓]${RESET} $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$LOG_FILE"; }
err()     { echo -e "${BLOOD}[✗]${RESET} $*" | tee -a "$LOG_FILE"; }
section() { echo -e "\n${BOLD}${RED}━━━  $*  ━━━${RESET}\n" | tee -a "$LOG_FILE"; }
die()     { err "$*"; exit 1; }

cmd_exists() { command -v "$1" &>/dev/null; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "Njosnari installer must run as root.  Use: sudo bash install.sh"
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO="${ID}"
        DISTRO_VERSION="${VERSION_ID:-unknown}"
    else
        DISTRO="unknown"
        DISTRO_VERSION="unknown"
    fi

    case "$DISTRO" in
        kali|debian|ubuntu|parrot|linuxmint) : ;;
        *)
            warn "Detected distro '${DISTRO}' — this installer targets Debian/Kali/Ubuntu."
            warn "Proceeding anyway; some packages may differ."
            ;;
    esac
    info "Distro: ${DISTRO} ${DISTRO_VERSION} | Arch: ${ARCH}"
}

# ── Phase 0: Pre-flight ───────────────────────────────────────────────────────
preflight() {
    section "Phase 0 — Pre-flight Checks"
    require_root
    detect_distro

    info "Initialising log → ${LOG_FILE}"
    : > "$LOG_FILE"

    # Check internet connectivity
    if ! ping -c1 -W3 8.8.8.8 &>/dev/null; then
        warn "No internet detected — some downloads may fail."
    else
        ok "Network connectivity confirmed."
    fi
}

# ── Phase 1: System Update ────────────────────────────────────────────────────
system_update() {
    section "Phase 1 — System Update"
    info "Running apt update..."
    apt-get update -qq 2>&1 | tee -a "$LOG_FILE"
    ok "apt update complete."
}

# ── Phase 2: System Dependencies ─────────────────────────────────────────────
install_system_deps() {
    section "Phase 2 — System Dependencies"

    local pkgs=(
        # Core build tools
        build-essential git curl wget unzip tar ca-certificates gnupg lsb-release
        # Python
        python3 python3-pip python3-venv python3-dev
        # Network recon tools
        nmap dnsutils whois netcat-traditional openssl
        # SSL/TLS tools
        sslscan
        # Port scanning
        masscan
        # DNS/subdomain
        dnsrecon
        # WAF & web tools
        nikto dirb gobuster
        # Metasploit dependencies
        postgresql libpq-dev ruby ruby-dev ruby-bundler
        # Misc utilities
        jq htop tmux net-tools iputils-ping procps
    )

    local to_install=()
    for pkg in "${pkgs[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null 2>&1; then
            to_install+=("$pkg")
        else
            log "  already installed: ${pkg}"
        fi
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        info "Installing ${#to_install[@]} package(s): ${to_install[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            "${to_install[@]}" 2>&1 | tee -a "$LOG_FILE"
        ok "System packages installed."
    else
        ok "All system packages already present."
    fi
}

# ── Phase 3: Metasploit Framework ────────────────────────────────────────────
install_metasploit() {
    section "Phase 3 — Metasploit Framework"

    if cmd_exists msfconsole; then
        ok "Metasploit Framework already installed at $(command -v msfconsole)."
        return 0
    fi

    # Kali ships Metasploit natively
    if [[ "$DISTRO" == "kali" ]]; then
        info "Kali detected — installing metasploit-framework via apt..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y metasploit-framework 2>&1 | tee -a "$LOG_FILE"
    else
        # Official Rapid7 installer for Ubuntu/Debian
        info "Downloading Rapid7 Metasploit installer..."
        local msf_installer="/tmp/msfinstall.sh"
        curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
            -o "$msf_installer" 2>&1 | tee -a "$LOG_FILE" \
        || {
            # Fallback: apt package on Debian/Ubuntu
            warn "Rapid7 installer download failed. Attempting apt fallback..."
            curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key \
                | gpg --dearmor > /usr/share/keyrings/metasploit-framework.gpg
            echo "deb [signed-by=/usr/share/keyrings/metasploit-framework.gpg] \
https://apt.metasploit.com/ $(lsb_release -cs) main" \
                > /etc/apt/sources.list.d/metasploit-framework.list
            apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y metasploit-framework
            msf_installer=""
        }
        if [[ -n "${msf_installer:-}" && -f "$msf_installer" ]]; then
            chmod +x "$msf_installer"
            bash "$msf_installer" 2>&1 | tee -a "$LOG_FILE"
        fi
    fi

    if cmd_exists msfconsole; then
        ok "Metasploit Framework installed successfully."
    else
        warn "msfconsole not found in PATH after install — check ${LOG_FILE}."
    fi

    # Initialise the MSF database (PostgreSQL)
    info "Initialising Metasploit PostgreSQL database..."
    systemctl enable postgresql --quiet 2>/dev/null || true
    systemctl start postgresql --quiet 2>/dev/null || true
    if cmd_exists msfdb; then
        msfdb init 2>&1 | tee -a "$LOG_FILE" || warn "msfdb init returned non-zero (may already be initialised)."
        ok "Metasploit database ready."
    fi
}

# ── Phase 4: Ollama LLM Engine ───────────────────────────────────────────────
install_ollama() {
    section "Phase 4 — Ollama LLM Engine"

    if cmd_exists ollama; then
        ok "Ollama already installed at $(command -v ollama)."
    else
        info "Fetching official Ollama install script..."
        curl -fsSL https://ollama.com/install.sh | bash 2>&1 | tee -a "$LOG_FILE"

        if cmd_exists ollama; then
            ok "Ollama installed successfully."
        else
            die "Ollama installation failed. Check ${LOG_FILE} for details."
        fi
    fi

    # Start Ollama daemon if not running
    info "Starting Ollama daemon..."
    if systemctl is-active --quiet ollama 2>/dev/null; then
        ok "Ollama service already running."
    else
        # Try systemd first, fall back to background process
        systemctl enable ollama --quiet 2>/dev/null && systemctl start ollama --quiet 2>/dev/null \
        || {
            warn "systemd start failed — launching ollama serve in background..."
            nohup ollama serve >> "$LOG_FILE" 2>&1 &
            sleep 3
        }
    fi

    # Wait for Ollama API to be reachable (max 30 s)
    info "Waiting for Ollama API at http://localhost:11434 ..."
    local retries=30
    until curl -sf http://localhost:11434/ &>/dev/null || [[ $retries -eq 0 ]]; do
        sleep 1
        (( retries-- ))
    done

    if [[ $retries -eq 0 ]]; then
        warn "Ollama API did not respond in time — model pull may fail."
    else
        ok "Ollama API is live."
    fi

    # Pull the lightweight model
    pull_ollama_model
}

pull_ollama_model() {
    info "Checking for model: ${OLLAMA_MODEL} ..."

    # Check if model already present
    if ollama list 2>/dev/null | grep -q "${OLLAMA_MODEL}"; then
        ok "Model '${OLLAMA_MODEL}' already pulled."
        return 0
    fi

    info "Pulling '${OLLAMA_MODEL}' — this may take a few minutes (~2 GB)..."
    if ollama pull "${OLLAMA_MODEL}" 2>&1 | tee -a "$LOG_FILE"; then
        ok "Model '${OLLAMA_MODEL}' ready."
    else
        warn "Model pull returned non-zero — verify manually with: ollama pull ${OLLAMA_MODEL}"
    fi
}

# ── Phase 5: Python Environment ───────────────────────────────────────────────
setup_python_env() {
    section "Phase 5 — Python Virtual Environment"

    info "Creating install directory: ${INSTALL_DIR}"
    mkdir -p "${INSTALL_DIR}"

    if [[ -d "${VENV_DIR}" ]]; then
        ok "Virtual environment already exists at ${VENV_DIR}."
    else
        info "Creating Python venv..."
        python3 -m venv "${VENV_DIR}" 2>&1 | tee -a "$LOG_FILE"
        ok "Venv created."
    fi

    info "Upgrading pip inside venv..."
    "${VENV_DIR}/bin/pip" install --quiet --upgrade pip 2>&1 | tee -a "$LOG_FILE"

    info "Installing Python dependencies..."
    local py_pkgs=(
        requests
        urllib3
        dnspython
        cryptography
        pyOpenSSL
        colorama
        rich
        python-whois
        tqdm
        aiohttp
        aiofiles
    )

    "${VENV_DIR}/bin/pip" install --quiet "${py_pkgs[@]}" 2>&1 | tee -a "$LOG_FILE"
    ok "Python dependencies installed."
}

# ── Phase 6: Deploy Njosnari Script ──────────────────────────────────────────
deploy_script() {
    section "Phase 6 — Deploy Njosnari"

    local script_src
    script_src="$(dirname "$(realpath "$0")")/${SCRIPT_NAME}"

    if [[ ! -f "$script_src" ]]; then
        warn "${SCRIPT_NAME} not found next to install.sh — skipping script copy."
        warn "Place '${SCRIPT_NAME}' in ${INSTALL_DIR} manually."
        return 0
    fi

    cp -f "$script_src" "${INSTALL_DIR}/${SCRIPT_NAME}"
    chmod 750 "${INSTALL_DIR}/${SCRIPT_NAME}"
    ok "Deployed ${SCRIPT_NAME} → ${INSTALL_DIR}/${SCRIPT_NAME}"

    # Create global launcher
    cat > /usr/local/bin/njosnari << LAUNCHER
#!/usr/bin/env bash
# Njosnari global launcher — generated by install.sh
exec "${VENV_DIR}/bin/python3" "${INSTALL_DIR}/${SCRIPT_NAME}" "\$@"
LAUNCHER
    chmod 755 /usr/local/bin/njosnari
    ok "Global launcher created: /usr/local/bin/njosnari"
}

# ── Phase 7: Post-install System Upgrade ──────────────────────────────────────
post_upgrade() {
    section "Phase 7 — Post-Install System Upgrade"
    info "Running apt upgrade -y (this may take a while)..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
        2>&1 | tee -a "$LOG_FILE"
    ok "System fully upgraded."

    info "Cleaning apt cache..."
    apt-get autoremove -y --purge -qq 2>&1 | tee -a "$LOG_FILE"
    apt-get clean -qq 2>&1 | tee -a "$LOG_FILE"
    ok "Cache cleaned."
}

# ── Phase 8: Verify Installation ─────────────────────────────────────────────
verify_install() {
    section "Phase 8 — Verification"

    local all_ok=true
    check_tool() {
        local name="$1"
        local check_cmd="$2"
        if eval "$check_cmd" &>/dev/null; then
            ok "  ${name}"
        else
            warn "  ${name} — NOT FOUND (non-fatal)"
            all_ok=false
        fi
    }

    check_tool "python3"         "command -v python3"
    check_tool "nmap"            "command -v nmap"
    check_tool "sslscan"         "command -v sslscan"
    check_tool "dnsrecon"        "command -v dnsrecon"
    check_tool "nikto"           "command -v nikto"
    check_tool "gobuster"        "command -v gobuster"
    check_tool "ollama"          "command -v ollama"
    check_tool "ollama daemon"   "curl -sf http://localhost:11434/"
    check_tool "model: ${OLLAMA_MODEL}" "ollama list | grep -q '${OLLAMA_MODEL}'"
    check_tool "msfconsole"      "command -v msfconsole"
    check_tool "njosnari script" "test -f ${INSTALL_DIR}/${SCRIPT_NAME}"
    check_tool "njosnari cmd"    "test -f /usr/local/bin/njosnari"

    echo
    if $all_ok; then
        ok "All checks passed."
    else
        warn "Some optional components had warnings — see ${LOG_FILE} for details."
    fi
}

# ── Completion Banner ─────────────────────────────────────────────────────────
completion_banner() {
    echo -e "\n${BLOOD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${GREEN}  ⚔  Njosnari installation complete.  ⚔${RESET}"
    echo -e "${BLOOD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo
    echo -e "  ${CYAN}Run:${RESET}     ${BOLD}njosnari${RESET}   (or)   ${BOLD}sudo njosnari${RESET}"
    echo -e "  ${CYAN}Direct:${RESET}  ${BOLD}sudo ${VENV_DIR}/bin/python3 ${INSTALL_DIR}/${SCRIPT_NAME}${RESET}"
    echo -e "  ${CYAN}Log:${RESET}     ${LOG_FILE}"
    echo -e "  ${CYAN}LLM:${RESET}     ollama run ${OLLAMA_MODEL}"
    echo
    echo -e "  ${DIM}\"The ravens fly. The raid begins.\"  — @s.k.7.l.d${RESET}"
    echo
}

# ── Entrypoint ────────────────────────────────────────────────────────────────
main() {
    print_banner
    preflight
    system_update
    install_system_deps
    install_metasploit
    install_ollama
    setup_python_env
    deploy_script
    post_upgrade
    verify_install
    completion_banner
}

main "$@"
