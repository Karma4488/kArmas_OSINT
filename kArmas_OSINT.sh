#!/data/data/com.termux/files/usr/bin/bash

# kArmas_OSINT - Advanced OSINT Reconnaissance Tool
# Version: 1.0
# Platform: Termux Android
# Purpose: Comprehensive passive and active reconnaissance
# Made in l0ve bY kArmasec

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BANNER="
╔═══════════════════════════════════════════════════╗
║         kArmas_OSINT v1.0                         ║
║    Advanced Reconnaissance & OSINT Suite          ║
║         Passive + Active Intelligence   
║         Made in l0v3 bY kArmasec
╚═══════════════════════════════════════════════════╝
"

echo -e "${GREEN}${BANNER}${NC}"

# Check for target argument
if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage: ./kArmas_OSINT.sh <target> [options]${NC}"
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  -o <output_dir>  : Specify output directory (default: osint_results)"
    echo -e "  -p               : Passive mode only (no active scanning)"
    echo -e "  -a               : Active mode (includes port scanning)"
    echo -e "  -f               : Full mode (all modules)"
    echo -e "\n${YELLOW}Example:${NC}"
    echo -e "  ./kArmas_OSINT.sh example.com -f -o results"
    exit 1
fi

TARGET=$1
OUTPUT_DIR="osint_results_${TARGET}_$(date +%Y%m%d_%H%M%S)"
MODE="basic"

# Parse arguments
shift
while getopts "o:paf" opt; do
    case $opt in
        o) OUTPUT_DIR="$OPTARG" ;;
        p) MODE="passive" ;;
        a) MODE="active" ;;
        f) MODE="full" ;;
        *) echo "Invalid option"; exit 1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
REPORT="$OUTPUT_DIR/FINAL_REPORT.txt"

echo -e "${GREEN}[+] Target: ${TARGET}${NC}"
echo -e "${GREEN}[+] Mode: ${MODE}${NC}"
echo -e "${GREEN}[+] Output Directory: ${OUTPUT_DIR}${NC}"
echo -e "${BLUE}[*] Starting reconnaissance...${NC}\n"

# Initialize report
echo "========================================" > "$REPORT"
echo "kArmas_OSINT - Reconnaissance Report" >> "$REPORT"
echo "Target: $TARGET" >> "$REPORT"
echo "Date: $(date)" >> "$REPORT"
echo "Mode: $MODE" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "" >> "$REPORT"

# ========================================
# MODULE 1: DNS Enumeration
# ========================================
echo -e "${YELLOW}[Module 1] DNS Enumeration${NC}"
echo "[Module 1] DNS Enumeration" >> "$REPORT"
echo "-----------------------------------" >> "$REPORT"

echo -e "${BLUE}  [*] Resolving DNS records...${NC}"
host "$TARGET" > "$OUTPUT_DIR/dns_basic.txt" 2>&1
nslookup "$TARGET" >> "$OUTPUT_DIR/dns_basic.txt" 2>&1
dig "$TARGET" ANY +noall +answer > "$OUTPUT_DIR/dns_dig.txt" 2>&1
dig "$TARGET" A +short >> "$REPORT"
dig "$TARGET" AAAA +short >> "$REPORT"
dig "$TARGET" MX +short >> "$REPORT"
dig "$TARGET" NS +short >> "$REPORT"
dig "$TARGET" TXT +short >> "$REPORT"

echo -e "${GREEN}  [✓] DNS records saved${NC}"
echo "" >> "$REPORT"

# ========================================
# MODULE 2: WHOIS Information
# ========================================
echo -e "${YELLOW}[Module 2] WHOIS Lookup${NC}"
echo "[Module 2] WHOIS Information" >> "$REPORT"
echo "-----------------------------------" >> "$REPORT"

whois "$TARGET" > "$OUTPUT_DIR/whois.txt" 2>&1
cat "$OUTPUT_DIR/whois.txt" | grep -E "(Registrar|Creation Date|Expiry|Name Server|Organization)" >> "$REPORT"
echo -e "${GREEN}  [✓] WHOIS data saved${NC}"
echo "" >> "$REPORT"

# ========================================
# MODULE 3: Subdomain Enumeration
# ========================================
if [ "$MODE" != "passive" ]; then
    echo -e "${YELLOW}[Module 3] Subdomain Enumeration${NC}"
    echo "[Module 3] Discovered Subdomains" >> "$REPORT"
    echo "-----------------------------------" >> "$REPORT"
    
    # Common subdomain wordlist
    SUBDOMAINS=("www" "mail" "ftp" "admin" "webmail" "smtp" "pop" "ns1" "ns2" "cpanel" "whm" "dns" "dns1" "dns2" "test" "dev" "staging" "api" "blog" "shop" "store" "forum" "support" "help" "portal" "vpn" "remote" "cloud" "mx" "mx1" "mx2")
    
    echo -e "${BLUE}  [*] Checking common subdomains...${NC}"
    for sub in "${SUBDOMAINS[@]}"; do
        result=$(host "${sub}.${TARGET}" 2>&1)
        if [[ $result != *"not found"* ]] && [[ $result != *"NXDOMAIN"* ]]; then
            echo "${sub}.${TARGET}" | tee -a "$OUTPUT_DIR/subdomains.txt" >> "$REPORT"
        fi
    done
    
    echo -e "${GREEN}  [✓] Subdomain enumeration complete${NC}"
    echo "" >> "$REPORT"
fi

# ========================================
# MODULE 4: Port Scanning
# ========================================
if [ "$MODE" = "active" ] || [ "$MODE" = "full" ]; then
    echo -e "${YELLOW}[Module 4] Port Scanning${NC}"
    echo "[Module 4] Open Ports" >> "$REPORT"
    echo "-----------------------------------" >> "$REPORT"
    
    echo -e "${BLUE}  [*] Scanning top ports...${NC}"
    nmap -sS -T4 --top-ports 100 "$TARGET" -oN "$OUTPUT_DIR/nmap_scan.txt" > /dev/null 2>&1
    cat "$OUTPUT_DIR/nmap_scan.txt" | grep "open" >> "$REPORT"
    
    echo -e "${BLUE}  [*] Service detection...${NC}"
    nmap -sV --top-ports 20 "$TARGET" -oN "$OUTPUT_DIR/nmap_services.txt" > /dev/null 2>&1
    
    echo -e "${GREEN}  [✓] Port scanning complete${NC}"
    echo "" >> "$REPORT"
fi

# ========================================
# MODULE 5: Web Reconnaissance
# ========================================
echo -e "${YELLOW}[Module 5] Web Reconnaissance${NC}"
echo "[Module 5] Web Information" >> "$REPORT"
echo "-----------------------------------" >> "$REPORT"

echo -e "${BLUE}  [*] Fetching HTTP headers...${NC}"
curl -I "http://${TARGET}" > "$OUTPUT_DIR/http_headers.txt" 2>&1
curl -I "https://${TARGET}" >> "$OUTPUT_DIR/http_headers.txt" 2>&1
cat "$OUTPUT_DIR/http_headers.txt" | grep -E "(Server|X-Powered-By|Content-Type)" >> "$REPORT"

echo -e "${BLUE}  [*] Checking robots.txt...${NC}"
curl -s "http://${TARGET}/robots.txt" > "$OUTPUT_DIR/robots.txt" 2>&1
if [ -s "$OUTPUT_DIR/robots.txt" ]; then
    echo "robots.txt found" >> "$REPORT"
fi

echo -e "${GREEN}  [✓] Web reconnaissance complete${NC}"
echo "" >> "$REPORT"

# ========================================
# MODULE 6: SSL/TLS Information
# ========================================
if [ "$MODE" = "full" ]; then
    echo -e "${YELLOW}[Module 6] SSL/TLS Analysis${NC}"
    echo "[Module 6] SSL/TLS Information" >> "$REPORT"
    echo "-----------------------------------" >> "$REPORT"
    
    echo -e "${BLUE}  [*] Checking SSL certificate...${NC}"
    echo | openssl s_client -connect "${TARGET}:443" -servername "${TARGET}" 2>/dev/null | openssl x509 -noout -text > "$OUTPUT_DIR/ssl_cert.txt" 2>&1
    cat "$OUTPUT_DIR/ssl_cert.txt" | grep -E "(Issuer|Subject|Not Before|Not After)" >> "$REPORT"
    
    echo -e "${GREEN}  [✓] SSL analysis complete${NC}"
    echo "" >> "$REPORT"
fi

# ========================================
# MODULE 7: Email Harvesting
# ========================================
if [ "$MODE" = "full" ]; then
    echo -e "${YELLOW}[Module 7] Email Harvesting${NC}"
    echo "[Module 7] Discovered Emails" >> "$REPORT"
    echo "-----------------------------------" >> "$REPORT"
    
    echo -e "${BLUE}  [*] Searching for email addresses...${NC}"
    curl -s "http://${TARGET}" | grep -Eo "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}" | sort -u > "$OUTPUT_DIR/emails.txt" 2>&1
    cat "$OUTPUT_DIR/emails.txt" >> "$REPORT"
    
    echo -e "${GREEN}  [✓] Email harvesting complete${NC}"
    echo "" >> "$REPORT"
fi

# ========================================
# MODULE 8: Technology Detection
# ========================================
echo -e "${YELLOW}[Module 8] Technology Fingerprinting${NC}"
echo "[Module 8] Detected Technologies" >> "$REPORT"
echo "-----------------------------------" >> "$REPORT"

echo -e "${BLUE}  [*] Detecting web technologies...${NC}"
curl -s "http://${TARGET}" > "$OUTPUT_DIR/webpage.html"
grep -i "wordpress\|joomla\|drupal\|jquery\|angular\|react\|vue" "$OUTPUT_DIR/webpage.html" | head -5 >> "$REPORT"

echo -e "${GREEN}  [✓] Technology detection complete${NC}"
echo "" >> "$REPORT"

# ========================================
# FINAL REPORT GENERATION
# ========================================
echo "" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "Scan completed: $(date)" >> "$REPORT"
echo "All files saved to: $OUTPUT_DIR" >> "$REPORT"
echo "========================================" >> "$REPORT"

echo -e "\n${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           RECONNAISSANCE COMPLETE                 ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
echo -e "${YELLOW}[+] Report saved to: ${REPORT}${NC}"
echo -e "${YELLOW}[+] All files in: ${OUTPUT_DIR}${NC}"
echo -e "${BLUE}[*] Files generated:${NC}"
ls -lh "$OUTPUT_DIR" | awk '{print "    " $9 " (" $5 ")"}'

echo -e "\n${GREEN}[✓] Scan complete! Review the FINAL_REPORT.txt for summary.${NC}"
