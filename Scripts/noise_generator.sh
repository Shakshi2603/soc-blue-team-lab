#!/bin/bash
# ==============================================================================
# File Identity: noise-generator.sh
# Objective: Generate realistic multi-tier background network telemetry noise 
# Target Profile: Ubuntu Web Node (192.168.10.30)
# ==============================================================================

TARGET_IP="192.168.10.30"
WORDLIST="/usr/share/wordlists/dirb/common.txt"
USERLIST=("finance_mgr" "hr_assist" "dev_ops_user" "backup_agent" "intern_01" "sysadmin_test")

echo "[+] Starting Enterprise Network Noise Simulation Pipeline..."
echo "[+] Target Ingestion Vector: ${TARGET_IP}"
echo "[+] Injecting continuous background logs... Press [CTRL+C] to terminate."

while true; do
    # --- TIER 1: WEB CORE APPLICATION APP NOISE ---
    # Pick a random string asset from the local web application wordlist map 
    RANDOM_PATH=$(shuf -n1 "$WORDLIST")
    
    # Fire an inbound web traffic hit to simulate normal user requests 
    curl -s -o /dev/null -w "%{http_code}" "http://${TARGET_IP}/${RANDOM_PATH}" > /dev/null
    
    # --- TIER 2: IDENTITY AUTHENTICATION LOG NOISE ---
    # Select a random user profile from the array variable map
    RANDOM_INDEX=$((RANDOM % ${#USERLIST[@]}))
    CHOSEN_USER=${USERLIST[$RANDOM_INDEX]}
    
    # Trigger a brief authentication attempt with an invalid key string to generate non-malicious errors 
    ssh -o ConnectTimeout=2 -o KbdInteractiveAuthentication=no -o PasswordAuthentication=no "${CHOSEN_USER}@${TARGET_IP}" 2>/dev/null
    
    # --- TIER 3: TEMPORAL RANDOMIZATION LAYER ---
    # Sleep for a random interval between 5 and 35 seconds before cycling the operations 
    SLEEP_DURATION=$((RANDOM % 30 + 5)) 
    sleep ${SLEEP_DURATION} 
done
