#!/bin/bash

# User Configuration
PCAP_FILE=$1
OUTPUT_DIR="malware_analysis_output"
VT_API_KEY="42d58bab9a247f75ec53d803b4663bf237860e0105ce996d927e50ef7b20ea5a"  # Replace with your VirusTotal API key

# Check for Required Tools
check_dependencies() {
    for cmd in tshark jq curl dialog gnuplot md5 shasum; do
        if ! command -v $cmd &> /dev/null; then
            echo "Error: $cmd is not installed. Please install it using Homebrew."
            exit 1
        fi
    done
}

# Prepare Output Directory
prepare_output() {
    mkdir -p "$OUTPUT_DIR"
    > "$OUTPUT_DIR/full_analysis.txt"
    > "$OUTPUT_DIR/suspicious_activities.txt"
    > "$OUTPUT_DIR/ddos_data.dat"
    mkdir -p "$OUTPUT_DIR/extracted_files"
}

# Log to Full Analysis and Suspicious Activities
log() {
    local message="$1"
    local is_suspicious="$2"
    local reason="$3"
    echo "$message" >> "$OUTPUT_DIR/full_analysis.txt"
    if [[ $is_suspicious == "true" ]]; then
        echo "$message - Reason: $reason" >> "$OUTPUT_DIR/suspicious_activities.txt"
    fi
}

# Protocol Analysis - Analyze All Protocols
protocol_analysis() {
    dialog --infobox "Performing Protocol Analysis..." 3 50
    tshark -r "$PCAP_FILE" -q -z "io,phs" > "$OUTPUT_DIR/protocol_statistics.txt"
    tshark -r "$PCAP_FILE" -q -z "http,tree" > "$OUTPUT_DIR/http_analysis.txt"
    tshark -r "$PCAP_FILE" -q -z "ssl,stat" > "$OUTPUT_DIR/ssl_statistics.txt"

    log "[INFO] Protocol Analysis Complete. Results saved in protocol_statistics.txt." false "N/A"
    dialog --msgbox "Protocol Analysis Complete:\nResults saved in $OUTPUT_DIR/protocol_statistics.txt" 10 50
}

# HTTP Analysis - Identify Websites Affected
http_analysis() {
    dialog --infobox "Analyzing HTTP Requests and Affected Websites..." 3 50
    tshark -r "$PCAP_FILE" -Y "http.request" -T fields -e http.host -e ip.src -e ip.dst > "$OUTPUT_DIR/affected_websites.txt"

    while IFS=$'\t' read -r host src_ip dst_ip; do
        if [[ $host == *"phishing"* || $host == *"malicious"* ]]; then
            log "[ALERT] Affected Website: $host (Source IP: $src_ip, Destination IP: $dst_ip)" true "Hostname contains suspicious keywords."
        else
            log "[INFO] Website: $host accessed by Source IP: $src_ip, Destination IP: $dst_ip" false "Normal traffic."
        fi
    done < "$OUTPUT_DIR/affected_websites.txt"

    dialog --msgbox "HTTP Analysis Complete:\nAffected websites saved in $OUTPUT_DIR/affected_websites.txt" 10 50
}

# File Extraction and Deep Analysis
file_extraction() {
    dialog --infobox "Extracting Files for Deep Analysis..." 3 50
    tshark -r "$PCAP_FILE" --export-objects http,"$OUTPUT_DIR/extracted_files/"

    local file_count=$(ls "$OUTPUT_DIR/extracted_files/" | wc -l)
    log "[INFO] Extracted $file_count files. Saved in extracted_files directory." false "N/A"

    dialog --msgbox "File Extraction Complete:\nExtracted files saved in $OUTPUT_DIR/extracted_files/" 10 50
}

# Hashing and Malware Detection
hash_and_detect() {
    dialog --infobox "Hashing Files and Detecting Malware..." 3 50
    mkdir -p "$OUTPUT_DIR/hashes"
    > "$OUTPUT_DIR/hashes/combined_hashes.txt"

    for file in "$OUTPUT_DIR/extracted_files/"*; do
        if [ -f "$file" ]; then
            md5=$(md5 "$file" | awk '{print $4}')
            sha256=$(shasum -a 256 "$file" | awk '{print $1}')
            log "[INFO] File: $(basename "$file"), MD5: $md5, SHA256: $sha256" false "File hashed."

            # Check VirusTotal with hashes
            response=$(curl -s --request GET \
                --url "https://www.virustotal.com/api/v3/files/$sha256" \
                --header "x-apikey: $VT_API_KEY")
            positives=$(echo "$response" | jq '.data.attributes.last_analysis_stats.malicious')

            if [[ $positives -gt 0 ]]; then
                log "[ALERT] Malware detected in file $(basename "$file") (SHA256: $sha256, $positives positives). Folder: $OUTPUT_DIR/extracted_files/" true "VirusTotal reported $positives detections."
                echo "[ALERT] Malware Detected: File $(basename "$file"), SHA256: $sha256, Positives: $positives - Reason: VirusTotal reported $positives detections." >> "$OUTPUT_DIR/suspicious_activities.txt"
            else
                log "[INFO] File $(basename "$file") is clean. Folder: $OUTPUT_DIR/extracted_files/" false "No issues detected by VirusTotal."
            fi
        fi
    done

    dialog --msgbox "Hashing and Malware Detection Complete.\nHashes saved in $OUTPUT_DIR/hashes/combined_hashes.txt" 10 50
}

# Brute Force Detection - Identify Multiple Login Attempts
brute_force_detection() {
    dialog --infobox "Detecting Brute Force Attacks on Network Ports..." 3 50
    tshark -r "$PCAP_FILE" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e ip.src -e tcp.dstport | sort | uniq -c | awk '$1 > 10 {print $0}' > "$OUTPUT_DIR/brute_force_attempts.txt"

    while read -r line; do
        log "[ALERT] Possible Brute Force Detected: $line" true "High SYN attempts to a specific port."
    done < "$OUTPUT_DIR/brute_force_attempts.txt"

    log "[INFO] Brute Force Detection Complete." false "N/A"
    dialog --msgbox "Brute Force Detection Complete:\nResults saved in $OUTPUT_DIR/brute_force_attempts.txt" 10 50
}

# Email Phishing Detection - Analyze Suspicious Email Traffic
email_phishing_detection() {
    dialog --infobox "Analyzing Email Traffic for Phishing Attempts..." 3 50
    tshark -r "$PCAP_FILE" -Y "smtp || pop || imap" -T fields -e ip.src -e ip.dst -e smtp.mail_from -e smtp.rcpt_to -e smtp.subject > "$OUTPUT_DIR/email_analysis.txt"

    while IFS=$'\t' read -r src_ip dst_ip mail_from rcpt_to subject; do
        if [[ $subject == *"urgent"* || $subject == *"update"* || $subject == *"account"* ]]; then
            log "[ALERT] Phishing Email Detected: From: $mail_from, To: $rcpt_to, Subject: $subject" true "Suspicious keywords in email subject."
        fi
    done < "$OUTPUT_DIR/email_analysis.txt"

    log "[INFO] Email Phishing Detection Complete." false "N/A"
    dialog --msgbox "Email Phishing Detection Complete:\nResults saved in $OUTPUT_DIR/email_analysis.txt" 10 50
}

# Traffic and DoS/DDoS Detection with Visualization Data
traffic_and_attack_detection() {
    dialog --infobox "Analyzing Traffic for Attacks (DoS/DDoS, MITM)..." 3 50
    tshark -r "$PCAP_FILE" -z conv,ip > "$OUTPUT_DIR/ip_conversations.txt"

    # Detect DoS/DDoS and log data for visualization
    echo "StartTime EndTime SourceIP DestinationIP TotalPackets TotalBytes Protocol" > "$OUTPUT_DIR/ddos_data.dat"
    tshark -r "$PCAP_FILE" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e frame.len -e ip.len -e _ws.col.Protocol | \
    awk '{
        time=$1; src=$2; dst=$3; len=$4; proto=$5;
        key=src"-"dst"-"proto;
        if (!(key in start)) start[key]=time;
        packets[key]++;
        bytes[key]+=len;
        end[key]=time;
    } END {
        for (k in start) {
            split(k, arr, "-");
            src=arr[1];
            dst=arr[2];
            proto=arr[3];
            printf "%.2f %.2f %s %s %d %d %s\n", start[k], end[k], src, dst, packets[k], bytes[k], proto;
        }
    }' >> "$OUTPUT_DIR/ddos_data.dat"

    # Highlight DoS/DDoS alerts (high packet counts)
    awk '{if ($5 > 10000) print "[ALERT] DoS/DDoS detected: "$3" -> "$4" with "$5" packets and "$6" bytes, Protocol: "$7}' "$OUTPUT_DIR/ddos_data.dat" | while read -r alert; do
        log "$alert" true "High packet count to a single destination IP indicates potential DoS/DDoS."
    done

    log "[INFO] Traffic and Attack Detection Complete." false "N/A"
    dialog --msgbox "Traffic Analysis Complete:\nResults saved in $OUTPUT_DIR" 10 50
}

# Visualize DoS/DDoS Attack and Protocols
visualize_ddos_and_protocols() {
    dialog --infobox "Generating Visualization for DoS/DDoS Attacks and Affected Protocols..." 3 50
    gnuplot <<-EOF
        set terminal png size 1200,600
        set output "$OUTPUT_DIR/ddos_protocol_visualization.png"
        set title "DoS/DDoS Attacks and Affected Protocols"
        set xlabel "Time (seconds)"
        set ylabel "Packets"
        set style data linespoints
        plot "$OUTPUT_DIR/ddos_data.dat" using 1:5 title "Packets Over Time" with lines lw 2, \
             "$OUTPUT_DIR/ddos_data.dat" using 2:5 title "Packets Per Destination" with points, \
             "$OUTPUT_DIR/ddos_data.dat" using 7:5 title "Affected Protocols" with lines lw 2
EOF

    dialog --msgbox "DoS/DDoS and Protocol Visualization saved as $OUTPUT_DIR/ddos_protocol_visualization.png" 10 50
}

# Visualization of Analysis Summary
visualize_results() {
    dialog --infobox "Generating Analysis Summary Visualization..." 3 50
    > "$OUTPUT_DIR/analysis_results.dat"

    echo "Protocol $(wc -l < "$OUTPUT_DIR/protocol_statistics.txt")" >> "$OUTPUT_DIR/analysis_results.dat"
    echo "Sessions $(wc -l < "$OUTPUT_DIR/sessions/tcp_sessions.txt")" >> "$OUTPUT_DIR/analysis_results.dat"
    echo "Files $(ls "$OUTPUT_DIR/extracted_files/" | wc -l)" >> "$OUTPUT_DIR/analysis_results.dat"
    echo "DoS $(wc -l < "$OUTPUT_DIR/dos_ddos_alerts.txt")" >> "$OUTPUT_DIR/analysis_results.dat"
    echo "MITM $(wc -l < "$OUTPUT_DIR/mitm_alerts.txt")" >> "$OUTPUT_DIR/analysis_results.dat"

    gnuplot <<-EOF
        set terminal png size 800,600
        set output "$OUTPUT_DIR/visualization.png"
        set title "Analysis Summary"
        set style data histograms
        set style fill solid border -1
        set boxwidth 0.9
        set xlabel "Analysis Categories"
        set ylabel "Counts"
        set xtics rotate by -45
        plot "$OUTPUT_DIR/analysis_results.dat" using 2:xtic(1) title ""
EOF

    dialog --msgbox "Analysis Summary Visualization saved as $OUTPUT_DIR/visualization.png" 10 50
}

# Main Menu
main_menu() {
    while true; do
        choice=$(dialog --clear --title "Advanced Malware Analysis" \
            --menu "Choose an option:" 20 70 13 \
            1 "Protocol Analysis" \
            2 "HTTP Analysis" \
            3 "Session Reconstruction" \
            4 "File Extraction & Deep Analysis" \
            5 "Traffic and Attack Detection" \
            6 "Malware Detection" \
            7 "Detect Brute Force Attacks" \
            8 "Detect Email Phishing" \
            9 "Visualize DoS/DDoS Attacks and Protocols" \
            10 "Generate Analysis Summary Visualization" \
            11 "View Suspicious Activities" \
            12 "Exit" 2>&1 >/dev/tty)

        case $choice in
            1) protocol_analysis ;;
            2) http_analysis ;;
            3) session_reconstruction ;;
            4) file_extraction ;;
            5) traffic_and_attack_detection ;;
            6) hash_and_detect ;;
            7) brute_force_detection ;;
            8) email_phishing_detection ;;
            9) visualize_ddos_and_protocols ;;
            10) visualize_results ;;
            11) dialog --textbox "$OUTPUT_DIR/suspicious_activities.txt" 20 70 ;;
            12) break ;;
            *) dialog --msgbox "Invalid Option" 10 50 ;;
        esac
    done
}

# Main Execution
main() {
    if [ -z "$PCAP_FILE" ]; then
        echo "Usage: $0 <pcap_file>"
        exit 1
    fi

    if [ ! -f "$PCAP_FILE" ]; then
        dialog --msgbox "Error: PCAP file not found." 10 50
        exit 1
    fi

    check_dependencies
    prepare_output
    main_menu
}

main
