#!/usr/bin/bash

# Title and welcome message
echo " _____  _____  _____  _____  _____  _____  ___  _____  _____ "
echo "/   __\/  _  \/  _  \/   __\/  _  \/  ___>/___\/     \/  _  \ "
echo "|   __||  |  ||  _  <|   __||  |  ||___  ||   ||  |--||  _  |"
echo "\__/   \_____/\__|\_/\_____/\__|__/<_____/\___/\_____/\__|__/"

sleep 1

echo "========================================="
echo "       Welcome to Forensica Toolkit      "
echo "      Forensic Analysis and Security     "
echo "========================================="

sleep 2

# Default settings
LOG_FILES=("/var/log/auth.log" "/var/log/syslog" "/var/log/dmesg")
PATTERNS=("Failed password" "error" "segfault" "unauthorized access")
THRESHOLD=70
ANALYSIS_FILE=""

# Function to display help
show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Memory Forensics:
  --mem
      Analyzes memory usage and identifies processes exceeding a specified memory threshold.
      By default, the threshold is set to 50 MB. Modify the THRESHOLD variable in the script as needed.

  -t [THRESHOLD (MB)]
     Specifies the threshold in MB's


Log File Analysis:
  --log
      Runs the log analysis using default developer-provided log files and patterns.

  -l [FILE|LOGFILE]
      Runs the log analysis using log files specified by the user.
      If a file is provided, it should contain paths to log files, one per line.
      If a single log file path is provided directly, that log file will be used for analysis.

  -p [PATTERN|FILE]
      Specifies patterns to search for in the log files.
      You can provide patterns directly or specify a file containing patterns, one per line.

Process Anomaly Detection:
  --anm
      Detects suspicious processes based on CPU usage and baseline process list.

  -tc [THRESHOLD]
      Set a custom CPU usage threshold for anomaly detection.

  -b [BASELINE|FILE]
      Specifies a baseline process list either directly or through a file.

Common Options:
  -h, --help
      Show this help message and exit.
EOF
}

# Function for Process Anomaly Detection
process_anomaly_detection() {
    local BASELINE_PROCESSES=("sshd" "bash" "systemd" "nginx")
    local THRESHOLD_CPU=80

    while getopts ":tc:b:" opt; do
        case $opt in
            t|c)
                THRESHOLD_CPU=$OPTARG
                ;;
            b)
                if [ -f "$OPTARG" ]; then
                    mapfile -t BASELINE_PROCESSES < "$OPTARG"
                else
                    IFS=',' read -r -a BASELINE_PROCESSES <<< "$OPTARG"
                fi
                ;;
            \?)
                echo "Invalid option: -$OPTARG" >&2
                return 1
                ;;
            :)
                echo "Option -$OPTARG requires an argument." >&2
                return 1
                ;;
        esac
    done
    shift $((OPTIND - 1))

    ANALYSIS_FILE="process_anomaly_report.txt"
    echo "Process Anomaly Report" > $ANALYSIS_FILE
    echo "Date: $(date)" >> $ANALYSIS_FILE
    echo "---------------------------------" >> $ANALYSIS_FILE

    ps aux --sort=-%cpu | while read -r line; do
        PROCESS_NAME=$(echo $line | awk '{print $11}')
        CPU_USAGE=$(echo $line | awk '{print $3}')

        if [[ ! " ${BASELINE_PROCESSES[@]} " =~ " ${PROCESS_NAME} " ]]; then
            echo "Suspicious process detected: $PROCESS_NAME" >> $ANALYSIS_FILE
            echo "CPU Usage: $CPU_USAGE%" >> $ANALYSIS_FILE

            if (( $(echo "$CPU_USAGE > $THRESHOLD_CPU" | bc -l) )); then
                echo "High CPU usage detected: $PROCESS_NAME ($CPU_USAGE%)" >> $ANALYSIS_FILE
            fi

            echo "---------------------------------" >> $ANALYSIS_FILE
        fi
    done

    echo "Process anomaly detection completed. Report saved to $ANALYSIS_FILE."
}

# Function for Memory Forensics
memory_forensics() {
    echo "Running Memory Forensics..."
    sleep 2

    local total_mem_mb=$(grep MemTotal /proc/meminfo | awk '{print $2/1024}')
    echo "Total Memory: ${total_mem_mb}MB"

    ANALYSIS_FILE="memory_usage.txt"
    echo "Memory usage analysis:" > $ANALYSIS_FILE
    echo "Total Memory: ${total_mem_mb}MB" >> $ANALYSIS_FILE
    echo "Processes exceeding threshold of ${THRESHOLD}MB:" >> $ANALYSIS_FILE

    ps aux --sort=-%mem | awk -v threshold=$THRESHOLD '
    NR>1 {
        mem_mb=$6/1024;
        if (mem_mb > threshold) {
            printf "%-10s %-10s %-10s %-10.2f\n", $1, $2, $3, mem_mb
        }
    }
    ' >> $ANALYSIS_FILE

    echo "Memory forensics completed. Analysis saved to $ANALYSIS_FILE."
    sleep 2
    cat "$ANALYSIS_FILE"
}

# Function for Log File Analysis
log_analysis() {
    echo "Running Log File Analysis..."
    sleep 2

    local LOG_FILES_TEMP=("${LOG_FILES[@]}")
    local PATTERNS_TEMP=("${PATTERNS[@]}")

    if [ -n "$USER_LOG_FILES" ]; then
        LOG_FILES_TEMP=()
        while IFS= read -r log_file; do
            LOG_FILES_TEMP+=("$log_file")
        done < "$USER_LOG_FILES"
    fi

    if [ -n "$USER_PATTERNS" ]; then
        PATTERNS_TEMP=()
        while IFS= read -r pattern; do
            PATTERNS_TEMP+=("$pattern")
        done < "$USER_PATTERNS"
    fi

    ANALYSIS_FILE="log_analysis_report.txt"
    echo "Log Analysis Report" > $ANALYSIS_FILE
    echo "Date: $(date)" >> $ANALYSIS_FILE
    echo "---------------------------------" >> $ANALYSIS_FILE

    for LOG_FILE in "${LOG_FILES_TEMP[@]}"; do
        echo "Analyzing $LOG_FILE..." >> $ANALYSIS_FILE
        echo "Extracting logs from last 7 days..." >> $ANALYSIS_FILE
        grep -iE "$(date --date='7 days ago' '+%b %e')" "$LOG_FILE" >> $ANALYSIS_FILE
        echo "---------------------------------" >> $ANALYSIS_FILE

        for PATTERN in "${PATTERNS_TEMP[@]}"; do
            echo "Searching for pattern: $PATTERN" >> $ANALYSIS_FILE
            local MATCHES=$(grep -ic "$PATTERN" "$LOG_FILE")
            if [ $MATCHES -gt 0 ]; then
                echo "Found $MATCHES occurrences of '$PATTERN'" >> $ANALYSIS_FILE
                grep -i "$PATTERN" "$LOG_FILE" >> $ANALYSIS_FILE
                echo "---------------------------------" >> $ANALYSIS_FILE

                if [[ "$PATTERN" == *"unauthorized access"* || "$PATTERN" == *"segfault"* ]]; then
                    echo "Critical pattern detected: $PATTERN. Sending alert..." >> $ANALYSIS_FILE
                    echo "Critical alert: $PATTERN detected in $LOG_FILE" | mail -s "Log Analysis Alert" "$EMAIL_ALERT"
                fi
            else
                echo "No occurrences of '$PATTERN' found." >> $ANALYSIS_FILE
            fi
        done
    done

    echo "Summary of Suspicious Activity:" >> $ANALYSIS_FILE
    for PATTERN in "${PATTERNS_TEMP[@]}"; do
        echo "Pattern: $PATTERN" >> $ANALYSIS_FILE
        grep -i "$PATTERN" "${LOG_FILES_TEMP[@]}" | awk '{print $1, $2, $3, $11}' | sort | uniq -c | sort -nr >> $ANALYSIS_FILE
    done

    echo "Log file analysis completed. Analysis saved to $ANALYSIS_FILE."
}

# Function to parse command-line options
parse_options() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --mem)
                memory_forensics
                exit 0
                ;;
            --log)
                log_analysis
                exit 0
                ;;
            --anm)
                shift
                process_anomaly_detection "$@"
                exit 0
                ;;
            -t)
                THRESHOLD="$2"
                shift 2
                ;;
            -l)
                USER_LOG_FILES="$2"
                shift 2
                ;;
            -p)
                USER_PATTERNS="$2"
                shift 2
                ;;
            -tc)
                CPU_THRESHOLD="$2"
                shift 2
                ;;
            -b)
                USER_BASELINE="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Parse command-line arguments
parse_options "$@"
