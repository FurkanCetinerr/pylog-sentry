PyLogSentry - Simple Log Analysis Tool
PyLogSentry is a simple Python-based command-line tool developed for analyzing Apache web server access.log files. It acts as a pre-warning system for cybersecurity analysts by detecting anomalous and suspicious activity through configurable rules.

This project was created to demonstrate basic log parsing, rule-based analysis, and reporting capabilities. It is a practical portfolio project for internships and entry-level (L1) cybersecurity positions.

🚀 Features
Rule-Based Analysis: Flexible rules that can be easily managed via the config.json file.

Log Parsing: Converting standard Apache log format into structured data using Regular Expressions (Regex).

Anomaly Detection:

Detecting IP addresses that make a high number of requests exceeding a certain threshold.

Detecting IP addresses that generate a high number of error codes (e.g., 404, 403), which could indicate brute-force or directory scanning.

Detecting suspicious URL patterns associated with known vulnerability scanning tools or attack vectors (e.g., wp-admin, etc/passwd, sqlmap, etc.).

Reporting: Printing detected alerts to the console and logging them to the alerts.log file with a timestamp.

📂 Project Structure
pylog-sentry/
├── .gitignore          # Specifies files not to be pushed to Git
├── README.md           # This file
├── config.json         # Analysis rules and settings
├── analyzer.py         # Main analysis script
└── sample_logs/
    └── access.log      # Sample log file for analysis

🛠️ Installation and Run
Follow the steps below to run the project on your local machine.

1. Clone the Project:

git clone https://github.com/FurkanCetinerr/pylog-sentry.git
cd pylog-sentry

2. Required Libraries:

The project has no dependencies other than Python's standard libraries. No additional installation is required.

3. Run the Analysis Tool:

You can start the analysis script with the following command:

python analyzer.py

When you run the script, it will analyze the log file specified in the config.json file and print its findings. If any alerts are found, they will also be added to the alerts.log file.

⚙️ Configuration (config.json)
You can customize the behavior of the analysis tool by editing the config.json file.

{
  "log_file_path": "sample_logs/access.log",
  "alerts_log_path": "alerts.log",
  "rules": {
    "high_request_threshold": 5,
    "error_code_threshold": 3,
    "suspicious_url_patterns": [
      "wp-login",
      "wp-admin",
      "../../",
      "etc/passwd",
      ".env",
      "sqlmap",
      "shell.php",
      "cmd.aspx"
    ],
    "monitored_error_codes": [403, 404]
  }
}

log_file_path: Path to the log file to analyze.

alerts_log_path: Path to the file where alerts will be saved.

high_request_threshold: The minimum number of requests required for an IP to be considered to have made "too many" requests.

error_code_threshold: The minimum number of times an IP is considered to have received a particular error code "too many times."

suspicious_url_patterns: Text patterns within the URL that are searched for and considered suspicious.

monitored_error_codes: HTTP error codes to be counted and included in the error_code_threshold rule.

📊 Sample Output
Console Output:

==================================================
PyLogSentry - Starting Log Analysis Tool...
==================================================
[INFO] The configuration file was successfully uploaded.

[INFO] Log file to be analyzed: sample_logs/access.log

[INFO] Analysis is starting...

[INFO] Analysis is complete.

--- Detected Warnings ---
[WARNING - Suspicious URL] IP: 45.12.6.188, URL: /wp-login.php, Detected Pattern: 'wp-login'
[WARNING - Suspicious URL] IP: 45.12.6.188, URL: /wp-admin/, Detected Pattern: 'wp-admin'
[WARNING - Suspicious URL] IP: 45.12.6.188, URL: /.env, Detected Pattern: '.env'
[WARNING - Suspicious URL] IP: 45.12.6.188, URL: /index.php?page=../../../../etc/passwd, Detected Pattern: '../../'
[WARNING - Suspicious URL] IP: 45.12.6.188, URL: /shell.php, Detected Pattern: 'shell.php'
[WARNING - Suspicious URL] IP: 45.12.6.188, URL: /cmd.aspx, Detected Pattern: 'cmd.aspx'
[WARNING - High Request Count] IP: 45.12.6.188, Request Count: 6 (Threshold: 5)
[WARNING - High Number of Error Codes] IP: 45.12.6.188, Error Code: 404, Number: 5 (Threshold: 3)
--- End of Warnings ---

[INFO] 8 warnings were successfully written to the 'alerts.log' file.

A total of 20 lines of log were examined, and 8 warnings were found.
===================================================

Alerts.log File Contents:

--- Analysis Report: 2023-10-27 15:30:00 ---
[WARNING - Suspicious URL] IP: 45.12.6.188, URL: /wp-login.php, Detected Pattern: 'wp-login'
...
[WARNING - Too Many Error Codes] IP: 45.12.6.188, Error Code: 404, Count: 5 (Threshold: 3)
