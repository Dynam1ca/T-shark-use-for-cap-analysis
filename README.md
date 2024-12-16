# T-shark-use-for-cap-analysis


Documentation for Bash Script: Pcap Analysis Using T-Shark
Purpose

This Bash script, Pcap_analysis_caplate.sh, automates packet capture analysis with T-Shark to swiftly identify and document suspicious network activity. This tool is integral for security professionals who require detailed insights into traffic patterns and potential security threats within network environments.

Functionality

Automated Analysis: Processes pcap files to extract key traffic details, such as source and destination IPs, protocols, and signs of potential threats.
Custom Filters: Allows the application of specific T-Shark filters to isolate or highlight certain traffic, aiding in targeted analysis.
Efficient Reporting: Generates structured reports that summarize the findings, providing a valuable tool for security audits and investigative tasks.
Installation Instructions

Prerequisites:
A Linux-based operating system with administrative privileges.
T-Shark, which can be installed on Debian-based systems via sudo apt-get install tshark.
Git, for cloning the repository, installable through sudo apt-get install git.

Installation Steps:
Clone the GitHub repository to obtain the latest version of the script:

git clone https://github.com/Dynam1ca/T-shark-use-for-cap-analysis

Navigate to the script directory:

cd T-shark-use-for-cap-analysis

Change the script permissions to make it executable:

chmod +x Pcap_analysis_caplate.sh

Configuration:
Edit the script to modify or add T-Shark filters based on your analysis 

requirements:
nano Pcap_analysis_caplate.sh ( to replace your VirusTotal API key
Customize parameters or paths as needed to fit your specific network environment.
Running the Script:

Run the script by passing a pcap file as an argument:
./Pcap_analysis_caplate.sh path/to/your/capture_file.pcap
Automate routine analyses by adding the script to your crontab:
crontab -e

# Add to run daily at midnight
0 0 * * * /path/to/T-shark-use-for-cap-analysis/Pcap_analysis_caplate.sh /path/to/capture_file.pcap
