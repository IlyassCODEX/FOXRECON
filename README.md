# Fox Recon - Smart Reconnaissance Tool


![ChatGPT Image Jun 24, 2025, 07_18_56 PM](https://github.com/user-attachments/assets/69e9525c-ec76-4683-ab25-fd7693d71b39)

Fox Recon is an intelligent web reconnaissance tool designed for security researchers and bug bounty hunters. It automates subdomain discovery and provides AI-powered security analysis to identify high-value targets and potential vulnerabilities.

## Features

- 🚀 **Fast Subdomain Enumeration** - Discover all subdomains associated with your target domain
- 🔍 **AI-Powered Analysis** - Get instant security insights and risk assessment
- 🎯 **High-Value Target Identification** - Prioritize your testing with automatically identified valuable targets
- 📊 **Interactive Dashboard** - Clean, modern interface with actionable results
- 📄 **Report Generation** - Export results as PDF or JSON for documentation


Install dependencies:

     pip install -r requirements.txt

Run the application:

    python3 app.py

Open your browser to:

    http://localhost:5000

Usage

    Start a Scan:

        Enter the target domain (e.g., example.com)

        Click "Start Scan"

        Watch real-time progress updates

    View Results:

        Interactive dashboard shows:

            Subdomain list with HTTP/HTTPS status

            Security risk assessment

            High-value targets

            Actionable recommendations

    Export Results:

        Download PDF reports for documentation

        Export JSON for further analysis

API Endpoints

Fox Recon provides these API endpoints:

    POST /start_scan - Start a new scan

    GET /scan_status/<scan_id> - Check scan progress

    GET /results/<scan_id> - View HTML results

    GET /api/results/<scan_id> - Get JSON results

    GET /export/<scan_id> - Export results (PDF/JSON)


Disclaimer

This tool is for authorized security testing only. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use on targets you have permission to test.
