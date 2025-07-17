## Overview
This PowerShell script is designed for security analysts and incident responders who need quick visibility into user authentication activity within environments integrated with **CrowdStrike Identity Protection**.

With minimal configuration, you can:
- Authenticate to CrowdStrike API using OAuth.
- Query Identity Protection data for a specific user by `SamAccountName`.
- Retrieve **successful authentication events** from the last X time period (customizable).
- Display results in a formatted table and export to CSV for further analysis or reporting.

---

### ✅ Features
- Uses **CrowdStrike GraphQL API** for rich data queries.
- Supports **time-based filtering** (e.g., last 7 days, last 30 minutes, last month).
- Exports data to **CSV** for integration with SIEMs or custom reporting.
- Supports CrowdStrike regions: **US-1, US-2, EU-1**.

---

### ⚠️ Limitations
- This script uses the `SamAccountName` attribute for lookup. In environments with **multiple domains**, users sharing the same name may cause ambiguity.
- Currently does not support **GovCloud environments**.

---

### 🔒 Minimum API Permissions Required
- Identity Protection Entities - **Read**
- Identity Protection GraphQL - **Write**
- Identity Protection Timeline - **Read**

---

### 🛠️ How to Use
1. **Configure parameters** in the script:
   - `ClientID`, `ClientSecret` – CrowdStrike API credentials.
   - `SamAccountName` – The username to investigate.
   - `Duration` – Time range for query (e.g., `P-7D` for 7 days).
   - `ReportExportPath` – Directory for CSV export.
   - `Cloud` – Your CrowdStrike region (`US-1`, `US-2`, `EU-1`).

2. **Run the script** in PowerShell.

3. **Review output** in console and CSV (if export enabled).

---

### 📦 Example Output
Timestamp Endpoint IP Device

2025-07-16T09:15:34Z WIN10-ADFS01 192.168.1.20 Windows
2025-07-16T09:05:02Z WIN10-ADFS02 192.168.1.21 Windows

---

### ✅ Ideal Use Cases
- Incident Response: Validate suspicious logins quickly.
- Security Audits: Identify historical login patterns.
- IT Operations: Generate login activity reports for compliance.

---

### 🧾 License
This tool is licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.

