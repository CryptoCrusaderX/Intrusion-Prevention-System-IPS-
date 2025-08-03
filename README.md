# SurakshaNet: Intrusion Detection & Prevention System (IDPS)

SurakshaNet is a **real-time Intrusion Detection and Prevention System (IDPS)** developed in **Python** for **macOS**.  
It combines **network monitoring**, **host-based file monitoring**, and **active IP blocking** into a lightweight application with a **modern GUI**.

---

##  Features

- **Real-Time Packet Sniffing**
  - Monitors all incoming and outgoing traffic.
  - Displays live packet logs with source and destination IPs.

- **File System Monitoring**
  - Detects file creation, modification, and deletion instantly.
  - Raises immediate alerts in the GUI.

- **Active Intrusion Prevention**
  - Dynamically blocks suspicious IP addresses using macOS **pfctl**.
  - Supports manual IP addition and clearing directly from the interface.

- **Modern Interactive Dashboard**
  - Visual circular rings for traffic and file alerts.
  - Organized tabs: **Dashboard**, **Alerts**, and **Settings**.
  - Smooth real-time updates without interface freezing.

---
## Installation & Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/CryptoCrusaderX/Intrusion-Prevention-System-IPS-.git
   cd Intrusion-Prevention-System-IPS-
   ```

2. **Create and Activate a Virtual Environment (Recommended)**
    ```bash
    python3 -m venv venv
    source venv/bin/activate   # For macOS/Linux 
    ```
---
3. **Install Required Dependencies**
    ```bash
    pip install -r requirements.txt
    ```
4. **Configure macOS Firewall for Dynamic Blocking
    - Add the following line to `/etc/pf.conf`:
        ```bash
        anchor "com.idps.block"
        ```
    - Reload pfctl:
        ```bash
        sudo pfctl -f /etc/pf.conf
        sudo pfctl -e
        ```
5. **Run the Application**
```bash
sudo python3 IDPS.py
```

##  Future Improvements

- Implement **machine learning–based anomaly detection**.  
- Extend **firewall support to Linux and Windows**.  
- Add **push notifications or email alerts** for critical events.  
- Support **exportable log reports** for audits.

---


