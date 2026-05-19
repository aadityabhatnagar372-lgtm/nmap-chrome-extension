# Nmap Web Interface - Installation & Usage Guide

Follow these simple instructions to install the dependencies, start the backend server, and load the extension into Google Chrome.

---

## 📋 Prerequisites
Before running, ensure you have:
1. **Python 3.9+** installed. You can verify this by running:
   ```bash
   python --version
   ```
2. **Nmap** installed and added to your system's environmental `PATH`:
   - **Windows:** Download the installer from [nmap.org/download.html](https://nmap.org/download.html). Ensure you check the box to add Nmap to the system PATH.
   - **Linux (Ubuntu/Debian):** `sudo apt update && sudo apt install nmap -y`
   - **macOS:** `brew install nmap`

---

## 🛠️ Step 1: Install Python Dependencies
Open your terminal (PowerShell, Command Prompt, or Bash) and navigate to the backend directory:

```bash
cd nmap_chrome_extension/backend
```

Install the required Python modules using pip:
```bash
pip install -r requirements.txt
```

---

## 🚀 Step 2: Start the Backend Server
From the backend directory, run:

```bash
python api.py
```

- The API server will start up on **`http://localhost:8001`**.
- Keep this terminal window open while using the extension.

---

## 🔌 Step 3: Install the Chrome Extension
1. Open Google Chrome.
2. Navigate to **`chrome://extensions/`** by typing it in your address bar.
3. In the top-right corner, toggle the **Developer mode** switch to **ON**.
4. In the top-left corner, click the **Load unpacked** button.
5. In the file picker, select the **`nmap_chrome_extension/extension`** folder.
6. The extension is now loaded! You will see the Nmap Web Interface icon in your toolbar.

---

## 💻 Step 4: Run a Scan
1. Click the Nmap extension icon in your Chrome toolbar.
2. Enter a target (e.g., `127.0.0.1`, `example.com`, or local network IP ranges).
3. Check the options you want to run (e.g., SYN Scan, OS Detection, Service Version, Ping Settings).
4. Click the **Run Scan** button.
5. The extension will automatically poll the backend and show you the real-time progress and final terminal logs.
