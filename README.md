# Nmap Chrome Extension & Backend

A professional-grade Chrome extension and backend API designed to orchestrate, execute, and monitor Nmap network scans directly from your browser. 

The architecture features a reactive and beautiful glassmorphic Chrome Extension UI that communicates asynchronously with a robust, robustly-isolated FastAPI-powered Windows/Linux backend using a polling background service-worker flow (`chrome.alarms` & `BackgroundTasks`).

---

## 🏗️ Architecture & Features
- **Asynchronous Scan Engine:** Runs scans in background processes (`asyncio.subprocess`) on the host system without stalling or blocking the server.
- **Chrome Extension UI:**
  - Premium, modern aesthetic styling.
  - Comprehensive flag mapping (Scan types, Host Discovery, Service/OS Detection, Port options, Firewall Evasion, and Custom options).
  - High-precision argument generator obeying strict mutual exclusivity rules.
- **Failover / Mock Mode:** Runs in mock mode if Nmap is not installed locally, allowing safe front-end evaluation.
- **State Management:** Asynchronous status polling keeps extension sync'd even if closed and reopened during scan.

---

## 🛠️ Installation & Setup

### 1. Backend Setup

#### Prerequisites
- **Python 3.9+**
- **Nmap:** Ensure Nmap is installed and added to your system's environment `PATH`.
  - *Windows:* Download from [nmap.org](https://nmap.org/download.html) and install it.
  - *Linux:* `sudo apt update && sudo apt install nmap -y`
  - *macOS:* `brew install nmap`

#### Running the Backend Locally
1. Navigate to the backend directory:
   ```bash
   cd nmap_chrome_extension/backend
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the FastAPI server using Uvicorn:
   ```bash
   python api.py
   ```
   *The backend will boot up on `http://localhost:8001`.*

#### Running via Docker (Alternative)
A `Dockerfile` is provided for isolated or non-host environment deployments.
1. Build the Docker image:
   ```bash
   docker build -t nmap-backend .
   ```
2. Run the Docker container:
   ```bash
   docker run -p 8001:8001 nmap-backend
   ```

---

### 2. Chrome Extension Installation

1. Open Google Chrome (or any Chromium-based browser like Brave, Edge, Opera).
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** in the top-left corner.
5. Select the `nmap_chrome_extension/extension` directory from your file system.
6. The Nmap icon will appear in your extension toolbar. Click it to launch the scanner UI!

---

## 🚀 How to Run a Scan

1. Click on the extension icon to open the popup.
2. Enter your scan target (e.g., `127.0.0.1`, `example.com`, or `192.168.1.1/24`).
3. Configure your scan parameters:
   - Select scan types (SYN scan, TCP Connect, UDP scan).
   - Adjust Host Discovery (Ping settings).
   - Toggle OS/Service detection or scripts.
   - Set Firewall Evasion flags or input timing preferences (`T0` - `T5`).
   - Alternatively, supply raw custom flags at the bottom.
4. Click **Run Scan**.
5. View real-time polling logs and final structured output.

---

## 🐳 Backend API Endpoints

- **`GET /health`**: Returns system health status and checks if Nmap is successfully discovered on the backend system path.
- **`POST /api/scan`**: Initiates a scan job. Returns a `job_id` and starts the background execution.
- **`GET /api/scan/{job_id}`**: Retrieves current status (`running`, `completed`, `failed`) and the raw/error outputs.
