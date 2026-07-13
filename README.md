# BlueIntel: Enterprise AI-Powered Malware Analysis Platform

BlueIntel is a commercial-grade, real-time malware analysis platform similar to VirusTotal and Hybrid Analysis. It delivers static unpacking, YARA rule validation, threat intelligence correlation, and an interactive Claude SecOps analyst console.

---

## Architecture Blueprint

- **Frontend**: React (Vite) + Tailwind CSS + Lucide Icons + Recharts. Includes a high-performance custom 3D threat simulation globe rendered on HTML5 Canvas.
- **Backend**: Django REST Framework (DRF) running Python detonation tasks.
- **Real-Time Data**: Server-Sent Events (SSE) push compilation data streams directly from backend worker threads to the browser console.
- **Databases**:
  - `default` SQL (`db.sqlite3`): Stores user accounts, encrypted settings, activities, notifications, and OTP queues.
  - `malware_sandbox_pool` (`db_sandbox.sqlite3`): Stores unstructured detonation JSON logs, classification reports, and threat feeds.

---

## Setup & Running Locally (Recommended)

### Prerequisites
- Python 3.11+
- Node.js 20+

### 1. Launch Django Backend Server
1. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate   # Windows
   source venv/bin/activate  # macOS/Linux
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run database migrations:
   ```bash
   python manage.py migrate --database=default
   python manage.py migrate --database=malware_sandbox_pool
   ```
4. Start the backend developer server:
   ```bash
   python manage.py runserver 127.0.0.1:8000
   ```

### 2. Launch Vite Frontend Client
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Start the dev server:
   ```bash
   npm run dev
   ```
4. Open your browser and navigate to **`http://localhost:5173`** or **`http://127.0.0.1:5173`**.

---

## Running with Docker Compose

If you prefer to run the entire stack inside containers:

1. In the root workspace folder, build and run the services:
   ```bash
   docker-compose up --build
   ```
2. Once the build completes, access the application in your browser at:
   - Frontend UI: **`http://localhost:5173`**
   - Backend API: **`http://localhost:8000`**

---

## Running Automated Tests

To run the automated API and unit test suite:
```bash
python manage.py test
```
The test suite validates:
- Supported vs. unsupported file extension uploads (e.g. `.exe` vs `.txt`).
- Fetching and saving operator cryptography settings keys.
- Live dashboard telemetry and stats aggregations.
- User notifications event list queue.

---

## Core Features Guide

### 1. 3D Threat Globe Map
- Go to the **3D Attack Globe** tab in the sidebar.
- Observe real-time simulated attacks firing global laser arcs.
- Click **Investigate** on any ledger log to trigger the Claude analyst agent for an advisory bulletin.

### 2. Duplex Agentic AI Auditor Console
- Upload a file for scan detonation.
- In the analysis details, access the Playbook section to send manual queries or execute preset triggers (`/audit-apis`, `/yara-forge`, `/mitre-map`, `/remediate`).
