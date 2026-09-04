# Frontend: CyberAccess Security Dashboard

Interactive React 18 + Vite + Tailwind CSS dashboard visualizing real-time BOLA defense telemetry, live threat radar, and one-click attack simulations.

## 🚀 Getting Started

### 1. Install Dependencies
```bash
npm install
```

### 2. Run Development Server
```bash
npm run dev
```

* **Dashboard URL:** `http://localhost:5173`

## 🌟 Key Features

* **Real-Time Threat Radar:** Visualizes risk scores ($0 - 100$) and tripped threat signals.
* **One-Click Attack Simulators:**
  * **Normal User Burst:** Simulates legitimate medical access with $0\%$ false positive rate.
  * **Rapid BOLA Enumeration:** Simulates automated ID fuzzing triggering instant 5-minute lockout.
  * **Low-and-Slow Reconnaissance:** Simulates stealth multi-window probing across extended time horizons.
  * **Coordinated Sybil Attack:** Visualizes $50+$ bot identities hitting protected endpoints.
* **Live Audit Log Stream:** Real-time feed of allow, deny, and block events with explanation breakdowns.
