# Real-Time Event Pipeline Simulator

This project is a **software-engineering–focused simulation of a real-time data processing pipeline**, inspired by Security Operations Center (SOC) workflows. It demonstrates how raw, high-volume events are ingested, processed, enriched, aggregated, and visualized in an interactive dashboard.

Rather than focusing on cybersecurity tooling, this project emphasizes **system design, backend processing, and real-time visualization**, showcasing how distributed components work together to transform raw events into meaningful insights.

---

## What This Project Demonstrates

- Event-driven backend architecture  
- Continuous data ingestion and processing  
- Data normalization and enrichment pipelines  
- Aggregation strategies for real-time systems  
- Live, state-driven frontend visualization  
- Clear separation between data generation, processing, and presentation layers  

---

## Simulated Processing Pipeline

The system models a complete end-to-end workflow:

**Event Generation → Ingestion → Normalization → Enrichment → Aggregation → Visualization → User Interpretation**

This mirrors how modern monitoring platforms, analytics systems, and observability tools operate internally.

---

## Core Features

- **Synthetic event simulation** modeling realistic activity patterns:
  - Brute-force–style bursts  
  - Botnet-like distributed traffic  
  - Anomalous network behavior  

- **Centralized backend service**
  - Receives and validates incoming events  
  - Normalizes and enriches raw data  
  - Aggregates events for efficient rendering  

- **Interactive visualization**
  - Geographic representation of activity  
  - Relative intensity based on event volume  
  - Live updates as new data arrives  

---

## Project Structure

- `server.py` — Backend service responsible for event ingestion, processing, aggregation, and serving the dashboard  
- `simulator.py` — Generates synthetic event traffic and feeds it into the pipeline  
- Frontend components — Render real-time data on an interactive map  

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME

Set up a Python virtual environment:

    python3 -m venv venv
    source venv/bin/activate

On Windows:

    venv\Scripts\activate

Install dependencies:

    pip install flask requests

Running the application requires two terminal windows or tabs.

Terminal 1 — Start the backend service:

    python3 server.py

This launches the event ingestion pipeline and dashboard server.

Terminal 2 — Start the event simulator:

    python3 simulator.py

This continuously sends synthetic events into the system.

Viewing the dashboard:

Open your browser and navigate to:

    http://localhost:5000

The dashboard updates in real time, showing how incoming events are aggregated and visualized as system state evolves.
