# MiniEDR

MiniEDR is a lightweight Endpoint Detection and Response (EDR) project built in Python. It collects endpoint telemetry, enriches process information using VirusTotal, and provides a simple dashboard for threat hunting and process visualization.

## Features

- Collect running processes and network connections.
- Calculate SHA-256 hashes for executable files.
- Store telemetry in a local SQLite database.
- Enrich process hashes with VirusTotal.
- Cache VirusTotal responses to reduce API requests.
- Visualize the process tree in an interactive dashboard.
- Search and filter processes by different attributes.

## Project Structure

```text
miniEDR/
│── agent.py          # Endpoint telemetry collector
│── enricher.py       # VirusTotal enrichment engine
│── app.py            # Streamlit dashboard
│── database.db       # SQLite database
│── requirements.txt
│── README.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/miniEDR.git
cd miniEDR
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate the virtual environment.

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

## Usage

Start the telemetry collector:

```bash
python agent.py
```

Run the enrichment engine:

```bash
python enricher.py
```

Launch the dashboard:

```bash
streamlit run app.py
```

## Technologies

- Python
- SQLite
- Streamlit
- psutil
- hashlib
- VirusTotal API
- PyVis

## Contributing

Nothing yet :)

## License

Nothing yet :)
