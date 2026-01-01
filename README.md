# Recon Framework UI

A comprehensive Reconnaissance Framework with a Web UI, integrating Subfinder, Nuclei, FFUF, and more into a unified dashboard.

## Features

-   **Dashboard**: Real-time stats and monitoring.
-   **Target Management**: Add, scan, and manage scope.
-   **Live Console**: Real-time terminal output in the browser.
-   **Inventory**: Asset tracking (Subdomains, URLs).
-   **Fuzzing (FFUF)**: Integrated directory fuzzing with dynamic wordlists.
-   **Vulnerability Scanning**: Nuclei integration.

## Getting Started

### Prerequisites

-   Docker & Docker Compose

### Running the App

```bash
docker compose up -d --build
```

Access the UI at: `http://localhost:8000`

## Development Workflow

### How to push changes

1.  **Make your changes** to the code.
2.  **Stage the changes**:
    ```bash
    git add .
    ```
3.  **Commit the changes** (Save a snapshot):
    ```bash
    git commit -m "Describe your changes here"
    ```
4.  **Push to GitHub**:
    ```bash
    git push
    ```

### Project Structure

-   `core/`: Core logic (Database, Models, Orchestrator).
-   `modules/`: Tool integrations (FFUF, socket, etc).
-   `templates/`: HTML frontend.
-   `fastapi_app.py`: Backend API.
