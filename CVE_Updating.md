# CVE Auto-Update System Implementation Plan

## Goal
Implement a system to automatically update the local CVE database from [cve.org](https://www.cve.org/) (via their GitHub repository) every "x" days.

## User Review Required
> [!IMPORTANT]
> **Storage Method**: The CVE database contains 100,000+ records. To avoid filesystem performance issues with thousands of small JSON files, I will parse the downloaded data into a single **SQLite database** (`cve.db`). This is more efficient and easier to query.

> [!NOTE]
> **Dependencies**: The script will use standard Python libraries (`urllib`, `zipfile`, `sqlite3`, `json`, `threading`) to avoid needing `pip install` on the user's machine if possible.

## Proposed Changes

### Controller_Codes

#### [NEW] [CVE_Updater.py](file:///d:/4th%20Year/Graduation%20Project/data/Github%20Testing/IPSDN/Controller_Codes/CVE_Updater.py)
*   **Purpose**: Handles downloading, processing, and scheduling updates.
*   **Key Functions**:
    *   `download_cve_zip()`: Downloads `main.zip` from `https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip`.
    *   `process_zip_to_db()`: Extracts JSONs from the ZIP in-memory or temp dir and inserts/updates records in `cve.db`.
    *   `check_and_update(interval_days)`: Checks `last_updated` timestamp. If expired, runs update.
    *   `start_scheduler(interval_days)`: Starts a background thread that sleeps and checks.

#### [MODIFY] [Controller.py](file:///d:/4th%20Year/Graduation%20Project/data/Github%20Testing/IPSDN/Controller_Codes/Controller.py)
*   import `CVE_Updater`.
*   In `__init__`, initialize the updater thread.
*   Add a configuration variable (or hardcode initially as requested "can be changed later") for `update_interval_days`. Default: 1 day.

## Verification Plan

### Automated Tests
*   **Mock Verification**:
    *   Run `CVE_Updater.py` directly with a very short interval (e.g., 0 days/immediate) to verify it attempts download.
    *   Check if `cve.db` is created and populated with sample data.
    *   Check if `cve_meta.json` (or similar) stores the last update time.

### Manual Verification
1.  Run the Controller.
2.  Observe console logs for "Checking for CVE updates..."
3.  Verify `cve.db` file size grows (indicating data ingestion).
4.  Test specific query (optional, if query tool added).
