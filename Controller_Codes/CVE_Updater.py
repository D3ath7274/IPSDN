import os
import json
import sqlite3
import urllib.request
import zipfile
import threading
import time
import io
import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("CVE_Updater")

CVE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve.db")
CVE_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
META_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_meta.json")

def init_db():
    """Initialize the SQLite database."""
    conn = sqlite3.connect(CVE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_records (
            cve_id TEXT PRIMARY KEY,
            date_published TEXT,
            date_updated TEXT,
            description TEXT,
            json_data TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_last_update_time():
    """Get the last update timestamp from the meta file."""
    if os.path.exists(META_FILE):
        try:
            with open(META_FILE, 'r') as f:
                data = json.load(f)
                return datetime.datetime.fromisoformat(data['last_updated'])
        except (json.JSONDecodeError, KeyError, ValueError):
            pass
    return None

def set_last_update_time(dt):
    """Save the last update timestamp to the meta file."""
    with open(META_FILE, 'w') as f:
        json.dump({'last_updated': dt.isoformat()}, f)

def download_and_update_db():
    """Download the CVE zip and update the local database."""
    logger.info("Starting CVE database update...")
    logger.info(f"Downloading from {CVE_URL}...")
    
    try:
        # Download the ZIP file
        with urllib.request.urlopen(CVE_URL) as response:
            zip_content = response.read()
        
        logger.info("Download complete. Processing ZIP file...")
        
        conn = sqlite3.connect(CVE_DB_PATH)
        cursor = conn.cursor()
        
        count = 0
        with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
            for filename in z.namelist():
                if filename.endswith(".json") and "CVE-" in filename:
                    try:
                        with z.open(filename) as f:
                            data = json.load(f)
                            
                            cve_id = data.get("cveMetadata", {}).get("cveId", "UNKNOWN")
                            date_published = data.get("cveMetadata", {}).get("datePublished", "")
                            date_updated = data.get("cveMetadata", {}).get("dateUpdated", "")
                            
                            # Extract english description if available
                            descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
                            description = ""
                            for desc in descriptions:
                                if desc.get("lang") == "en":
                                    description = desc.get("value", "")
                                    break
                            
                            cursor.execute('''
                                INSERT OR REPLACE INTO cve_records (cve_id, date_published, date_updated, description, json_data)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (cve_id, date_published, date_updated, description, json.dumps(data)))
                            
                            count += 1
                            if count % 1000 == 0:
                                conn.commit()
                                logger.info(f"Processed {count} records...")
                                
                    except Exception as e:
                        logger.error(f"Error processing file {filename}: {e}")
                        continue
        
        conn.commit()
        conn.close()
        
        now = datetime.datetime.now()
        set_last_update_time(now)
        logger.info(f"CVE database update completed. Processed {count} records. Next update scheduled.")
        
    except Exception as e:
        logger.error(f"Failed to update CVE database: {e}")

def update_loop(interval_days=1):
    """Background loop to check for updates."""
    init_db()
    
    while True:
        last_update = get_last_update_time()
        now = datetime.datetime.now()
        
        should_update = False
        if last_update is None:
            should_update = True
        else:
            delta = now - last_update
            if delta.days >= interval_days:
                should_update = True
        
        if should_update:
            download_and_update_db()
        else:
            logger.info("No update needed yet.")
        
        # Check every hour if it's time to update, to avoid long sleeps blocking shutdown (if we handled shutdown)
        # But for simplicity, we sleep for an hour then check the day condition again.
        # Or simply sleep for the remaining time. 
        # For robustness, let's sleep 1 hour.
        time.sleep(3600) 

def start_scheduler(interval_days=1):
    """Start the update scheduler in a background thread."""
    t = threading.Thread(target=update_loop, args=(interval_days,), daemon=True)
    t.start()
    logger.info(f"CVE Updater scheduler started with interval of {interval_days} days.")

if __name__ == "__main__":
    # Test run
    # download_and_update_db()
    pass
