import threading
import uuid
from datetime import datetime

class ScanManager:
    def __init__(self):
        self.scans = {}

    def create_scan(self, config):
        scan_id = str(uuid.uuid4())
        self.scans[scan_id] = {
            "config": config,
            "status": {
                "headers": "pending",
                "outdated": "pending",
                "forms": "pending",
                "cve": "pending"
            },
            "log": [],
            "created_at": datetime.utcnow(),
            "aborted": False
        }
        return scan_id

    def get_scan(self, scan_id):
        return self.scans.get(scan_id)

    def update_status(self, scan_id, module, status):
        if scan_id in self.scans:
            self.scans[scan_id]['status'][module] = status

    def append_log(self, scan_id, message):
        if scan_id in self.scans:
            self.scans[scan_id]['log'].append(message)

    def abort(self, scan_id):
        if scan_id in self.scans:
            self.scans[scan_id]['aborted'] = True

scan_manager = ScanManager()
