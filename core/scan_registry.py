from typing import Dict, List, Any
import asyncio

class ScanRegistry:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ScanRegistry, cls).__new__(cls)
            cls._instance.active_scans = {} # type: Dict[str, List[asyncio.subprocess.Process]]
        return cls._instance

    def register_scan(self, scan_id: str):
        if scan_id not in self.active_scans:
            self.active_scans[scan_id] = []
            
    def add_process(self, scan_id: str, process):
        if scan_id in self.active_scans:
            self.active_scans[scan_id].append(process)
            
    def remove_scan(self, scan_id: str):
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]
            
    def cancel_scan(self, scan_id: str):
        """Terminates all processes associated with the scan_id."""
        if scan_id in self.active_scans:
            print(f"[*] Cancelling scan {scan_id} with {len(self.active_scans[scan_id])} processes.")
            for process in self.active_scans[scan_id]:
                try:
                    process.terminate()
                    # We can also call kill() if terminate avoids
                except Exception as e:
                    print(f"[!] Error terminating process: {e}")
            del self.active_scans[scan_id]
            return True
        return False

# Global instance
registry = ScanRegistry()
