"""
FAST RAT - Core Engine
Handles detection, Excel storage, and containment actions.
"""
import os
import pandas as pd
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional
import threading
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FAST-RAT")

DATA_DIR = "data"
INCIDENTS_FILE = os.path.join(DATA_DIR, "incidents.xlsx")
EVENTS_FILE = os.path.join(DATA_DIR, "events.xlsx")
ACTIONS_FILE = os.path.join(DATA_DIR, "actions.xlsx")

# Thread lock for Excel writes
excel_lock = threading.Lock()

@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str
    status: str = "detected"
    source_ip: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    actions_taken: str = ""
    description: str = ""

class ExcelStorage:
    """Handles all Excel file operations for incidents and events."""
    
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        self._init_files()
    
    def _init_files(self):
        """Create Excel files if they don't exist."""
        if not os.path.exists(INCIDENTS_FILE):
            df = pd.DataFrame(columns=['incident_id', 'title', 'severity', 'status', 
                                       'source_ip', 'created_at', 'actions_taken', 'description'])
            df.to_excel(INCIDENTS_FILE, index=False, engine='openpyxl')
            logger.info(f"Created {INCIDENTS_FILE}")
        
        if not os.path.exists(EVENTS_FILE):
            df = pd.DataFrame(columns=['event_id', 'event_type', 'source_ip', 
                                       'severity', 'payload', 'timestamp'])
            df.to_excel(EVENTS_FILE, index=False, engine='openpyxl')
            logger.info(f"Created {EVENTS_FILE}")
        
        if not os.path.exists(ACTIONS_FILE):
            df = pd.DataFrame(columns=['action_id', 'action_type', 'target', 
                                       'status', 'performed_by', 'timestamp'])
            df.to_excel(ACTIONS_FILE, index=False, engine='openpyxl')
            logger.info(f"Created {ACTIONS_FILE}")
            logger.info(f"Created {EVENTS_FILE}")
    
    def store_incident(self, incident: Incident) -> bool:
        """Store or update an incident in Excel."""
        with excel_lock:
            try:
                df = pd.read_excel(INCIDENTS_FILE, engine='openpyxl')
                
                # Check if incident exists (update) or new (append)
                mask = df['incident_id'] == incident.incident_id
                if mask.any():
                    # Update existing
                    idx = df[mask].index[0]
                    df.loc[idx] = [incident.incident_id, incident.title, incident.severity,
                                   incident.status, incident.source_ip, incident.created_at,
                                   incident.actions_taken, incident.description]
                else:
                    # Append new
                    new_row = pd.DataFrame([{
                        'incident_id': incident.incident_id,
                        'title': incident.title,
                        'severity': incident.severity,
                        'status': incident.status,
                        'source_ip': incident.source_ip,
                        'created_at': incident.created_at,
                        'actions_taken': incident.actions_taken,
                        'description': incident.description
                    }])
                    df = pd.concat([df, new_row], ignore_index=True)
                
                df.to_excel(INCIDENTS_FILE, index=False, engine='openpyxl')
                return True
            except Exception as e:
                logger.error(f"Failed to store incident: {e}")
                return False
    
    def log_event(self, event_data: dict) -> bool:
        """Log a raw event to Excel."""
        with excel_lock:
            try:
                df = pd.read_excel(EVENTS_FILE, engine='openpyxl')
                
                new_row = pd.DataFrame([{
                    'event_id': len(df) + 1,
                    'event_type': event_data.get('event_type', ''),
                    'source_ip': event_data.get('source_ip', ''),
                    'severity': event_data.get('severity', 'INFO'),
                    'payload': event_data.get('payload', ''),
                    'timestamp': event_data.get('timestamp', datetime.now().isoformat())
                }])
                df = pd.concat([df, new_row], ignore_index=True)
                
                # Keep only last 1000 events to prevent file bloat
                if len(df) > 1000:
                    df = df.tail(1000)
                
                df.to_excel(EVENTS_FILE, index=False, engine='openpyxl')
                return True
            except Exception as e:
                logger.error(f"Failed to log event: {e}")
                return False
    
    def get_all_incidents(self) -> List[dict]:
        """Get all incidents as list of dicts."""
        try:
            df = pd.read_excel(INCIDENTS_FILE, engine='openpyxl')
            df = df.fillna('')  # Replace NaN with empty strings
            return df.to_dict('records')
        except:
            return []
    
    def get_incident(self, incident_id: str) -> Optional[dict]:
        """Get single incident by ID."""
        try:
            df = pd.read_excel(INCIDENTS_FILE, engine='openpyxl')
            match = df[df['incident_id'] == incident_id]
            if not match.empty:
                return match.iloc[0].to_dict()
            return None
        except:
            return None
    
    def get_recent_events(self, limit: int = 20) -> List[dict]:
        """Get recent events."""
        try:
            df = pd.read_excel(EVENTS_FILE, engine='openpyxl')
            df = df.fillna('')  # Replace NaN
            return df.tail(limit).to_dict('records')[::-1]  # Reverse for newest first
        except:
            return []
    
    def get_stats(self) -> dict:
        """Get incident statistics."""
        try:
            df = pd.read_excel(INCIDENTS_FILE, engine='openpyxl')
            return {
                'total': len(df),
                'critical': len(df[df['severity'] == 'CRITICAL']),
                'high': len(df[df['severity'] == 'HIGH']),
                'medium': len(df[df['severity'] == 'MEDIUM']),
                'low': len(df[df['severity'] == 'LOW']),
                'by_status': {
                    'detected': len(df[df['status'] == 'detected']),
                    'contained': len(df[df['status'] == 'contained']),
                    'closed': len(df[df['status'] == 'closed'])
                }
            }
        except:
            return {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'by_status': {}}
    
    def get_analytics_data(self, range_type: str = 'daily') -> dict:
        """Get data for analytics charts."""
        try:
            df = pd.read_excel(INCIDENTS_FILE, engine='openpyxl')
            if df.empty:
                return {'labels': [], 'data': [], 'severity_counts': {}}
            
            df['created_at'] = pd.to_datetime(df['created_at'])
            now = datetime.now()
            
            # Filter by range
            if range_type == 'daily':
                df = df[df['created_at'] >= now - pd.Timedelta(days=1)]
                df['period'] = df['created_at'].dt.strftime('%H:00')
            elif range_type == 'weekly':
                df = df[df['created_at'] >= now - pd.Timedelta(days=7)]
                df['period'] = df['created_at'].dt.strftime('%a')
            else:  # monthly
                df = df[df['created_at'] >= now - pd.Timedelta(days=30)]
                df['period'] = df['created_at'].dt.strftime('%d')
            
            # Aggregate
            counts = df.groupby('period').size().to_dict()
            severity_counts = df['severity'].value_counts().to_dict()
            
            return {
                'labels': list(counts.keys()),
                'data': list(counts.values()),
                'severity_counts': severity_counts
            }
        except Exception as e:
            logger.error(f"Analytics error: {e}")
            return {'labels': [], 'data': [], 'severity_counts': {}}
    
    def store_action(self, action_data: dict) -> bool:
        """Store a containment action."""
        with excel_lock:
            try:
                df = pd.read_excel(ACTIONS_FILE, engine='openpyxl')
                
                new_row = pd.DataFrame([{
                    'action_id': f"ACT-{int(datetime.now().timestamp() * 1000)}",
                    'action_type': action_data.get('action_type', ''),
                    'target': action_data.get('target', ''),
                    'status': action_data.get('status', 'active'),
                    'performed_by': action_data.get('performed_by', 'Manual'),
                    'timestamp': datetime.now().isoformat()
                }])
                df = pd.concat([df, new_row], ignore_index=True)
                df.to_excel(ACTIONS_FILE, index=False, engine='openpyxl')
                logger.info(f"🛡️ Action stored: {action_data.get('action_type')} -> {action_data.get('target')}")
                return True
            except Exception as e:
                logger.error(f"Failed to store action: {e}")
                return False
    
    def get_all_actions(self) -> List[dict]:
        """Get all actions."""
        try:
            df = pd.read_excel(ACTIONS_FILE, engine='openpyxl')
            df = df.fillna('')
            return df.to_dict('records')[::-1]  # Newest first
        except:
            return []


class DetectionEngine:
    """Rule-based threat detection."""
    
    THREAT_RULES = {
        'failed_login': {'min_count': 5, 'severity': 'HIGH', 'title': 'Brute Force Attack'},
        'malware_detected': {'severity': 'CRITICAL', 'title': 'Malware Detection'},
        'port_scan': {'severity': 'HIGH', 'title': 'Port Scanning Activity'},
        'data_exfiltration': {'severity': 'CRITICAL', 'title': 'Data Exfiltration Attempt'},
        'ransomware_activity': {'severity': 'CRITICAL', 'title': 'Ransomware Activity'},
        'sql_injection': {'severity': 'HIGH', 'title': 'SQL Injection Attempt'},
        'policy_violation': {'severity': 'MEDIUM', 'title': 'Policy Violation'},
        'suspicious_login': {'severity': 'MEDIUM', 'title': 'Suspicious Login'}
    }
    
    def analyze_event(self, event: dict) -> Optional[Incident]:
        """Analyze event and create incident if threat detected."""
        event_type = event.get('event_type', '')
        severity = event.get('severity', 'INFO')
        
        # Only create incidents for non-safe events
        if severity in ['INFO', 'LOW']:
            return None
        
        rule = self.THREAT_RULES.get(event_type)
        if rule:
            title = rule.get('title', event_type)
            sev = rule.get('severity', severity)
        else:
            title = f"{event_type} detected"
            sev = severity
        
        incident_id = f"INC-{int(datetime.now().timestamp() * 1000)}"
        
        return Incident(
            incident_id=incident_id,
            title=f"{title} from {event.get('source_ip', 'unknown')}",
            severity=sev,
            source_ip=event.get('source_ip', ''),
            description=event.get('payload', '')
        )


class ContainmentEngine:
    """Simulated containment actions with realistic logging."""
    
    def __init__(self):
        self.blocked_ips = set()
        self.quarantined_files = []
        self.terminated_processes = []
    
    def block_ip(self, ip: str) -> str:
        """Simulate adding IP to firewall blocklist."""
        self.blocked_ips.add(ip)
        logger.warning(f"🛡️ [FIREWALL] Adding rule: iptables -A INPUT -s {ip} -j DROP")
        logger.warning(f"🛡️ [FIREWALL] Adding rule: iptables -A OUTPUT -d {ip} -j DROP")
        logger.info(f"✅ IP {ip} added to blocklist ({len(self.blocked_ips)} total blocked)")
        return f"Firewall rule added: Block {ip}"
    
    def quarantine_file(self, filepath: str) -> str:
        """Simulate moving file to quarantine folder."""
        import os
        quarantine_path = f"/quarantine/{os.path.basename(filepath)}.quarantined"
        self.quarantined_files.append(filepath)
        logger.warning(f"🔒 [QUARANTINE] Moving {filepath} -> {quarantine_path}")
        logger.warning(f"🔒 [QUARANTINE] Setting permissions: chmod 000 {quarantine_path}")
        logger.info(f"✅ File quarantined: {filepath}")
        return f"File quarantined: {filepath}"
    
    def terminate_process(self, process_name: str, pid: int = None) -> str:
        """Simulate terminating malicious process."""
        pid = pid or 9999
        self.terminated_processes.append(process_name)
        logger.warning(f"💀 [PROCESS] Sending SIGKILL to PID {pid} ({process_name})")
        logger.info(f"✅ Process terminated: {process_name}")
        return f"Process terminated: {process_name} (PID {pid})"
    
    def isolate_host(self, hostname: str) -> str:
        """Simulate network isolation of compromised host."""
        logger.warning(f"🔌 [NETWORK] Disabling network interfaces on {hostname}")
        logger.warning(f"🔌 [NETWORK] Adding VLAN isolation rule for {hostname}")
        logger.info(f"✅ Host isolated: {hostname}")
        return f"Host isolated from network: {hostname}"
    
    def disable_user(self, username: str) -> str:
        """Simulate disabling compromised user account."""
        logger.warning(f"🚫 [ACCOUNT] Disabling user: {username}")
        logger.warning(f"🚫 [ACCOUNT] Revoking active sessions for: {username}")
        logger.info(f"✅ User disabled: {username}")
        return f"User account disabled: {username}"
    
    def alert_admin(self, message: str, severity: str = "HIGH") -> str:
        """Send alert to security team."""
        logger.warning(f"📧 [ALERT-{severity}] Security Team: {message}")
        logger.info(f"✅ Alert sent to security team")
        return f"Alert sent: {message}"


class FastRATEngine:
    """Main FAST RAT engine combining all components."""
    
    def __init__(self):
        self.storage = ExcelStorage()
        self.detection = DetectionEngine()
        self.containment = ContainmentEngine()
        logger.info("🚀 FAST RAT Engine initialized")
    
    def process_event(self, event: dict):
        """Process incoming event through the pipeline."""
        # Always log raw event
        self.storage.log_event(event)
        
        # Detect threats
        incident = self.detection.analyze_event(event)
        
        if incident:
            # Auto-containment for critical threats
            if incident.severity == 'CRITICAL':
                action = self.containment.block_ip(incident.source_ip)
                incident.actions_taken = action
                incident.status = 'contained'
                
                # Log automatic action to Excel
                self.storage.store_action({
                    'action_type': 'Block IP',
                    'target': incident.source_ip,
                    'status': 'active',
                    'performed_by': 'Automatic (CRITICAL threat)'
                })
            
            # Store incident
            self.storage.store_incident(incident)
            logger.info(f"🚨 Incident created: {incident.incident_id} [{incident.severity}]")
            return incident
        
        return None
