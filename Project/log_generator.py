"""
FAST RAT - Smart Log Generator
Generates randomized legitimate and attack traffic.
"""
import random
import time
import threading
from datetime import datetime
from ir_core import FastRATEngine
import logging

logger = logging.getLogger("LogGenerator")

class LogGenerator:
    """Generates mixed legitimate and attack traffic."""
    
    SAFE_EVENTS = [
        {'type': 'successful_login', 'payload': 'User login successful', 'severity': 'INFO'},
        {'type': 'file_access', 'payload': 'Accessed document: report.pdf', 'severity': 'INFO'},
        {'type': 'web_request', 'payload': 'GET /api/health 200 OK', 'severity': 'INFO'},
        {'type': 'system_check', 'payload': 'System health check passed', 'severity': 'INFO'},
        {'type': 'backup_complete', 'payload': 'Daily backup completed', 'severity': 'INFO'},
        {'type': 'email_sent', 'payload': 'Email delivered successfully', 'severity': 'INFO'},
        {'type': 'firewall_allow', 'payload': 'Allowed connection on port 443', 'severity': 'INFO'},
        {'type': 'dns_query', 'payload': 'DNS resolution: google.com', 'severity': 'INFO'}
    ]
    
    ATTACK_EVENTS = [
        # CRITICAL (10%)
        {'type': 'ransomware_activity', 'payload': 'Rapid file encryption detected', 'severity': 'CRITICAL'},
        {'type': 'data_exfiltration', 'payload': 'Large outbound transfer to external IP', 'severity': 'CRITICAL'},
        {'type': 'malware_detected', 'payload': 'Trojan.Win32.Emotet detected', 'severity': 'CRITICAL'},
        # HIGH (20%)
        {'type': 'failed_login', 'payload': 'Multiple failed SSH login attempts', 'severity': 'HIGH'},
        {'type': 'port_scan', 'payload': 'TCP SYN scan detected from external host', 'severity': 'HIGH'},
        {'type': 'sql_injection', 'payload': "SQL payload: ' OR 1=1 --", 'severity': 'HIGH'},
        {'type': 'privilege_escalation', 'payload': 'User added to admin group', 'severity': 'HIGH'},
        # MEDIUM (10%)
        {'type': 'policy_violation', 'payload': 'Unauthorized software installation', 'severity': 'MEDIUM'},
        {'type': 'suspicious_login', 'payload': 'Login from unusual location', 'severity': 'MEDIUM'},
        {'type': 'excessive_fail', 'payload': '3 failed attempts (below threshold)', 'severity': 'MEDIUM'}
    ]
    
    USERS = ['alice', 'bob', 'charlie', 'david', 'eve', 'admin']
    SAFE_IPS = ['192.168.1.10', '192.168.1.15', '192.168.1.20', '10.0.0.5', '10.0.0.10']
    ATTACK_IPS = ['185.220.101.42', '91.219.29.81', '45.155.205.99', '103.234.72.18']
    
    def __init__(self, engine: FastRATEngine):
        self.engine = engine
        self.running = False
        self.thread = None
    
    def _generate_safe_event(self) -> dict:
        """Generate a legitimate traffic event."""
        scenario = random.choice(self.SAFE_EVENTS)
        user = random.choice(self.USERS)
        
        return {
            'event_type': scenario['type'],
            'source_ip': random.choice(self.SAFE_IPS),
            'severity': scenario['severity'],
            'payload': f"{scenario['payload']} (user: {user})",
            'timestamp': datetime.now().isoformat()
        }
    
    def _generate_attack_event(self) -> dict:
        """Generate an attack event with weighted severity."""
        # Weight: 25% CRITICAL, 50% HIGH, 25% MEDIUM
        critical = [e for e in self.ATTACK_EVENTS if e['severity'] == 'CRITICAL']
        high = [e for e in self.ATTACK_EVENTS if e['severity'] == 'HIGH']
        medium = [e for e in self.ATTACK_EVENTS if e['severity'] == 'MEDIUM']
        
        roll = random.random()
        if roll < 0.25:
            scenario = random.choice(critical)
        elif roll < 0.75:
            scenario = random.choice(high)
        else:
            scenario = random.choice(medium)
        
        return {
            'event_type': scenario['type'],
            'source_ip': random.choice(self.ATTACK_IPS),
            'severity': scenario['severity'],
            'payload': scenario['payload'],
            'timestamp': datetime.now().isoformat()
        }
    
    def _run(self):
        """Main generation loop."""
        logger.info("📊 Log Generator started")
        
        while self.running:
            try:
                # 60% safe, 40% attack
                if random.random() < 0.6:
                    event = self._generate_safe_event()
                    logger.info(f"[SAFE] {event['event_type']}")
                else:
                    event = self._generate_attack_event()
                    logger.warning(f"[ATTACK] {event['event_type']} ({event['severity']})")
                
                self.engine.process_event(event)
                
                # Random delay 2-5 seconds
                time.sleep(random.uniform(2, 5))
                
            except Exception as e:
                logger.error(f"Generator error: {e}")
                time.sleep(5)
    
    def start(self):
        """Start generator in background thread."""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()
            logger.info("✅ Log Generator thread started")
    
    def stop(self):
        """Stop generator."""
        self.running = False
        logger.info("⏹️ Log Generator stopped")
