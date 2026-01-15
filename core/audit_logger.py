"""
Audit Logger - Full audit trail for all AgentZero109 operations
Ensures accountability and enables post-mortem analysis
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from enum import Enum


class EventType(Enum):
    """Types of events that can be logged"""
    SCAN_START = "scan_start"
    SCAN_END = "scan_end"
    REQUEST_SENT = "request_sent"
    VULNERABILITY_FOUND = "vulnerability_found"
    EXPLOIT_ATTEMPTED = "exploit_attempted"
    REPORT_GENERATED = "report_generated"
    ERROR = "error"
    RATE_LIMIT = "rate_limit"
    KILL_SWITCH = "kill_switch"
    HUMAN_REVIEW = "human_review"


class AuditLogger:
    """
    Comprehensive audit logging system
    Tracks all operations for accountability and analysis
    """
    
    def __init__(self, log_dir: str = "audit_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Create timestamped log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"audit_{timestamp}.jsonl"
        
        # Also setup standard logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("AgentZero109")
        
    def log_event(
        self,
        event_type: EventType,
        details: Dict[str, Any],
        severity: str = "INFO",
        target: Optional[str] = None
    ) -> None:
        """
        Log an event to both structured and human-readable logs
        
        Args:
            event_type: Type of event being logged
            details: Event-specific details
            severity: Log severity level
            target: Target URL/endpoint if applicable
        """
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type.value,
            "severity": severity,
            "target": target,
            "details": details
        }
        
        # Write to JSONL file for structured analysis
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
        
        # Also log to standard logger
        log_msg = f"[{event_type.value}] {target or 'N/A'}: {details.get('message', str(details))}"
        
        if severity == "ERROR":
            self.logger.error(log_msg)
        elif severity == "WARNING":
            self.logger.warning(log_msg)
        else:
            self.logger.info(log_msg)
    
    def log_request(
        self,
        method: str,
        url: str,
        headers: Dict,
        body: Optional[str] = None,
        response_code: Optional[int] = None
    ) -> None:
        """Log HTTP request details"""
        # Sanitize sensitive headers
        safe_headers = {k: v for k, v in headers.items() 
                       if k.lower() not in ['authorization', 'cookie', 'x-api-key']}
        
        self.log_event(
            EventType.REQUEST_SENT,
            {
                "method": method,
                "url": url,
                "headers": safe_headers,
                "body_length": len(body) if body else 0,
                "response_code": response_code
            },
            target=url
        )
    
    def log_vulnerability(
        self,
        vuln_type: str,
        severity: str,
        target: str,
        confidence: str,
        details: Dict[str, Any]
    ) -> None:
        """Log discovered vulnerability"""
        self.log_event(
            EventType.VULNERABILITY_FOUND,
            {
                "vulnerability_type": vuln_type,
                "severity": severity,
                "confidence": confidence,
                **details
            },
            severity="WARNING",
            target=target
        )
    
    def log_exploit_attempt(
        self,
        target: str,
        exploit_type: str,
        success: bool,
        details: Dict[str, Any]
    ) -> None:
        """Log exploit validation attempt"""
        self.log_event(
            EventType.EXPLOIT_ATTEMPTED,
            {
                "exploit_type": exploit_type,
                "success": success,
                **details
            },
            severity="WARNING" if success else "INFO",
            target=target
        )
    
    def log_error(self, error_msg: str, exception: Optional[Exception] = None) -> None:
        """Log error condition"""
        details = {"message": error_msg}
        if exception:
            details["exception"] = str(exception)
            details["exception_type"] = type(exception).__name__
        
        self.log_event(EventType.ERROR, details, severity="ERROR")
    
    def trigger_kill_switch(self, reason: str) -> None:
        """Log kill switch activation"""
        self.log_event(
            EventType.KILL_SWITCH,
            {"reason": reason, "message": "AgentZero109 operations halted"},
            severity="ERROR"
        )
        self.logger.critical(f"KILL SWITCH ACTIVATED: {reason}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Generate summary of audit log"""
        events = []
        with open(self.log_file, 'r') as f:
            for line in f:
                events.append(json.loads(line))
        
        summary = {
            "total_events": len(events),
            "event_types": {},
            "vulnerabilities_found": 0,
            "exploits_attempted": 0,
            "errors": 0
        }
        
        for event in events:
            event_type = event["event_type"]
            summary["event_types"][event_type] = summary["event_types"].get(event_type, 0) + 1
            
            if event_type == "vulnerability_found":
                summary["vulnerabilities_found"] += 1
            elif event_type == "exploit_attempted":
                summary["exploits_attempted"] += 1
            elif event_type == "error":
                summary["errors"] += 1
        
        return summary
