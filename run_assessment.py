"""
Cerberus AI - Main Assessment Runner
"""

import asyncio
import sys
from datetime import datetime

sys.path.insert(0, '.')

from plugins.security.password_auditor import EnterprisePasswordAuditor
from plugins.security.account_scanner import AccountSecurityScanner
from plugins.security.report_generator import SecurityReportGenerator


async def run_full_assessment():
    """Run complete security assessment"""
    
    print("=" * 60)
    print("🔒 Cerberus AI - Security Assessment Tool")
    print("=" * 60)
    print()
    
    # 1. Password Audit
    print("[1/3] Password Audit...")
    auditor = EnterprisePasswordAuditor()
    
    username = input("Enter username/email: ") or "test@example.com"
    password = input("Enter password to audit: ") or "Test123!"
    
    password_result = auditor.audit_password(username, password)
    
    print(f"✅ Strength: {password_result.strength_score}/10")
    print(f"✅ Crack time: {password_result.crack_time_estimate}")
    print()
    
    # 2. Account Scan
    print("[2/3] Account Security Scan...")
    scanner = AccountSecurityScanner()
    
    account_data = {
        "2fa_enabled": input("2FA enabled? (y/n): ").lower() == 'y',
        "password_min_length": int(input("Password min length: ") or "8"),
        "active_sessions": int(input("Active sessions: ") or "1"),
        "recovery_email": input("Recovery email? (y/n): ").lower() == 'y',
        "recovery_phone": input("Recovery phone? (y/n): ").lower() == 'y',
        "login_alerts": input("Login alerts? (y/n): ").lower() == 'y',
        "connected_apps": int(input("Connected apps: ") or "0"),
    }
    
    scan_result = await scanner.scan_account(account_data)
    
    print(f"✅ Findings: {scan_result['total_findings']}")
    print(f"   - Critical: {scan_result['critical']}")
    print(f"   - High: {scan_result['high']}")
    print()
    
    # 3. Generate Report
    print("[3/3] Generating Report...")
    generator = SecurityReportGenerator()
    
    combined = {
        "total_findings": scan_result['total_findings'],
        "critical": scan_result['critical'],
        "high": scan_result['high'],
        "findings": scan_result['findings'],
    }
    
    report = generator.generate_report(combined)
    
    report_file = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"✅ Report saved: {report_file}")
    print()
    print("=" * 60)
    print("🔒 Assessment Complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_full_assessment())
