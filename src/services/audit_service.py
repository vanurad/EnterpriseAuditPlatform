from src.winrm.connection_factory import ConnectionFactory
from src.collectors.system import SystemCollector
from src.collectors.services import ServicesCollector
from src.collectors.security_policy import SecurityPolicyCollector
from src.collectors.audit_policy import AuditPolicyCollector
from src.collectors.ntp import NTPCollector
from src.collectors.local_users import LocalUsersCollector
from src.collectors.security_updates import SecurityUpdatesCollector


class AuditService:

    @staticmethod
    def start(ip, username, password):

        client = ConnectionFactory.create_connection(ip, username, password)

        system = SystemCollector(client).collect()
        services = ServicesCollector(client).collect()
        security_policy = SecurityPolicyCollector(client).collect()
        audit_policy = AuditPolicyCollector(client).collect()
        ntp = NTPCollector(client).collect()
        local_users_data = LocalUsersCollector(client).collect()
        security_updates = SecurityUpdatesCollector(client).collect()

        expected_services = {
            "PlugPlay": "Stopped",
            "RemoteRegistry": "Stopped",
            "Spooler": "Stopped",
            "Themes": "Stopped",
            "W32Time": "Running",
            "WinRM": "Running"
        }

        service_results = []

        for svc in services:
            expected = expected_services.get(svc["Name"], "Unknown")
            actual = svc["State"]

            service_results.append({
                "Name": svc["Name"],
                "DisplayName": svc["DisplayName"],
                "Expected": expected,
                "Actual": actual,
                "StartMode": svc["StartMode"],
                "Status": "PASS" if str(actual).strip().lower() == str(expected).strip().lower() else "FAIL"
            })

        expected_password_policy = {
            "PasswordHistorySize": {"display": "Enforce password history", "expected": "4"},
            "MaximumPasswordAge": {"display": "Maximum password age", "expected": "42"},
            "MinimumPasswordAge": {"display": "Minimum password age", "expected": "0"},
            "MinimumPasswordLength": {"display": "Minimum password length", "expected": "12"},
            "PasswordComplexity": {"display": "Password must meet complexity requirements", "expected": "1"},
            "ClearTextPassword": {"display": "Store passwords using reversible encryption", "expected": "0"}
        }

        expected_lockout_policy = {
            "LockoutDuration": {"display": "Account lockout duration", "expected": "30"},
            "LockoutBadCount": {"display": "Account lockout threshold", "expected": "5"},
            "ResetLockoutCount": {"display": "Reset account lockout counter after", "expected": "10"}
        }

        password_policy = security_policy.get("PasswordPolicy", {})
        lockout_policy = security_policy.get("AccountLockoutPolicy", {})

        password_results = []
        for key, value in expected_password_policy.items():
            actual = str(password_policy.get(key, "Not Found")).strip()
            password_results.append({
                "Policy": value["display"],
                "Expected": value["expected"],
                "Actual": actual,
                "Status": "PASS" if actual == value["expected"] else "FAIL"
            })

        lockout_results = []
        for key, value in expected_lockout_policy.items():
            actual = str(lockout_policy.get(key, "Not Found")).strip()
            lockout_results.append({
                "Policy": value["display"],
                "Expected": value["expected"],
                "Actual": actual,
                "Status": "PASS" if actual == value["expected"] else "FAIL"
            })

        audit_policy_results = []
        for item in audit_policy:
            audit_policy_results.append({
                "Category": "Local Audit Policy",
                "Subcategory": item.get("Policy", ""),
                "Expected": item.get("Expected", ""),
                "Actual": item.get("Actual", ""),
                "Status": item.get("Status", "FAIL")
            })

        approved_ntp_servers = [
            "ntp01.redbus.com",
            "ntp02.redbus.com",
            "ntp01.redus.com",
            "ntp02.redus.com"
        ]

        ntp_results = []

        service_state = str(ntp.get("ServiceState", "")).strip()
        ntp_results.append({
            "Check": "Windows Time service status",
            "Expected": "Running",
            "Actual": service_state,
            "Status": "PASS" if service_state.lower() == "running" else "FAIL"
        })

        start_mode = str(ntp.get("StartMode", "")).strip()
        ntp_results.append({
            "Check": "Windows Time startup type",
            "Expected": "Auto",
            "Actual": start_mode,
            "Status": "PASS" if start_mode.lower() in ["auto", "automatic"] else "FAIL"
        })

        ntp_server = str(ntp.get("NtpServer", "")).strip()
        source = str(ntp.get("Source", "")).strip()
        combined_ntp_value = f"{ntp_server} {source}".lower()

        ntp_ok = any(server.lower() in combined_ntp_value for server in approved_ntp_servers)

        ntp_results.append({
            "Check": "NTP server configuration",
            "Expected": "ntp01.redbus.com or ntp02.redbus.com",
            "Actual": ntp_server if ntp_server else source,
            "Status": "PASS" if ntp_ok else "FAIL"
        })

        return {
            "system": system,
            "services": service_results,
            "password_policy": password_results,
            "account_lockout_policy": lockout_results,
            "audit_policy": audit_policy_results,
            "ntp_policy": ntp_results,
            "local_users": local_users_data.get("Users", []),
            "local_groups": local_users_data.get("Groups", []),
            "security_updates": security_updates
        }