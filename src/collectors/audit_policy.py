import json


class AuditPolicyCollector:

    def __init__(self, client):
        self.client = client

    def collect(self):
        script = r"""
$SeceditPath = "C:\Windows\System32\secedit.exe"
$temp = "$env:TEMP\audit_policy.cfg"

& $SeceditPath /export /cfg $temp /areas SECURITYPOLICY | Out-Null

$content = Get-Content $temp

function Get-PolicyValue($name) {
    $line = $content | Where-Object { $_ -match "^$name\s*=" }
    if ($line) {
        return ($line -split "=")[1].Trim()
    }
    return "Not Found"
}

$result = @(
    @{
        Policy = "Audit account logon events"
        Expected = "Success, Failure"
        Actual = Get-PolicyValue "AuditAccountLogon"
    },
    @{
        Policy = "Audit account management"
        Expected = "Success, Failure"
        Actual = Get-PolicyValue "AuditAccountManage"
    },
    @{
        Policy = "Audit directory service access"
        Expected = "Success, Failure"
        Actual = Get-PolicyValue "AuditDSAccess"
    },
    @{
        Policy = "Audit logon events"
        Expected = "Success, Failure"
        Actual = Get-PolicyValue "AuditLogonEvents"
    },
    @{
        Policy = "Audit object access"
        Expected = "Success, Failure"
        Actual = Get-PolicyValue "AuditObjectAccess"
    },
    @{
        Policy = "Audit policy change"
        Expected = "Success, Failure"
        Actual = Get-PolicyValue "AuditPolicyChange"
    },
    @{
        Policy = "Audit privilege use"
        Expected = "Success, Failure"
        Actual = Get-PolicyValue "AuditPrivilegeUse"
    },
    @{
        Policy = "Audit process tracking"
        Expected = "Success, Failure"
        Actual = Get-PolicyValue "AuditProcessTracking"
    },
    @{
        Policy = "Audit system events"
        Expected = "Success, Failure"
        Actual = Get-PolicyValue "AuditSystemEvents"
    }
)

Remove-Item $temp -Force -ErrorAction SilentlyContinue

$result | ConvertTo-Json -Depth 5 -Compress
"""
        output = self.client.execute_ps(script)
        data = json.loads(output)

        if isinstance(data, dict):
            data = [data]

        for item in data:
            actual = str(item.get("Actual", "")).strip()

            if actual == "3":
                item["Actual"] = "Success, Failure"
            elif actual == "1":
                item["Actual"] = "Success"
            elif actual == "2":
                item["Actual"] = "Failure"
            elif actual == "0":
                item["Actual"] = "No Auditing"

            item["Status"] = "PASS" if item["Actual"] == item["Expected"] else "FAIL"

        return data