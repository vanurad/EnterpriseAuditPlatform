import json


class SecurityPolicyCollector:

    def __init__(self, client):
        self.client = client

    def collect(self):
        script = r"""
$SeceditPath = "C:\Windows\System32\secedit.exe"
$temp = "$env:TEMP\security_policy.cfg"

& $SeceditPath /export /cfg $temp | Out-Null

$content = Get-Content $temp

function Get-PolicyValue($name) {
    $line = $content | Where-Object { $_ -match "^$name\s*=" }
    if ($line) {
        return ($line -split "=")[1].Trim()
    }
    return "Not Found"
}

$result = @{
    PasswordPolicy = @{
        PasswordHistorySize = Get-PolicyValue "PasswordHistorySize"
        MaximumPasswordAge = Get-PolicyValue "MaximumPasswordAge"
        MinimumPasswordAge = Get-PolicyValue "MinimumPasswordAge"
        MinimumPasswordLength = Get-PolicyValue "MinimumPasswordLength"
        PasswordComplexity = Get-PolicyValue "PasswordComplexity"
        ClearTextPassword = Get-PolicyValue "ClearTextPassword"
    }
    AccountLockoutPolicy = @{
        LockoutBadCount = Get-PolicyValue "LockoutBadCount"
        ResetLockoutCount = Get-PolicyValue "ResetLockoutCount"
        LockoutDuration = Get-PolicyValue "LockoutDuration"
    }
}

Remove-Item $temp -Force -ErrorAction SilentlyContinue

$result | ConvertTo-Json -Depth 5 -Compress
"""
        output = self.client.execute_ps(script)
        return json.loads(output)