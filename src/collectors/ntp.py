import json


class NTPCollector:

    def __init__(self, client):
        self.client = client

    def collect(self):
        script = r"""
$W32tmPath = "C:\Windows\System32\w32tm.exe"

$service = Get-CimInstance Win32_Service -Filter "Name='W32Time'"

$statusOutput = & $W32tmPath /query /status 2>$null
$configOutput = & $W32tmPath /query /configuration 2>$null

$source = ""
foreach ($line in $statusOutput) {
    if ($line -match "^Source:\s*(.*)$") {
        $source = $Matches[1].Trim()
    }
}

$ntpServer = ""
foreach ($line in $configOutput) {
    if ($line -match "^NtpServer:\s*(.*)$") {
        $ntpServer = $Matches[1].Trim()
    }
}

@{
    ServiceName = "Windows Time"
    ServiceState = $service.State
    StartMode = $service.StartMode
    Source = $source
    NtpServer = $ntpServer
} | ConvertTo-Json -Compress
"""
        output = self.client.execute_ps(script)
        return json.loads(output)