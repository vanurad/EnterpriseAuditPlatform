import json


class SystemCollector:

    def __init__(self, client):
        self.client = client

    def collect(self):
        script = r"""
$ComputerName = $env:COMPUTERNAME
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem

@{
    Hostname = $ComputerName
    WindowsProductName = $os.Caption
    WindowsVersion = $os.Version
    OsArchitecture = $os.OSArchitecture
    Manufacturer = $cs.Manufacturer
    Model = $cs.Model
    Domain = $cs.Domain
    TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    LastBootTime = $os.LastBootUpTime
} | ConvertTo-Json -Compress
"""
        output = self.client.execute_ps(script)
        return json.loads(output)