import json


class ServicesCollector:

    def __init__(self, client):
        self.client = client

    def collect(self):
        script = r"""
$services = @("PlugPlay","RemoteRegistry","Spooler","Themes","WinRM","W32Time")

Get-CimInstance Win32_Service |
Where-Object { $services -contains $_.Name } |
Select-Object Name, DisplayName, State, StartMode |
ConvertTo-Json -Compress
"""
        output = self.client.execute_ps(script)
        data = json.loads(output)

        if isinstance(data, dict):
            data = [data]

        return data