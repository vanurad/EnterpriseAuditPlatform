import json


class SecurityUpdatesCollector:

    def __init__(self, client):
        self.client = client

    def collect(self):
        script = r"""
$updates = Get-HotFix |
Where-Object {
    $_.HotFixID -like "KB*" -and
    ($_.Description -match "Security|Update|Hotfix|Cumulative")
} |
Sort-Object InstalledOn -Descending |
Select-Object -First 20 HotFixID, Description, InstalledOn

$result = @()

foreach ($update in $updates) {
    $result += @{
        KB = $update.HotFixID
        Description = $update.Description
        InstalledOn = if ($update.InstalledOn) { $update.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
    }
}

$result | ConvertTo-Json -Depth 5 -Compress
"""
        output = self.client.execute_ps(script)

        data = json.loads(output)

        if isinstance(data, dict):
            data = [data]

        return data