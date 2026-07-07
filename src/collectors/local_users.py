import json


class LocalUsersCollector:

    def __init__(self, client):
        self.client = client

    def collect(self):
        script = r"""
$defaultUsers = @(
    "Administrator",
    "Guest",
    "DefaultAccount",
    "WDAGUtilityAccount"
)

$importantGroups = @(
    "Administrators",
    "Remote Desktop Users",
    "Remote Management Users",
    "Backup Operators",
    "Event Log Readers",
    "Users",
    "Guests"
)

$users = Get-LocalUser | ForEach-Object {
    $user = $_
    $groups = @()

    foreach ($group in Get-LocalGroup) {
        try {
            $members = Get-LocalGroupMember -Group $group.Name -ErrorAction Stop
            foreach ($member in $members) {
                if ($member.Name -match "\\$($user.Name)$" -or $member.Name -eq $user.Name) {
                    $groups += $group.Name
                }
            }
        } catch {}
    }

    $access = @()

    if ($groups -contains "Administrators") { $access += "Administrator" }
    if ($groups -contains "Remote Desktop Users") { $access += "Remote Desktop" }
    if ($groups -contains "Remote Management Users") { $access += "Remote Management" }
    if ($groups -contains "Backup Operators") { $access += "Backup Operator" }
    if ($groups -contains "Event Log Readers") { $access += "Event Log Reader" }
    if ($groups.Count -eq 0) { $access += "No Special Access" }
    if ($access.Count -eq 0) { $access += "Standard User" }

    @{
        Username = $user.Name
        AccountType = if ($defaultUsers -contains $user.Name) { "Default" } else { "Custom" }
        Status = if ($user.Enabled) { "Enabled" } else { "Disabled" }
        Groups = ($groups -join ", ")
        AccessLevel = ($access -join ", ")
    }
}

$groupsResult = @()

foreach ($groupName in $importantGroups) {
    try {
        $members = Get-LocalGroupMember -Group $groupName -ErrorAction Stop | ForEach-Object { $_.Name }

        $groupsResult += @{
            Group = $groupName
            Members = ($members -join ", ")
            Count = $members.Count
        }
    } catch {
        $groupsResult += @{
            Group = $groupName
            Members = ""
            Count = 0
        }
    }
}

@{
    Users = $users
    Groups = $groupsResult
} | ConvertTo-Json -Depth 5 -Compress
"""
        output = self.client.execute_ps(script)
        return json.loads(output)