function Get-AzRestBastionShareableLink {

    # Author: Karim El-Melhaoui(@KarimsCloud), O3 Cyber
    # Description: PowerShell function for getting an existing shareable link in Azure Bastion
    # https://learn.microsoft.com/en-us/azure/bastion/shareable-link


    $Token = (New-Object System.Management.Automation.PSCredential("token", (Get-AzAccessToken -AsSecureString).token)).GetNetworkCredential().Password
    $Headers = @{Authorization = "Bearer $Token)" }

    $AzBastions = Get-AzBastion
    Write-Output "Getting all Shareable Links for Azure bastions"
    foreach ($AzBastion in $AzBastions) {        
        $RGName = $AzBastion.ResourceGroupName
        $BastionName = $AzBastion.Name
    
        try {
            $BastionLink = Invoke-RestMethod -Method Post -Uri "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($RGName)/providers/Microsoft.Network/bastionHosts/$($BastionName)/GetShareableLinks?api-version=2022-05-01" -Headers $Headers | Select-Object -ExpandProperty Value | Select-Object -ExpandProperty bsl
            Write-Host -ForegroundColor Green "Public link for Bastion: $BastionLink"
        }
        catch {
            Write-Output "Something went wrong. : $_"
        }
    }
}

#Get-AzRestBastionShareableLink
