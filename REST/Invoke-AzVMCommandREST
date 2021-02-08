
function Invoke-AzVMCommandREST{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription ID")]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$false,
        HelpMessage="The management scoped token")]
        [string]$managementToken,

        [Parameter(Mandatory=$false,
        HelpMessage="The VM to target")]
        [string]$targetVMArg,

        [Parameter(Mandatory=$true,
        HelpMessage="Command to execute")]
        [string]$commandToExecute
    )

    if($managementToken -eq ""){
        $response = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Method GET -Headers @{Metadata="true"} -UseBasicParsing
        $content = $response.Content | ConvertFrom-Json
        $managementToken = $content.access_token
    }
    
    if ($SubscriptionId -eq ''){

        # List all subscriptions for a tenant
        $subscriptions = ((Invoke-WebRequest -Uri ('https://management.azure.com/subscriptions?api-version=2019-11-01') -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | ConvertFrom-Json).value

        # Select which subscriptions to dump info for
        $subChoice = $subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru

        $SubscriptionId = $subChoice.subscriptionId
        Write-Output $SubscriptionId

        if($subChoice.count -eq 0){Write-Verbose 'No subscriptions selected, exiting'; break}

    }
    else{$subChoice = $SubscriptionId; $noLoop = 1}
    
    try{

    $virtualMachines = ((Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/providers/Microsoft.Compute/virtualMachines?api-version=2020-06-01")) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content) | ConvertFrom-Json
    
    
    $targetVM = $virtualMachines.value | out-gridview -Title "Select target VM" -PassThru
   

    $vmName = $targetVM.name
    $resourceGroup = $targetVM.id.split("/")[4]
    $location = $targetVM.Location

    $commandBody = '{"commandId":"RunPowershellScript","script":["' + $commandToExecute + '"],"parameters":[]}'
    $runCommands = ((Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/resourceGroups/",$resourceGroup,"/providers/Microsoft.Compute/virtualMachines/",$vmName,"/runCommand?api-version=2020-06-01")) -Verbose:$false -ContentType "application/json" -Method POST -Body $commandBody -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content | ConvertFrom-Json).value

    Write-Output "Executing command on target VM: $vmName"
    }
    catch{Write-Output "Something went wrong: $_"}
}





    
