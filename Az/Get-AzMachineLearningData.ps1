<#
    File: Get-AzMachineLearningData.ps1
    Author: Christian Bortone (@xybytes) - 2024
    Description: PowerShell functions for dumping Azure Machine Learning Workspace information.
#>

function Get-AzMachineLearningData{

<#
    .SYNOPSIS
        PowerShell function for dumping information from Azure Machine Learning Workspaces.
    .DESCRIPTION
        The function will dump available information for an Azure ML Workspace. This includes compute instances, resources, models, jobs, endpoints, etc.
    .PARAMETER ResourceGroupName
        Resource group name to use.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER folder
        The folder to output to.
    .EXAMPLE
        PS C:\> Get-AzMachineLearningData -ResourceGroupName "ML-ResourceGroup" -folder MLOutput -Verbose
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="Resource group name.")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$false, HelpMessage="Subscription to use.")]
        [string]$Subscription = "",

        [Parameter(Mandatory=$false, HelpMessage="Folder to output to.")]
        [string]$folder = ""
    )

    # Check login status
    $LoginStatus = Get-AzContext
    $accountName = ($LoginStatus.Account).Id
    if ($LoginStatus.Account -eq $null){Write-Warning "No active login. Prompting for login." 
        try {Connect-AzAccount -ErrorAction Stop}
        catch{Write-Warning "Login process failed."}
    }

    # Subscription name is technically required if one is not already set, list sub names if one is not provided "Get-AzSubscription"
    if ($Subscription){        
        Select-AzSubscription -SubscriptionName $Subscription | Out-Null
    }
    else{
        # List subscriptions, pipe out to gridview selection
        $Subscriptions = Get-AzSubscription -WarningAction SilentlyContinue
        $subChoice = $Subscriptions | Out-GridView -Title "Select One or More Subscriptions" -PassThru
        foreach ($sub in $subChoice) {Get-AzBatchAccountData -Subscription $sub -folder $folder}
        return
    }

    Write-Verbose "Logged In as $accountName"

    # Folder setup
    if ($folder -ne ""){
        if(Test-Path $folder){}
        else{New-Item -ItemType Directory $folder | Out-Null}
    }
    else{$folder = $PWD.Path}

    # Stop the change warnings
    Update-AzConfig -DisplayBreakingChangeWarning $false | Out-Null

    Write-Verbose -Message ('Dumping Workspaces from the "' + (Get-AzContext).Subscription.Name + '" Subscription')

    # Get ML Workspaces
    $workspaces = Get-AzMLWorkspace -ResourceGroupName $ResourceGroupName

    Write-Verbose "\t$($workspaces.Count) Workspace(s) Enumerated"

    $workspaces | ForEach-Object{

        $currentWorkspace = $_.Name

        Write-Verbose "`t`tAttempting to dump data from the $currentWorkspace workspace"

        # Get Workspace Keys
        Write-Verbose "`t`t`tAttempting to dump keys"
        $workspaceKeys = Get-AzMLWorkspaceKey -ResourceGroupName $ResourceGroupName -Name $_.Name
        $workspaceKeys | Out-File -Append "$folder\$currentWorkspace-Keys.txt"

        # Get Workspace Compute Resources
        Write-Verbose "`t`t`t`tAttempting to dump compute data"
        $computes = Get-AzMLWorkspaceCompute -ResourceGroupName $ResourceGroupName -WorkspaceName $_.Name |
            ForEach-Object {
            $propAsObj = $_.Property | ConvertFrom-Json

                [PSCustomObject]@{
                    Name                                 = $_.Name
                    computeType                          = $propAsObj.properties.computeType
                    Id                                   = $_.Id
                    IdentityType                         = $_.IdentityType
                    Location                             = $_.Location
                    createdOn                            = $propAsObj.createdOn
                    modifiedOn                           = $propAsObj.modifiedOn
                    isAttachedCompute                    = $propAsObj.isAttachedCompute
                    disableLocalAuth                     = $propAsObj.disableLocalAuth
                    subnet                               = $propAsObj.properties.subnet.id
                    sshPublicAccess                      = $propAsObj.properties.sshSettings.sshPublicAccess
                    adminUserName                        = $propAsObj.properties.sshSettings.adminUserName
                    sshPort                              = $propAsObj.properties.sshSettings.sshPort
                    publicIpAddress                      = $propAsObj.properties.connectivityEndpoints.publicIpAddress
                    privateIpAddress                     = $propAsObj.properties.connectivityEndpoints.privateIpAddress
                    lastOperation                        = $propAsObj.properties.lastOperation.operationTime
                    schedules                            = $propAsObj.properties.schedules.computeStartStop
                    vmSize                               = $propAsObj.properties.vmSize
                    applicationSharingPolicy             = $propAsObj.properties.applicationSharingPolicy
                    endpointUri                          = $propAsObj.properties.applications.endpointUri
                    state                                = $propAsObj.properties.state
                }
            }
        
        Write-Verbose "`t`t`t$($computes.Count) Compute Resource(s) Enumerated"
        $computes | Out-File -Append "$folder\$currentWorkspace-Computes.txt"

        # Get Workspace Online Endpoints
        Write-Verbose "`t`t`t`tAttempting to dump endpoint data"
        $endpoints = Get-AzMLWorkspaceOnlineEndpoint -ResourceGroupName $ResourceGroupName -WorkspaceName $_.Name |
            ForEach-Object {
                    
                    $propAsObj = $_.EndpointPropertiesBaseProperty | ConvertFrom-Json
                    Write-Verbose "`t`t`t$($endpoints.Count) Endpoint(s) Enumerated"
                    $sysdataAsObj = $_.SystemData | ConvertFrom-json
                    Write-Verbose "`t`t`tAttempting to dump keys"
                    $keys = Get-AzMLWorkspaceOnlineEndpointKey -ResourceGroupName $ResourceGroupName -WorkspaceName $_.Name -Name $_.Name
                
                [PSCustomObject]@{
                    Name                            = $_.Name
                    Id                              = $_.Id
                    Description                     = $_.Description
                    AuthMode                        = $_.AuthMode
                    Type                            = $_.Type
                    ScoringUri                      = $_.ScoringUri
                    SwaggerUri                      = $_.SwaggerUri
                    CreatedBy                       = $sysdataAsObj.createdBy
                    CreatedAt                       = $sysdataAsObj.createdAt
                    LastModifiedAt                  = $sysdataAsObj.lastModifiedAt
                    SystemDataCreatedAt             = $_.SystemDataCreatedAt
                    Onlineendpointid                = $propAsObj.'azureml.onlineendpointid'
                    AzureAsyncOperationUri          = $propAsObj.AzureAsyncOperationUri
                    PrimaryKey                      = $keys.PrimaryKey
                    SecondaryKey                    = $keys.SecondaryKey
                }
            }
        
        Write-Verbose "`t`t`t$($endpoints.Count) Compute Endpoint(s) Enumerated"
        $endpoints | Out-File -Append "$folder\$currentWorkspace-Endpoints.txt"

        # Get Workspace Jobs
        Write-Verbose "`t`t`t`tAttempting to dump jobs data"
        $jobs = Get-AzMLWorkspaceJob -ResourceGroupName $ResourceGroupName -WorkspaceName $_.Name |
            ForEach-Object {

                $propAsObj = $_.Property | ConvertFrom-Json
                Write-Verbose "`t`t`t$($endpoints.Count) Job(s) Enumerated"

                [PSCustomObject]@{
                Name                            = $_.Name
                Id                              = $_.Id
                SystemDataCreatedAt             = $_.SystemDataCreatedAt
                SystemDataCreatedBy             = $_.SystemDataCreatedBy
                jobType                         = $propAsObj.jobType
                endpoint                        = $propAsObj.services.Studio.endpoint
                command                         = $propAsObj.command
                environmentId                   = $propAsObj.environmentId
                outputs                         = $propAsObj.outputs.default
                }

            }

        Write-Verbose "`t`t`t$($jobs.Count) Compute Job(s) Enumerated"
        $computes | Out-File -Append "$folder\$currentWorkspace-Jobs.txt"

    # Get Workspace Models
    $models = Get-AzMLWorkspaceModelContainer -ResourceGroupName $ResourceGroupName -WorkspaceName $_.Name |
        ForEach-Object {

            [PSCustomObject]@{
            Name                            = $_.Name
            Id                              = $_.Id
            SystemDataCreatedAt             = $_.SystemDataCreatedAt
            Type                            = $_.Type
            ProvisioningState               = $_.ProvisioningState
            IsArchived                      = $_.IsArchived
            }

        }

        Write-Verbose "`t`t`t$($models.Count) Compute Model(s) Enumerated"
        $computes | Out-File -Append "$folder\$currentWorkspace-Models.txt"


    # Get Storage Account Keys of a Workspace.
    $storagekey = Get-AzMLWorkspaceStorageAccountKey -ResourceGroupName $ResourceGroupNam -Name $_.Name
    $storagekey | Out-File -Append "$folder\$currentWorkspace-Storagekey.txt"
 
    Write-Verbose "`t`tCompleted dumping of the $currentWorkspace workspace"
    
    }
}
 
