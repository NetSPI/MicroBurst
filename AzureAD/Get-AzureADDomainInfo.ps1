<#
    File: Get-AzureADDomainInfo.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2020
    Description: PowerShell functions for enumerating information from AzureAD domains.
#>


# Check if the AzureAD Module is installed and imported
if(!(Get-Module AzureAD)){
    try{Import-Module AzureAD -ErrorAction Stop}
    catch{Install-Module -Name AzureAD -Confirm}
    }


Function Get-AzureADDomainInfo
{
<#

    .SYNOPSIS
        PowerShell function for dumping information from an AzureAD domain via an authenticated AzureAD connection.
	.DESCRIPTION
		The function will dump available information for an AzureAD domain out to CSV files in the -folder parameter (or current) directory.
    .PARAMETER folder
        The folder to output to.   
    .PARAMETER Users
        The flag for dumping the list of AzureAD-Users. 
    .PARAMETER Groups
        The flag for dumping the list of AzureAD-Groups. Disable ('N') if you just want to get a user list.
	.EXAMPLE
        PS C:\> Get-AzureADDomainInfo -Verbose
        VERBOSE: Currently logged in via AzureAD as kfosaaen@netspi.com
        VERBOSE: 	Use Connect-AzureAD to change your user
        VERBOSE: Getting Domains...
        VERBOSE: 	3 Domains were found.
        VERBOSE: Getting Domain Users...
        VERBOSE: 	255 Domain Users were found.
        VERBOSE: Getting Domain Groups...
        VERBOSE: 	204 Domain Groups were found.
        VERBOSE: Getting Domain Users for each group...
        VERBOSE: 	Domain Group Users were enumerated for 204 groups.
        VERBOSE: Getting AzureAD Applications...
        VERBOSE: 	41 applications were enumerated.
        VERBOSE: Getting AzureADMS Applications...
        VERBOSE: 	41 MS applications were enumerated.
        VERBOSE: Getting Domain Service Principals...
        VERBOSE: 	500 service principals were enumerated.
        VERBOSE: All done with AzureAD tasks.
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Folder to output to.")]
        [string]$folder,
        [parameter(Mandatory=$false)]
        [ValidateSet("Y","N")]
        [String]$Users = "Y",
        [parameter(Mandatory=$false)]
        [ValidateSet("Y","N")]
        [String]$Groups = "Y"
    )

    try{$AZADAccount = (Get-AzureADCurrentSessionInfo -ErrorAction Stop).Account.Id}
    catch{Write-Verbose "No active connections to the AzureAD service"; Write-Verbose "Prompting for Authentication"}

    if ($AZADAccount -eq $null){
        # Authenticate to AzureAD
        try{Connect-AzureAD -ErrorAction Stop}
        catch{Write-Verbose "Failed to connect to AzureAD service"; break}
    }

    $AZADAccount = (Get-AzureADCurrentSessionInfo -ErrorAction Stop).Account.Id
    Write-Verbose "Currently logged in via AzureAD as $AZADAccount"; Write-Verbose `t'Use Connect-AzureAD to change your user'

    # Folder Parameter Checking
    if ($folder){if(Test-Path $folder){if(Test-Path $folder"\AzureAD"){}else{New-Item -ItemType Directory $folder"\AzureAD"|Out-Null}}else{New-Item -ItemType Directory $folder|Out-Null ; New-Item -ItemType Directory $folder"\AzureAD"|Out-Null}}
    else{if(Test-Path AzureAD){}else{New-Item -ItemType Directory AzureAD|Out-Null};$folder=".\"}

    # Get/Write Domains
    Write-Verbose "Getting Domains..."
    $domains = Get-AzureADDomain
    $domains | select Name,IsRoot,IsVerified,AuthenticationType,AvailabilityStatus,ForceDeleteState,IsAdminManaged,IsDefault,IsDefaultForCloudRedirections,IsInitial,State | Export-Csv -NoTypeInformation -LiteralPath $folder"\AzureAD\Domains.CSV"
    $domainCount = $domains.Count
    Write-Verbose "`t$domainCount Domains were found."

    if ($Users -eq "Y"){   
        # Get/Write Users for each domain
        Write-Verbose "Getting Domain Users..."
        
        # List Users
        $azureADUsers = Get-AzureADUser -All $true

        # List Directory Roles
        $entraIDRoles = Get-AzureADDirectoryRole

        # Initialize an empty map to store user roles
        $userRolesMap = @{}
        # Loop through each role in the Azure AD roles set
        foreach ($role in $entraIDRoles) {
            
            # Retrieve the members associated with each role
            $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
            
            # Loop through each member associated with the role
            foreach ($member in $members) {
                
                # If the user is not already in the map, initialize an empty list
                if (-not $userRolesMap.ContainsKey($member.ObjectId)) {
                    $userRolesMap[$member.ObjectId] = @()
                }
                
                # Add the role name to the user's list of roles
                $userRolesMap[$member.ObjectId] += $role.DisplayName
            }
        }
        
        # Retrieve all Azure AD groups
        $azureADGroups = Get-AzureADGroup -All $true
        
        # Initialize an empty map to store group memberships for users
        $userGroupsMap = @{}
        
        # Loop through each group in the Azure AD groups
        foreach ($group in $azureADGroups) {
            # Retrieve the members of each grou
            $members = Get-AzureADGroupMember -ObjectId $group.ObjectId
            
            # Loop through each member of the group
            foreach ($member in $members) {
                
                # If the user is not already in the map, initialize an empty list
                if (-not $userGroupsMap.ContainsKey($member.ObjectId)) {
                    $userGroupsMap[$member.ObjectId] = @()
                }
                
                # Add the group name to the user's list of groups
                $userGroupsMap[$member.ObjectId] += $group.DisplayName
            }
        }
        
        # Create an output object for each Azure AD user with their roles and groups
        $exportUsers = $azureADUsers | ForEach-Object {
            
            # Retrieve the roles assigned to the user and join them into a single string
            $AzureADroles = $userRolesMap[$_.ObjectId] -join "; "
            
            # Retrieve the groups the user belongs to and join them into a single string
            $AzureADgroups = if ($userGroupsMap.ContainsKey($_.ObjectId) -and $userGroupsMap[$_.ObjectId]) { 
            $userGroupsMap[$_.ObjectId] -join "; " 
            } else { 
                ""
            }
            
            # Create a custom object to store the user's details and export them
            [PSCustomObject]@{
                DisplayName                       = $_.DisplayName
                UserPrincipalName                 = $_.UserPrincipalName
                ObjectId                          = $_.ObjectId
                DirectoryRoles                    = $AzureADroles
                ADGroups                          = $AzureADgroups                
                ObjectType                        = $_.ObjectType
                AccountEnabled                    = $_.AccountEnabled
                AgeGroup                          = $_.AgeGroup
                City                              = $_.City
                CompanyName                       = $_.CompanyName
                ConsentProvidedForMinor           = $_.ConsentProvidedForMinor
                Country                           = $_.Country
                CreationType                      = $_.CreationType
                Department                        = $_.Department
                DirSyncEnabled                    = $_.DirSyncEnabled
                FacsimileTelephoneNumber          = $_.FacsimileTelephoneNumber
                GivenName                         = $_.GivenName
                Surname                           = $_.Surname
                IsCompromised                     = $_.IsCompromised
                ImmutableId                       = $_.ImmutableId
                JobTitle                          = $_.JobTitle
                LastDirSyncTime                   = $_.LastDirSyncTime
                LegalAgeGroupClassification       = $_.LegalAgeGroupClassification
                Mail                              = $_.Mail
                MailNickName                      = $_.MailNickName
                Mobile                            = $_.Mobile
                OnPremisesSecurityIdentifier      = $_.OnPremisesSecurityIdentifier
                PasswordPolicies                  = $_.PasswordPolicies
                PasswordProfile                   = $_.PasswordProfile
                PhysicalDeliveryOfficeName        = $_.PhysicalDeliveryOfficeName
                PostalCode                        = $_.PostalCode
                PreferredLanguage                 = $_.PreferredLanguage
                RefreshTokensValidFromDateTime    = $_.RefreshTokensValidFromDateTime
                ShowInAddressList                 = $_.ShowInAddressList
                SipProxyAddress                   = $_.SipProxyAddress
                State                             = $_.State
                StreetAddress                     = $_.StreetAddress
                TelephoneNumber                   = $_.TelephoneNumber
                UsageLocation                     = $_.UsageLocation
                UserState                         = $_.UserState
                UserStateChangedOn                = $_.UserStateChangedOn
                UserType                          = $_.UserType

            }
        }

        # Export to CSV
        $exportUsers | Export-Csv -NoTypeInformation -LiteralPath "$folder\AzureAD\AzureAD_Users.CSV"
    
        $azureADUserscount = $azureADUsers.Count
        Write-Verbose "`t$azureADUserscount Domain Users were found."
    }
    
    if ($Groups -eq "Y"){
        # Get/Write Groups
        Write-Verbose "Getting Domain Groups..."
    
        # Create Folder
        if(Test-Path $folder"\AzureAD\Groups"){}
        else{New-Item -ItemType Directory $folder"\AzureAD\Groups" | Out-Null}

        # List Groups
        $groupList = Get-AzureADGroup -All 1
        $groupCount = $groupList.Count
        Write-Verbose "`t$groupCount Domain Groups were found."
        if($groupCount -gt 0){
            Write-Verbose "Getting Domain Users for each group..."
            $groupList | select DisplayName,Description,DeletionTimestamp,ObjectId,ObjectType,DirSyncEnabled,LastDirSyncTime,Mail,MailEnabled,MailNickName,OnPremisesSecurityIdentifier,SecurityEnabled | Export-Csv -NoTypeInformation -LiteralPath $folder"\AzureAD\Groups.CSV"

            $groupList | ForEach-Object {

                # Clean up the folder names for invalid path characters
                $displayName = $_.DisplayName
                $charlist = [string[]][System.IO.Path]::GetInvalidFileNameChars()
                foreach ($char in $charlist){$displayName = $displayName.replace($char,'.')}

                # Get group members and export to CSV
                Get-AzureADGroupMember -All 1 -ObjectId $_.ObjectId | select DisplayName,Mail,MailNickName,Mobile,DeletionTimestamp,ObjectId,ObjectType,AccountEnabled,AgeGroup,City,CompanyName,ConsentProvidedForMinor,Country,CreationType,Department,DirSyncEnabled,FacsimileTelephoneNumber,GivenName,IsCompromised,ImmutableId,JobTitle,LastDirSyncTime,LegalAgeGroupClassification,OnPremisesSecurityIdentifier,PasswordPolicies,PasswordProfile,PhysicalDeliveryOfficeName,PostalCode,PreferredLanguage,RefreshTokensValidFromDateTime,ShowInAddressList,SipProxyAddress,State,StreetAddress,Surname,TelephoneNumber,UsageLocation,UserPrincipalName,UserState,UserStateChangedOn,UserType | Export-Csv -NoTypeInformation -LiteralPath (-join($folder,"\AzureAD\Groups\",$displayName,"_Users.CSV"))
            }
            Write-Verbose "`tDomain Group Users were enumerated for $groupCount groups."
        }
    }

    # Get/Write AzureAD Applications
    Write-Verbose "Getting AzureAD Applications..."
    $azureADApps = Get-AzureADApplication -All 1
    $azureADApps | select DisplayName,Homepage,DeletionTimestamp,ObjectId,ObjectType,AllowGuestsSignIn,AllowPassthroughUsers,AppId,AppLogoUrl,AvailableToOtherTenants,ErrorUrl,GroupMembershipClaims,InformationalUrls,IsDeviceOnlyAuthSupported,IsDisabled,LogoutUrl,Oauth2AllowImplicitFlow,Oauth2AllowUrlPathMatching,Oauth2RequirePostResponse,OptionalClaims,ParentalControlSettings,PreAuthorizedApplications,PublicClient,PublisherDomain,RecordConsentConditions,SamlMetadataUrl,SignInAudience,WwwHomepage | Export-Csv -NoTypeInformation -LiteralPath $folder"\AzureAD\Domain_Applications.CSV"
    $azureADAppsCount = $azureADApps.Count
    Write-Verbose "`t$azureADAppsCount applications were enumerated."

    # Get/Write AzureADMS Applications
    Write-Verbose "Getting AzureADMS Applications..."
    $azureADMSApps = Get-AzureADMSApplication -All 1
    $azureADMSApps | select DisplayName,Id,OdataType,Api,AppId,ApplicationTemplateId,GroupMembershipClaims,IsDeviceOnlyAuthSupported,IsFallbackPublicClient,CreatedDateTime,DeletedDateTime,Info,OptionalClaims,ParentalControlSettings,PublicClient,PublisherDomain,SignInAudience,TokenEncryptionKeyId,Web | Export-Csv -NoTypeInformation -LiteralPath $folder"\AzureAD\Domain_MSApplications.CSV"
    $azureADMSAppsCount = $azureADMSApps.Count
    Write-Verbose "`t$azureADMSAppsCount MS applications were enumerated."

    # Get/Write Service Principals
    Write-Verbose "Getting Domain Service Principals..."
    $principals = Get-AzureADServicePrincipal -All 1
    $principals | select DisplayName,AppDisplayName,DeletionTimestamp,ObjectId,ObjectType,AccountEnabled,AppId,AppOwnerTenantId,AppRoleAssignmentRequired,ErrorUrl,Homepage,LogoutUrl,PreferredTokenSigningKeyThumbprint,PublisherName,SamlMetadataUrl,ServicePrincipalType | Export-Csv -NoTypeInformation -LiteralPath $folder"\AzureAD\Domain_SPNs.CSV"
    $principalCount = $principals.Count
    Write-Verbose "`t$principalCount service principals were enumerated."

    Write-Verbose "All done with AzureAD tasks.`n"
}
