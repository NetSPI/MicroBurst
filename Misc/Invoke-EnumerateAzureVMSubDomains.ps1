<#
    File: Invoke-EnumerateAzureVMSubDomains.ps1
    Author: Renos Nikolaou (@r3n_hat), 2025
    Description: PowerShell function for enumerating Azure Virtual Machines Subdomains.

#>


Function Invoke-EnumerateAzureVMSubDomains {

    <#
            .SYNOPSIS
            PowerShell function for enumerating public Azure Virtual Machines Subdomains.
            .DESCRIPTION
            The function will check for valid [name].[region].cloudapp.azure.com host names via DNS.
            If a valid virtual machines subdomain found, the function will list them out.
            .PARAMETER Base
            The Base name to prepend/append with permutations.
            .PARAMETER Permutations
            Specific permutations file to use. Default is permutations.txt (included in this repo)
            .EXAMPLE
            PS C:\> Invoke-EnumerateAzureVMSubDomains -Base CompanyName -Verbose
            Found -  CompanyName.eastus.cloudapp.azure.com

            Subdomain                                Region                
	        ---------                                -------                
	        CompanyName.eastus.cloudapp.azure.com     East US Virtual Machines

    #>



    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage="Base name to use.")]
        [string]$Base = "",

        [Parameter(Mandatory=$false,
        HelpMessage="Specific permutations file to use.")]
        [string]$Permutations = "$PSScriptRoot\permutations.txt"
    )

    # Define Azure VM Region Hostnames
    $subLookup = @{
    'eastus.cloudapp.azure.com'           = 'East US Virtual Machines';
    'eastus2.cloudapp.azure.com'          = 'East US 2 Virtual Machines';
    'westus.cloudapp.azure.com'           = 'West US Virtual Machines';
    'westus2.cloudapp.azure.com'          = 'West US 2 Virtual Machines';
    'westus3.cloudapp.azure.com'          = 'West US 3 Virtual Machines';
    'centralus.cloudapp.azure.com'        = 'Central US Virtual Machines';
    'northcentralus.cloudapp.azure.com'   = 'North Central US Virtual Machines';
    'southcentralus.cloudapp.azure.com'   = 'South Central US Virtual Machines';
    'westcentralus.cloudapp.azure.com'    = 'West Central US Virtual Machines';
    'northeurope.cloudapp.azure.com'      = 'North Europe (Ireland) Virtual Machines';
    'westeurope.cloudapp.azure.com'       = 'West Europe (Netherlands) Virtual Machines';
    'uksouth.cloudapp.azure.com'          = 'United Kingdom South Virtual Machines';
    'ukwest.cloudapp.azure.com'           = 'United Kingdom West Virtual Machines';
    'francecentral.cloudapp.azure.com'    = 'France Central Virtual Machines';
    'germanywestcentral.cloudapp.azure.com' = 'Germany West Central Virtual Machines';
    'italynorth.cloudapp.azure.com'       = 'Italy North Virtual Machines';
    'norwayeast.cloudapp.azure.com'       = 'Norway East Virtual Machines';
    'polandcentral.cloudapp.azure.com'    = 'Poland Central Virtual Machines';
    'spaincentral.cloudapp.azure.com'     = 'Spain Central Virtual Machines';
    'swedencentral.cloudapp.azure.com'    = 'Sweden Central Virtual Machines';
    'switzerlandnorth.cloudapp.azure.com' = 'Switzerland North Virtual Machines';
    'australiaeast.cloudapp.azure.com'    = 'Australia East Virtual Machines';
    'australiacentral.cloudapp.azure.com' = 'Australia Central Virtual Machines';
    'australiasoutheast.cloudapp.azure.com' = 'Australia Southeast Virtual Machines';
    'centralindia.cloudapp.azure.com'     = 'Central India Virtual Machines';
    'southindia.cloudapp.azure.com'       = 'South India Virtual Machines';
    'japaneast.cloudapp.azure.com'        = 'Japan East Virtual Machines';
    'japanwest.cloudapp.azure.com'        = 'Japan West Virtual Machines';
    'koreacentral.cloudapp.azure.com'     = 'Korea Central Virtual Machines';
    'koreasouth.cloudapp.azure.com'       = 'Korea South Virtual Machines';
    'eastasia.cloudapp.azure.com'         = 'East Asia (Hong Kong) Virtual Machines';
    'southeastasia.cloudapp.azure.com'    = 'Southeast Asia (Singapore) Virtual Machines';
    'newzealandnorth.cloudapp.azure.com'  = 'New Zealand North Virtual Machines';
    'canadacentral.cloudapp.azure.com'    = 'Canada Central Virtual Machines';
    'canadaeast.cloudapp.azure.com'       = 'Canada East Virtual Machines';
    'uaenorth.cloudapp.azure.com'         = 'UAE North Virtual Machines';
    'qatarcentral.cloudapp.azure.com'     = 'Qatar Central Virtual Machines';
    'israelcentral.cloudapp.azure.com'    = 'Israel Central Virtual Machines';
    'southafricanorth.cloudapp.azure.com' = 'South Africa North Virtual Machines';
    'mexicocentral.cloudapp.azure.com'    = 'Mexico Central Virtual Machines';
    'brazilsouth.cloudapp.azure.com'      = 'Brazil South Virtual Machines';
}


    $runningList = @()
    $lookupResult = ""

    if ($Permutations -and (Test-Path $Permutations)) {
        $PermutationContent = Get-Content $Permutations
    } else {
        Write-Verbose "No permutations file found"
    }

    # Create data table to store results
    $TempTbl = New-Object System.Data.DataTable 
    $TempTbl.Columns.Add("Subdomain") | Out-Null
    $TempTbl.Columns.Add("Region") | Out-Null

    $iter = 0
    
    # Check Each Subdomain
    $subLookup.Keys | ForEach-Object {
        $iter++
        $subprogress = ($iter / $subLookup.Count) * 100
        Write-Progress -Status 'Progress..' -Activity "Enumerating $Base subdomains for $_ subdomain" -PercentComplete $subprogress

        # Check the base word
        $lookup = $Base + '.' + $_
        try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false -DnsOnly | select Name | Select-Object -First 1)|Out-Null}catch{}
        if ($lookupResult -ne ""){Write-Verbose "Found $lookup"; $runningList += $lookup; $TempTbl.Rows.Add([string]$lookup,[string]$subLookup[$_]) | Out-Null}
        $lookupResult = ""

        # Check Permutations
        foreach ($word in $PermutationContent) {
            $lookup = $word + $Base + '.' + $_
            try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false -DnsOnly | select Name | Select-Object -First 1)|Out-Null}catch{}
            if ($lookupResult -ne ""){Write-Verbose "Found $lookup"; $runningList += $lookup; $TempTbl.Rows.Add([string]$lookup,[string]$subLookup[$_]) | Out-Null}
            $lookupResult = ""
        
	    # BasePermutation
            $lookup = $Base + $word + '.' + $_
            try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false -DnsOnly | select Name | Select-Object -First 1)|Out-Null}catch{}
            if ($lookupResult -ne ""){Write-Verbose "Found $lookup"; $runningList += $lookup; $TempTbl.Rows.Add([string]$lookup,[string]$subLookup[$_]) | Out-Null}
            $lookupResult = ""

	    # PermutationBase with Hyphens
	        $lookup = $Base + '-' + $word + '.' + $_
            try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false -DnsOnly | select Name | Select-Object -First 1)|Out-Null}catch{}
            if ($lookupResult -ne ""){Write-Verbose "Found $lookup"; $runningList += $lookup; $TempTbl.Rows.Add([string]$lookup,[string]$subLookup[$_]) | Out-Null}
            $lookupResult = ""

	    # BasePermutation with Hyphens
            $lookup = $word + '-' + $Base + '.' + $_
            try{($lookupResult = Resolve-DnsName $lookup -ErrorAction Stop -Verbose:$false -DnsOnly | select Name | Select-Object -First 1)|Out-Null}catch{}
            if ($lookupResult -ne ""){Write-Verbose "Found $lookup"; $runningList += $lookup; $TempTbl.Rows.Add([string]$lookup,[string]$subLookup[$_]) | Out-Null}
            $lookupResult = ""

        }

    }
    $TempTbl | Sort-Object Service
}
