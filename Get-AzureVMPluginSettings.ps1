<#
    File: Get-AzureVMPluginSettings.ps1
    Author: Jake Karnes, NetSPI - 2020
    Description: PowerShell function for dumping information from Azure VM Plugin Settings
#>

Function Get-AzureVMPluginSettings
{
<#
    .SYNOPSIS
        PowerShell function for dumping information from Azure VM Plugin Settings
	.DESCRIPTION
        The function will read all available plugin settings, decrypt protected values (if the required certificate can be found) and return all the settings.		
    .EXAMPLE
        PS C:\> Get-AzureVMPluginSettings

        FullFileName                    : C:\Packages\Plugins\Microsoft.Azure.Security.IaaSAntimalware\1.5.5.9\RuntimeSettings\0.settings
        ProtectedSettingsCertThumbprint : 
        ProtectedSettings               : 
        ProtectedSettingsDecrypted      : 
        PublicSettings                  : {"AntimalwareEnabled":true,"RealtimeProtectionEnabled":"false","ScheduledScanSettings":{...},"Exclusions":{...}}

        FullFileName                    : C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\RuntimeSettings\0.settings
        ProtectedSettingsCertThumbprint : 23B8893CD7712293DF75FE0A19AFECF1CFF0119D
        ProtectedSettings               : MIIB8AYJKoZIhvcNAQc...UNMih8=
        ProtectedSettingsDecrypted      : {"fileUris":["http://.../netspi/launcher.ps1"]}
        PublicSettings                  : {"commandToExecute":"powershell -ExecutionPolicy Unrestricted -file launcher.ps1 "}

        FullFileName                    : C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\1.1.3\RuntimeSettings\1.settings
        ProtectedSettingsCertThumbprint : C85DD4C5E9614D2958C66B3CE8AF383034D6193E
        ProtectedSettings               : MIIBsAYJKoZI...B+E0ZomM6gAghguFCQ28f2w==
        ProtectedSettingsDecrypted      : 
        PublicSettings                  : {"script":["whoami"]}
#>

    #Load dependency
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null

    #Get all runtime settings files.
    $settingsFiles = Get-ChildItem -Path C:\Packages\Plugins\*\*\RuntimeSettings -Include *.settings -Recurse
    foreach($settingsFile in $settingsFiles){
	    #Convert file contents to JSON
	    $settingsJson = Get-Content $settingsFile | Out-String | ConvertFrom-Json

	    #For each runTimeSetting (there should only be one, but it is an array)
	    foreach($setting in $settingsJson.runtimeSettings){
        
            #Build a container object which we'll output later
            $outputObj = "" | Select-Object -Property FullFileName,ProtectedSettingsCertThumbprint,ProtectedSettings,ProtectedSettingsDecrypted,PublicSettings
            $outputObj.FullFileName = $settingsFile.FullName
            $outputObj.ProtectedSettingsCertThumbprint = $setting.handlerSettings.protectedSettingsCertThumbprint
            $outputObj.ProtectedSettings = $setting.handlerSettings.protectedSettings
            $outputObj.PublicSettings = $setting.handlerSettings.publicSettings | ConvertTo-Json -Compress 

		    #Extract the thumbprint
		    $thumbprint = $setting.handlerSettings.protectedSettingsCertThumbprint

		    #Only continue if a thumbprint is specified. Not all settings files have protected properties
		    if($thumbprint){
			    #Search all certificates, keeping the one with the corresponding thumbprint
			    $cert = Get-ChildItem -Path 'Cert:\' -Recurse | where {$_.Thumbprint -eq $thumbprint}

			    #Check if we found a cert, we might not find a corresponding cert if running as a lower privileged user
			    if($cert){
				    #Check that the cert has a private key we can access. We can't decrypt without the private key
				    if($cert.HasPrivateKey){

					    #Decode the protected settings into a byte array
					    $bytes =  [System.Convert]::FromBase64String($outputObj.ProtectedSettings)

					    #Decrypt the bytes using the cert's private key
					    $envelope = New-Object Security.Cryptography.Pkcs.EnvelopedCms
					    $envelope.Decode($bytes)
					    $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection $cert
					    $envelope.Decrypt($col)
					    $decryptedContent = [text.encoding]::UTF8.getstring($envelope.ContentInfo.Content)

                        #Add the decrypted settings to our container. The JSON conversion ensures that whitespace is minimized
                        $outputObj.ProtectedSettingsDecrypted = $decryptedContent | ConvertFrom-Json| ConvertTo-Json -Compress 
				    }
			    }
		    }

        #Output our gathered setting info
        Write-Output $outputObj
	    }
    }
}