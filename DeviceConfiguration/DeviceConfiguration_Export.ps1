
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
[cmdletbinding()]
param (
    [Parameter(Mandatory = $false)][String]$ExportPath,
    [Parameter(Mandatory = $false)][String]$UserPrincipalName,
    [Parameter(Mandatory = $false)][Switch]$UseGraphAPIModule,
    [Parameter(Mandatory = $false)][Switch]$UseGraphAPIREST,
    [Parameter(Mandatory = $false)][Switch]$DoNotCheckForModuleUpdates,
    [Parameter(Mandatory = $false)][Switch]$DoNotIncludeDateInFileNames
)

#TODO: rename this script to Export-DeviceConfigurationProfiles to comply with verb-noun naming convention

$strThisScriptVersionNumber = [version]'1.2.20220903.0'

$script:VerbosePreferenceAtStartOfScript = $VerbosePreference

####################################################

function Get-AuthToken {
    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>

    [cmdletbinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        $UserUPN
    )

    $mailaddressUserUPN = New-Object 'System.Net.Mail.MailAddress' -ArgumentList $UserUPN

    $strDomainName = $mailaddressUserUPN.Host

    Write-Verbose 'Checking for AzureAD module...'

    $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
    $arrModuleAzureAD = @(Get-Module -Name 'AzureAD' -ListAvailable)
    $VerbosePreference = $script:VerbosePreferenceAtStartOfScript

    if ($arrModuleAzureAD.Count -eq 0) {
        Write-Verbose 'AzureAD PowerShell module not found, looking for AzureADPreview'
        $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
        $arrModuleAzureAD = @(Get-Module -Name 'AzureADPreview' -ListAvailable)
        $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
    }

    if ($arrModuleAzureAD.Count -eq 0) {
        Write-Error ('AzureAD Powershell module not installed...' + "`n" + 'Install by running "Install-Module AzureAD" or "Install-Module AzureADPreview" from an elevated PowerShell prompt' + "`n" + 'Script cannot continue...')
        exit
    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if ($arrModuleAzureAD.Count -gt 1) {
        $versionNewestInstalledAzureADModule = (($arrModuleAzureAD + $arrModuleAzureADPreview) | ForEach-Object { [version]($_.Version) } | Sort-Object)[-1]

        $arrModuleNewestInstalledAzureAD = @(($arrModuleAzureAD + $arrModuleAzureADPreview) | Where-Object { ([version]($_.Version)) -eq $versionNewestInstalledAzureADModule })

        # In the event there are multiple installations of the same version, reduce to a
        # single instance of the module
        if ($arrModuleNewestInstalledAzureAD.Count -gt 1) {
            $moduleAzureAD = @($arrModuleNewestInstalledAzureAD | Select-Object -Unique)[0]
        } else {
            $moduleAzureAD = $arrModuleNewestInstalledAzureAD[0]
        }
    } else {
        $moduleAzureAD = $arrModuleAzureAD[0]
    }

    $strPathToADALDLL = Join-Path $moduleAzureAD.ModuleBase 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
    $strPathToADALFormsDLL = Join-Path $moduleAzureAD.ModuleBase 'Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll'

    [System.Reflection.Assembly]::LoadFrom($strPathToADALDLL) | Out-Null

    [System.Reflection.Assembly]::LoadFrom($strPathToADALFormsDLL) | Out-Null

    $strMicrosoftIntunePowerShellAppID = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547'

    $strRedirectURI = 'urn:ietf:wg:oauth:2.0:oob'

    $strResourceAppIDURI = 'https://graph.microsoft.com'

    $strAuthority = ('https://login.microsoftonline.com/' + $strDomainName)

    try {
        $authenticationcontext = New-Object 'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext' -ArgumentList $strAuthority

        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

        $platformparameters = New-Object 'Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters' -ArgumentList 'Auto'

        $useridentifier = New-Object 'Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier' -ArgumentList ($UserUPN, 'OptionalDisplayableId')

        $authResult = $authenticationcontext.AcquireTokenAsync($strResourceAppIDURI, $strMicrosoftIntunePowerShellAppID, $strRedirectURI, $platformparameters, $useridentifier).Result

        # If the accesstoken is valid then create the authentication header

        if ($authResult.AccessToken) {
            # Creating header for Authorization token

            $authHeader = @{
                'Content-Type' = 'application/json'
                'Authorization' = 'Bearer ' + $authResult.AccessToken
                'ExpiresOn' = $authResult.ExpiresOn
            }

            return $authHeader
        } else {
            Write-Output 'Error: Authorization Access Token is null, please re-run authentication...'
            break
        }
    } catch {
        Write-Output ('An error occurred getting an authorization token: ' + $_.Exception.Message + ' ' + $_.Exception.ItemName)
        break
    }
}

####################################################

function Test-StringIsGUID {
    <#
    .SYNOPSIS
    This function is used to test if a string is a valid GUID
    .DESCRIPTION
    The function tests if a string is a valid GUID
    .EXAMPLE
    Test-StringIsGUID -GUID '12345678-1234-1234-1234-123456789012'
    Returns $true
    .NOTES
    NAME: Test-IsGUID
    #>

    [cmdletbinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$GUID
    )

    $guidTest = [guid]::Empty
    $boolResult = [guid]::TryParse($GUID, [ref]$guidTest)

    return $boolResult
}

function Get-AndroidEnterpriseOEMConfigDeviceConfigurationProfile {
    <#
    .SYNOPSIS
    This function is used to get device configuration profiles from the Graph API REST interface that target Android Enterprise OEMConfigs.
    .DESCRIPTION
    The function connects to the Graph API interface and gets any device configuration profiles built targeting Android Enterprise OEMConfigs.
    .EXAMPLE
    Get-AndroidEnterpriseOEMConfigDeviceConfigurationProfile
    Returns any Android Enterprise OEMConfig device configuration profiles configured in Intune
    .NOTES
    Filters to just microsoft.graph.androidManagedStoreAppConfiguration objects where appSupportsOemConfig -eq $true
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIModule,
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIREST
    )

    if (($UseGraphAPIModule.IsPresent) -or ($UseGraphAPIREST.IsPresent -eq $false)) {
        # Either the user specified to use the Graph API Module or the user did not specify
        # to use the Graph API REST interface
        $boolUseGraphAPIModule = $true
    } else {
        $boolUseGraphAPIModule = $false
    }

    if ($boolUseGraphAPIModule) {
        #TODO: Using the Graph API Module approach
        # Get-MgDeviceAppMgtMobileAppConfiguration -Filter "microsoft.graph.androidManagedStoreAppConfiguration/appSupportsOemConfig%20eq%20true"
    } else {
        # Using the Graph API REST approach
        $strGraphAPIVersion = 'beta'
        $strDCPResource = 'deviceAppManagement/mobileAppConfigurations'
        $strGraphAPIQueryString = '$filter=microsoft.graph.androidManagedStoreAppConfiguration/appSupportsOemConfig%20eq%20true'

        try {
            $strURI = 'https://graph.microsoft.com/' + $strGraphAPIVersion + '/' + $strDCPResource + '?' + $strGraphAPIQueryString
            $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            return (Invoke-RestMethod -Uri $strURI -Headers $global:hashtableAuthToken -Method Get).Value
            $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
        } catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            if ($null -ne $script:versionPowerShell) {
                if ($script:versionPowerShell -ge [version]'5.0') {
                    Write-Information ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
                } else {
                    Write-Verbose ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
                }
            } else {
                Write-Verbose ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            }
            return $null
        }
    }
}

function Get-SettingsCatalogBasedDeviceConfigurationProfile {
    <#
    .SYNOPSIS
    This function is used to get settings catalog-based device configuration profiles from the Graph API REST interface.
    .DESCRIPTION
    The function connects to the Graph API interface and gets any settings catalog-based device configuration profiles.
    .EXAMPLE
    Get-SettingsCatalogBasedDeviceConfigurationProfile
    Returns any settings catalog-based device configuration profiles configured in Intune.
    A non-exhaustive lists of these types of configuration profiles are:
    macOS - Settings Catalog
    Win10+ - Settings Catalog
    .NOTES
    This function filters the results using the following filter:
    (platforms eq 'windows10' or platforms eq 'macOS' or platforms eq 'iOS') and (technologies eq 'mdm' or technologies eq 'windows10XManagement' or technologies eq 'appleRemoteManagement') and (templateReference/templateFamily eq 'none')

    This function does not retrieve the following device configuration profiles (note: list is non-exhaustive):
    macOS - Templates - Custom
    macOS - Templates - Device Features
    macOS - Templates - Device Restrictions
    macOS - Templates - Endpoint Protection
    macOS - Templates - Extensions
    macOS - Templates - PKCS Certificate
    macOS - Templates - PKCS Imported Certificate
    macOS - Templates - Preference File
    macOS - Templates - SCEP Certificate
    macOS - Templates - Trusted Certificate
    macOS - Templates - VPN
    macOS - Templates - Wi-Fi
    macOS - Templates - Wired Network
    Win10+ - Templates - Administrative Templates
    Win10+ - Templates - Custom
    Win10+ - Templates - Delivery Optimization
    Win10+ - Templates - Device Firmware Configuration Interface
    Win10+ - Templates - Device Restrictions
    Win10+ - Templates - Device Restrictions (Win10 Team)
    Win10+ - Templates - Domain Join
    Win10+ - Templates - Edition Upgrade and Mode Switch
    Win10+ - Templates - Email
    Win10+ - Templates - Endpoint Protection
    Win10+ - Templates - Identity Protection
    Win10+ - Templates - Imported Administrative Templates
    Win10+ - Templates - Kiosk
    Win10+ - Templates - MS Defender for Endpoint
    Win10+ - Templates - Network Boundary
    Win10+ - Templates - PKCS Certificate
    Win10+ - Templates - PKCS Imported Certificate
    Win10+ - Templates - SCEP Certificate
    Win10+ - Templates - Secure Assessment (Education)
    Win10+ - Templates - Shared Multi-User Device
    Win10+ - Templates - Trusted Certificate
    Win10+ - Templates - VPN
    Win10+ - Templates - Wi-Fi
    Win10+ - Templates - Windows Health Monitoring
    Win10+ - Templates - Wired Network
    Win8.1+ - Device Restriction
    Win8.1+ - SCEP Certificate
    Win8.1+ - Trusted Certificate
    Win8.1+ - VPN
    Win8.1+ - Wi-Fi
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIModule,
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIREST
    )

    if (($UseGraphAPIModule.IsPresent) -or ($UseGraphAPIREST.IsPresent -eq $false)) {
        # Either the user specified to use the Graph API Module or the user did not specify
        # to use the Graph API REST interface
        $boolUseGraphAPIModule = $true
    } else {
        $boolUseGraphAPIModule = $false
    }

    if ($boolUseGraphAPIModule) {
        #TODO: Using the Graph API Module approach
        # Get-MgDeviceManagementConfigurationPolicy -Top 1000 -Filter "(platforms%20eq%20%27windows10%27%20or%20platforms%20eq%20%27macOS%27%20or%20platforms%20eq%20%27iOS%27)%20and%20(technologies%20eq%20%27mdm%27%20or%20technologies%20eq%20%27windows10XManagement%27%20or%20technologies%20eq%20%27appleRemoteManagement%27)%20and%20(templateReference/templateFamily%20eq%20%27none%27)" 
    } else {
        # Using the Graph API REST approach
        $strGraphAPIVersion = 'beta'
        $strDCPResource = 'deviceManagement/configurationPolicies'
        $strGraphAPIQueryString = '$filter=(platforms%20eq%20%27windows10%27%20or%20platforms%20eq%20%27macOS%27%20or%20platforms%20eq%20%27iOS%27)%20and%20(technologies%20eq%20%27mdm%27%20or%20technologies%20eq%20%27windows10XManagement%27%20or%20technologies%20eq%20%27appleRemoteManagement%27)%20and%20(templateReference/templateFamily%20eq%20%27none%27)'

        try {
            $strURI = 'https://graph.microsoft.com/' + $strGraphAPIVersion + '/' + $strDCPResource + '?' + $strGraphAPIQueryString
            $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            $arrPSCustomObjectSettingsCatalogBasedProfiles = @((Invoke-RestMethod -Uri $strURI -Headers $global:hashtableAuthToken -Method Get).Value)
            $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
        } catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            if ($versionPowerShell -ge [version]'5.0') {
                Write-Information ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            } else {
                Write-Verbose ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            }
            return
        }

        $arraylistPSCustomObjectSettingsCatalogBasedProfilesForOutput = New-Object System.Collections.ArrayList
        foreach ($pscustomobjectSettingsCatalogBasedProfile in $arrPSCustomObjectSettingsCatalogBasedProfiles) {
            $strDeviceConfigurationProfileID = $pscustomobjectSettingsCatalogBasedProfile.id

            $arrPSCustomObjectSettings = @(Get-SettingsCatalogBasedDeviceConfigurationProfileSetting -DeviceConfigurationProfileID $strDeviceConfigurationProfileID -UseGraphAPIModule:$UseGraphAPIModule -UseGraphAPIREST:$UseGraphAPIREST)
            $hashtableSettings = @{}
            foreach ($pscustomobjectSetting in $arrPSCustomObjectSettings) {
                $strSettingID = $pscustomobjectSetting.id
                $hashtableSettings.Add($strSettingID, $pscustomobjectSetting)
            }
            $pscustomobjectSettingsCatalogBasedProfile | Add-Member -MemberType NoteProperty -Name 'settings' -Value $hashtableSettings
            [void]($arraylistPSCustomObjectSettingsCatalogBasedProfilesForOutput.Add($pscustomobjectSettingsCatalogBasedProfile))
        }
        return $arraylistPSCustomObjectSettingsCatalogBasedProfilesForOutput.ToArray()
    }
}

function Get-SettingsCatalogBasedDeviceConfigurationProfileSetting {
    <#
    .SYNOPSIS
    This function is used to get the settings in a settings catalog-based device
    configuration profiles from the Graph API REST interface.
    .DESCRIPTION
    The function connects to the Graph API interface and gets any settings for a
    settings catalog-based device configuration profiles.
    .EXAMPLE
    Get-SettingsCatalogBasedDeviceConfigurationProfileSetting -DeviceConfigurationProfileID 'b0c0b0c0-b0c0-b0c0-b0c0-b0c0b0c0b0c0'

    This example gets the settings for the device configuration profile with the ID
    'b0c0b0c0-b0c0-b0c0-b0c0-b0c0b0c0b0c0'.
    .NOTES
    Not intended for end users
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIModule,
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIREST,
        [Parameter(Mandatory = $false)][string]$DeviceConfigurationProfileID
    )

    if (($UseGraphAPIModule.IsPresent) -or ($UseGraphAPIREST.IsPresent -eq $false)) {
        # Either the user specified to use the Graph API Module or the user did not specify
        # to use the Graph API REST interface
        $boolUseGraphAPIModule = $true
    } else {
        $boolUseGraphAPIModule = $false
    }

    if ($boolUseGraphAPIModule) {
        #TODO: Using the Graph API Module approach
        # Get-MgDeviceManagementConfigurationPolicySetting -DeviceManagementConfigurationPolicyId $DeviceConfigurationProfileID -ExpandProperty "settingDefinitions"
    } else {
        # Using the Graph API REST approach
        $strGraphAPIVersion = 'beta'
        $strDCPResource = 'deviceManagement/configurationPolicies/' + $DeviceConfigurationProfileID + '/settings?$expand=settingDefinitions'

        try {
            $strURI = 'https://graph.microsoft.com/' + $strGraphAPIVersion + '/' + $strDCPResource
            $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            return (Invoke-RestMethod -Uri $strURI -Headers $global:hashtableAuthToken -Method Get).Value
            $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
        } catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            if ($versionPowerShell -ge [version]'5.0') {
                Write-Information ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            } else {
                Write-Verbose ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            }
            return $null
        }
    }
}

function Get-GroupPolicyBasedDeviceConfigurationProfile {
    <#
    .SYNOPSIS
    This function is used to get Group Policy-based configuration profiles from the
    Graph API REST interface.
    .DESCRIPTION
    The function connects to the Graph API interface and gets any Group Policy-based
    device configuration profiles.
    A non-exhaustive list of the device configuration profiles retrieved by this
    function are:
    Win10+ - Templates - Administrative Templates
    Win10+ - Templates - Imported Administrative Templates
    .EXAMPLE
    Get-TemplateBasedDeviceConfigurationProfile
    Returns any device configuration profiles configured in Intune
    .NOTES
    This function does not retrieve the following device configuration profiles (note:
    list is non-exhaustive):
    macOS - Settings Catalog
    macOS - Templates - Custom
    macOS - Templates - Device Features
    macOS - Templates - Device Restrictions
    macOS - Templates - Endpoint Protection
    macOS - Templates - Extensions
    macOS - Templates - PKCS Certificate
    macOS - Templates - PKCS Imported Certificate
    macOS - Templates - Preference File
    macOS - Templates - SCEP Certificate
    macOS - Templates - Trusted Certificate
    macOS - Templates - VPN
    macOS - Templates - Wi-Fi
    macOS - Templates - Wired Network
    Win10+ - Settings Catalog
    Win10+ - Templates - Custom
    Win10+ - Templates - Delivery Optimization
    Win10+ - Templates - Device Firmware Configuration Interface
    Win10+ - Templates - Device Restrictions
    Win10+ - Templates - Device Restrictions (Win10 Team)
    Win10+ - Templates - Domain Join
    Win10+ - Templates - Edition Upgrade and Mode Switch
    Win10+ - Templates - Email
    Win10+ - Templates - Endpoint Protection
    Win10+ - Templates - Identity Protection
    Win10+ - Templates - Kiosk
    Win10+ - Templates - MS Defender for Endpoint
    Win10+ - Templates - Network Boundary
    Win10+ - Templates - PKCS Certificate
    Win10+ - Templates - PKCS Imported Certificate
    Win10+ - Templates - SCEP Certificate
    Win10+ - Templates - Secure Assessment (Education)
    Win10+ - Templates - Shared Multi-User Device
    Win10+ - Templates - Trusted Certificate
    Win10+ - Templates - VPN
    Win10+ - Templates - Wi-Fi
    Win10+ - Templates - Windows Health Monitoring
    Win10+ - Templates - Wired Network
    Win8.1+ - Device Restriction
    Win8.1+ - SCEP Certificate
    Win8.1+ - Trusted Certificate
    Win8.1+ - VPN
    Win8.1+ - Wi-Fi
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIModule,
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIREST
    )

    if (($UseGraphAPIModule.IsPresent) -or ($UseGraphAPIREST.IsPresent -eq $false)) {
        # Either the user specified to use the Graph API Module or the user did not specify
        # to use the Graph API REST interface
        $boolUseGraphAPIModule = $true
    } else {
        $boolUseGraphAPIModule = $false
    }

    if ($boolUseGraphAPIModule) {
        #TODO: Using the Graph API Module approach
        # Get-MgDeviceManagementGroupPolicyConfiguration
    } else {
        # Using the Graph API REST approach
        $strGraphAPIVersion = 'beta'
        $strDCPResource = 'deviceManagement/groupPolicyConfigurations'

        try {
            $strURI = 'https://graph.microsoft.com/' + $strGraphAPIVersion + '/' + $strDCPResource
            $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            $arrPSCustomObjectGroupPolicyBasedProfiles = @((Invoke-RestMethod -Uri $strURI -Headers $global:hashtableAuthToken -Method Get).Value)
            $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
        } catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            if ($versionPowerShell -ge [version]'5.0') {
                Write-Information ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            } else {
                Write-Verbose ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            }
            return
        }

        $arraylistPSCustomObjectGroupPolicyBasedProfilesForOutput = New-Object System.Collections.ArrayList
        foreach ($pscustomobjectGroupPolicyBasedProfile in $arrPSCustomObjectGroupPolicyBasedProfiles) {
            $strDeviceConfigurationProfileID = $pscustomobjectGroupPolicyBasedProfile.id

            $arrDefinitionValues = @(Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValue -DeviceConfigurationProfileID $strDeviceConfigurationProfileID -UseGraphAPIModule:$UseGraphAPIModule -UseGraphAPIREST:$UseGraphAPIREST)
            $hashtableDefinitionValues = @{}
            foreach ($pscustomobjectDefinitionValue in $arrDefinitionValues) {
                $strGroupPolicyDefinitionValueID = $pscustomobjectDefinitionValue.id

                $arrDefinitionValueDefinition = @(Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValueDefinition -DeviceConfigurationProfileID $strDeviceConfigurationProfileID -GroupPolicyDefinitionValueID $strGroupPolicyDefinitionValueID -UseGraphAPIModule:$UseGraphAPIModule -UseGraphAPIREST:$UseGraphAPIREST)
                $hashtableDefinitionValueDefinitions = @{}
                foreach ($pscustomobjectDefinitionValueDefinition in $arrDefinitionValueDefinition) {
                    $strDefinitionValueDefinitionID = $pscustomobjectDefinitionValueDefinition.id
                    $hashtableDefinitionValueDefinitions.Add($strDefinitionValueDefinitionID, $pscustomobjectDefinitionValueDefinition)
                }
                $pscustomobjectDefinitionValue | Add-Member -MemberType NoteProperty -Name 'definitionValueDefinitions' -Value $hashtableDefinitionValueDefinitions

                # $arrDefinitionValuePresentationValues = @(Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValuePresentationValue -DeviceConfigurationProfileID $strDeviceConfigurationProfileID -GroupPolicyDefinitionValueID $strGroupPolicyDefinitionValueID -UseGraphAPIModule:$UseGraphAPIModule -UseGraphAPIREST:$UseGraphAPIREST)
                # $hashtableDefinitionValuePresentationValues = @{}
                # foreach ($pscustomobjectDefinitionValuePresentationValue in $arrDefinitionValuePresentationValues) {
                #     $strDefinitionValuePresentationValueID = $pscustomobjectDefinitionValuePresentationValue.id
                #     $hashtableDefinitionValuePresentationValues.Add($strDefinitionValuePresentationValueID, $pscustomobjectDefinitionValuePresentationValue)
                # }
                # $pscustomobjectDefinitionValue | Add-Member -MemberType NoteProperty -Name 'definitionValuePresentationValues' -Value $hashtableDefinitionValuePresentationValues

                $arrDefinitionValueExpandedPresentationValues = @(Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValueExpandedPresentationValue -DeviceConfigurationProfileID $strDeviceConfigurationProfileID -GroupPolicyDefinitionValueID $strGroupPolicyDefinitionValueID -UseGraphAPIModule:$UseGraphAPIModule -UseGraphAPIREST:$UseGraphAPIREST)
                $hashtableDefinitionValueExpandedPresentationValues = @{}
                foreach ($pscustomobjectDefinitionValueExpandedPresentationValue in $arrDefinitionValueExpandedPresentationValues) {
                    $strDefinitionValueExpandedPresentationValueID = $pscustomobjectDefinitionValueExpandedPresentationValue.id
                    $hashtableDefinitionValueExpandedPresentationValues.Add($strDefinitionValueExpandedPresentationValueID, $pscustomobjectDefinitionValueExpandedPresentationValue)
                }
                $pscustomobjectDefinitionValue | Add-Member -MemberType NoteProperty -Name 'definitionValueExpandedPresentationValues' -Value $hashtableDefinitionValueExpandedPresentationValues

                $hashtableDefinitionValues.Add($pscustomobjectDefinitionValue.id, $pscustomobjectDefinitionValue)
            }
            $pscustomobjectGroupPolicyBasedProfile | Add-Member -MemberType NoteProperty -Name 'DefinitionValues' -Value $hashtableDefinitionValues
            [void]($arraylistPSCustomObjectGroupPolicyBasedProfilesForOutput.Add($pscustomobjectGroupPolicyBasedProfile))
        }
        return $arraylistPSCustomObjectGroupPolicyBasedProfilesForOutput.ToArray()
    }
}

function Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValue {
    <#
    .SYNOPSIS
    This function is used to get the definition values for a Group Policy-based device
    configuration profile from the Graph API REST interface.
    .DESCRIPTION
    The function connects to the Graph API interface and gets any Group Policy-based
    device configuration profile definition values associated with a given Group
    Policy-based device configuration profile.
    .EXAMPLE
    Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValue -DeviceConfigurationProfileID 'f0b5c0c0-0c0c-0c0c-0c0c-0c0c0c0c0c0c'
    Returns the definition values for the Group Policy-based device configuration
    profile with the ID 'f0b5c0c0-0c0c-0c0c-0c0c-0c0c0c0c0c0c'
    .NOTES
    Not meant to be called by end users
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIModule,
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIREST,
        [Parameter(Mandatory = $true)][string]$DeviceConfigurationProfileID
    )

    if (($UseGraphAPIModule.IsPresent) -or ($UseGraphAPIREST.IsPresent -eq $false)) {
        # Either the user specified to use the Graph API Module or the user did not specify
        # to use the Graph API REST interface
        $boolUseGraphAPIModule = $true
    } else {
        $boolUseGraphAPIModule = $false
    }

    if ($boolUseGraphAPIModule) {
        #TODO: Using the Graph API Module approach
        # Get-MgDeviceManagementGroupPolicyConfigurationDefinitionValue
    } else {
        # Using the Graph API REST approach
        $strGraphAPIVersion = 'beta'

        if ([string]::IsNullOrEmpty($DeviceConfigurationProfileID)) {
            Write-Warning 'The Group Policy-based device configuration profile ID is empty. No definition values will be returned.'
            return
        } elseif ((Test-StringIsGUID -GUID $DeviceConfigurationProfileID) -eq $false) {
            Write-Warning 'The Group Policy-based device configuration profile ID is not a valid GUID. No definition values will be returned.'
            return
        }
        $strDCPResource = 'deviceManagement/groupPolicyConfigurations/' + $DeviceConfigurationProfileID + '/definitionValues'

        try {
            $strURI = 'https://graph.microsoft.com/' + $strGraphAPIVersion + '/' + $strDCPResource
            $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            return (Invoke-RestMethod -Uri $strURI -Headers $global:hashtableAuthToken -Method Get).Value
            $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
        } catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            if ($versionPowerShell -ge [version]'5.0') {
                Write-Information ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            } else {
                Write-Verbose ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            }
            return
        }
    }
}

function Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValueDefinition {
    <#
    .SYNOPSIS
    This function is used to get the definition value definition for a Group Policy-
    based device configuration profile's definition value using the Graph API REST
    interface.
    .DESCRIPTION
    The function connects to the Graph API interface and gets the Group Policy-based
    device configuration profile definition value definition associated with a given
    Group Policy-based device configuration profile and definition value.
    .EXAMPLE
    Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValueDefinition -DeviceConfigurationProfileID '12345678-1234-1234-1234-123456789012' -GroupPolicyDefinitionValueID '12345678-1234-1234-1234-123456789012'
    Returns the definition value definition for the Group Policy-based device
    configuration profile with ID 12345678-1234-1234-1234-123456789012 and definition
    value with ID 12345678-1234-1234-1234-123456789012
    .NOTES
    Not meant to be called by end users
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIModule,
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIREST,
        [Parameter(Mandatory = $true)][string]$DeviceConfigurationProfileID,
        [Parameter(Mandatory = $true)][string]$GroupPolicyDefinitionValueID
    )

    if (($UseGraphAPIModule.IsPresent) -or ($UseGraphAPIREST.IsPresent -eq $false)) {
        # Either the user specified to use the Graph API Module or the user did not specify
        # to use the Graph API REST interface
        $boolUseGraphAPIModule = $true
    } else {
        $boolUseGraphAPIModule = $false
    }

    if ($boolUseGraphAPIModule) {
        #TODO: Using the Graph API Module approach
        # Get-MgDeviceManagementGroupPolicyConfigurationDefinitionValueDefinition
    } else {
        # Using the Graph API REST approach
        $strGraphAPIVersion = 'beta'

        if ([string]::IsNullOrEmpty($DeviceConfigurationProfileID)) {
            Write-Warning 'The Group Policy-based device configuration profile ID is empty. No definition values will be returned.'
            return
        } elseif ((Test-StringIsGUID -GUID $DeviceConfigurationProfileID) -eq $false) {
            Write-Warning 'The Group Policy-based device configuration profile ID is not a valid GUID. No definition values will be returned.'
            return
        }
        if ([string]::IsNullOrEmpty($GroupPolicyDefinitionValueID)) {
            Write-Warning 'The Group Policy-based device configuration profile ID is empty. No definition values will be returned.'
            return
        } elseif ((Test-StringIsGUID -GUID $GroupPolicyDefinitionValueID) -eq $false) {
            Write-Warning 'The Group Policy-based device configuration profile ID is not a valid GUID. No definition values will be returned.'
            return
        }
        $strDCPResource = 'deviceManagement/groupPolicyConfigurations/' + $DeviceConfigurationProfileID + '/definitionValues/' + $GroupPolicyDefinitionValueID + '/definition'

        try {
            $strURI = 'https://graph.microsoft.com/' + $strGraphAPIVersion + '/' + $strDCPResource
            $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            return (Invoke-RestMethod -Uri $strURI -Headers $global:hashtableAuthToken -Method Get)
            $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
        } catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            if ($versionPowerShell -ge [version]'5.0') {
                Write-Information ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            } else {
                Write-Verbose ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            }
            return
        }
    }
}

#TODO: remove this function
# function Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValuePresentationValue {
#     <#
#     .SYNOPSIS
#     This function is used to get the definition value presentation values for a Group
#     Policy-based device configuration profile's definition value using the Graph API
#     REST interface.
#     .DESCRIPTION
#     The function connects to the Graph API interface and gets the Group Policy-based
#     device configuration profile definition value presentation values associated with a
#     given Group Policy-based device configuration profile and definition value.
#     .EXAMPLE
#     Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValuePresentationValue -DeviceConfigurationProfileID '12345678-1234-1234-1234-123456789012' -GroupPolicyDefinitionValueID '12345678-1234-1234-1234-123456789012'
#     Returns the definition value presentation values for the Group Policy-based device
#     configuration profile with ID 12345678-1234-1234-1234-123456789012 and definition
#     value with ID 12345678-1234-1234-1234-123456789012
#     .NOTES
#     Not meant to be called by end users
#     #>

#     [cmdletbinding()]
#     param (
#         [Parameter(Mandatory = $false)][Switch]$UseGraphAPIModule,
#         [Parameter(Mandatory = $false)][Switch]$UseGraphAPIREST,
#         [Parameter(Mandatory = $true)][string]$DeviceConfigurationProfileID,
#         [Parameter(Mandatory = $true)][string]$GroupPolicyDefinitionValueID
#     )

#     if (($UseGraphAPIModule.IsPresent) -or ($UseGraphAPIREST.IsPresent -eq $false)) {
#         # Either the user specified to use the Graph API Module or the user did not specify
#         # to use the Graph API REST interface
#         $boolUseGraphAPIModule = $true
#     } else {
#         $boolUseGraphAPIModule = $false
#     }

#     if ($boolUseGraphAPIModule) {
#         #TODO: Using the Graph API Module approach
#         # Get-MgDeviceManagementGroupPolicyConfigurationDefinitionValuePresentationValue
#     } else {
#         # Using the Graph API REST approach
#         $strGraphAPIVersion = 'beta'

#         if ([string]::IsNullOrEmpty($DeviceConfigurationProfileID)) {
#             Write-Warning 'The Group Policy-based device configuration profile ID is empty. No definition values will be returned.'
#             return
#         } elseif ((Test-StringIsGUID -GUID $DeviceConfigurationProfileID) -eq $false) {
#             Write-Warning 'The Group Policy-based device configuration profile ID is not a valid GUID. No definition values will be returned.'
#             return
#         }
#         if ([string]::IsNullOrEmpty($GroupPolicyDefinitionValueID)) {
#             Write-Warning 'The Group Policy-based device configuration profile ID is empty. No definition values will be returned.'
#             return
#         } elseif ((Test-StringIsGUID -GUID $GroupPolicyDefinitionValueID) -eq $false) {
#             Write-Warning 'The Group Policy-based device configuration profile ID is not a valid GUID. No definition values will be returned.'
#             return
#         }
#         $strDCPResource = 'deviceManagement/groupPolicyConfigurations/' + $DeviceConfigurationProfileID + '/definitionValues/' + $GroupPolicyDefinitionValueID + '/presentationValues'

#         try {
#             $strURI = 'https://graph.microsoft.com/' + $strGraphAPIVersion + '/' + $strDCPResource
#             $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
#             return (Invoke-RestMethod -Uri $strURI -Headers $global:hashtableAuthToken -Method Get).Value
#             $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
#         } catch {
#             $ex = $_.Exception
#             $errorResponse = $ex.Response.GetResponseStream()
#             $reader = New-Object System.IO.StreamReader($errorResponse)
#             $reader.BaseStream.Position = 0
#             $reader.DiscardBufferedData()
#             $responseBody = $reader.ReadToEnd();
#             if ($versionPowerShell -ge [version]'5.0') {
#                 Write-Information ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
#             } else {
#                 Write-Verbose ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
#             }
#             return
#         }
#     }
# }

function Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValueExpandedPresentationValue {
    <#
    .SYNOPSIS
    This function is used to get the definition value expanded presentation values for
    a Group Policy-based device configuration profile's definition value using the
    Graph API REST interface.
    .DESCRIPTION
    The function connects to the Graph API interface and gets the Group Policy-based
    device configuration profile definition value expanded presentation values
    associated with a given Group Policy-based device configuration profile and
    definition value.
    .EXAMPLE
    Get-GroupPolicyBasedDeviceConfigurationProfileDefinitionValueExpandedPresentationValue -DeviceConfigurationProfileID '12345678-1234-1234-1234-123456789012' -GroupPolicyDefinitionValueID '12345678-1234-1234-1234-123456789012'
    Returns the definition value expanded presentation values for the Group Policy-
    based device configuration profile with ID 12345678-1234-1234-1234-123456789012
    and definition value with ID 12345678-1234-1234-1234-123456789012
    .NOTES
    Not meant to be called by end users
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIModule,
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIREST,
        [Parameter(Mandatory = $true)][string]$DeviceConfigurationProfileID,
        [Parameter(Mandatory = $true)][string]$GroupPolicyDefinitionValueID
    )

    if (($UseGraphAPIModule.IsPresent) -or ($UseGraphAPIREST.IsPresent -eq $false)) {
        # Either the user specified to use the Graph API Module or the user did not specify
        # to use the Graph API REST interface
        $boolUseGraphAPIModule = $true
    } else {
        $boolUseGraphAPIModule = $false
    }

    if ($boolUseGraphAPIModule) {
        #TODO: Using the Graph API Module approach
        # Get-MgDeviceManagementGroupPolicyConfigurationDefinitionValuePresentationValue -ExpandProperty @('presentation')
    } else {
        # Using the Graph API REST approach
        $strGraphAPIVersion = 'beta'

        if ([string]::IsNullOrEmpty($DeviceConfigurationProfileID)) {
            Write-Warning 'The Group Policy-based device configuration profile ID is empty. No definition values will be returned.'
            return
        } elseif ((Test-StringIsGUID -GUID $DeviceConfigurationProfileID) -eq $false) {
            Write-Warning 'The Group Policy-based device configuration profile ID is not a valid GUID. No definition values will be returned.'
            return
        }
        if ([string]::IsNullOrEmpty($GroupPolicyDefinitionValueID)) {
            Write-Warning 'The Group Policy-based device configuration profile ID is empty. No definition values will be returned.'
            return
        } elseif ((Test-StringIsGUID -GUID $GroupPolicyDefinitionValueID) -eq $false) {
            Write-Warning 'The Group Policy-based device configuration profile ID is not a valid GUID. No definition values will be returned.'
            return
        }
        $strDCPResource = 'deviceManagement/groupPolicyConfigurations/' + $DeviceConfigurationProfileID + '/definitionValues/' + $GroupPolicyDefinitionValueID + '/presentationValues?$expand=presentation'

        try {
            $strURI = 'https://graph.microsoft.com/' + $strGraphAPIVersion + '/' + $strDCPResource
            $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            return (Invoke-RestMethod -Uri $strURI -Headers $global:hashtableAuthToken -Method Get).Value
            $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
        } catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            if ($versionPowerShell -ge [version]'5.0') {
                Write-Information ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            } else {
                Write-Verbose ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            }
            return
        }
    }
}

function Get-TemplateBasedDeviceConfigurationProfile {
    <#
    .SYNOPSIS
    This function is used to get device configuration profiles from the Graph API REST interface that were built using a template, a custom OMA-URI, or a custom configuration file.
    .DESCRIPTION
    The function connects to the Graph API interface and gets any device configuration profiles built using a template, a custom OMA-URI, or a custom configuration file.
    A non-exhaustive list of the device configuration profiles retrieved by this function are:
    macOS - Templates - Custom
    macOS - Templates - Device Features
    macOS - Templates - Device Restrictions
    macOS - Templates - Endpoint Protection
    macOS - Templates - Extensions
    macOS - Templates - PKCS Certificate
    macOS - Templates - PKCS Imported Certificate
    macOS - Templates - Preference File
    macOS - Templates - SCEP Certificate
    macOS - Templates - Trusted Certificate
    macOS - Templates - VPN
    macOS - Templates - Wi-Fi
    macOS - Templates - Wired Network
    Win10+ - Templates - Custom
    Win10+ - Templates - Delivery Optimization
    Win10+ - Templates - Device Firmware Configuration Interface
    Win10+ - Templates - Device Restrictions
    Win10+ - Templates - Device Restrictions (Win10 Team)
    Win10+ - Templates - Domain Join
    Win10+ - Templates - Edition Upgrade and Mode Switch
    Win10+ - Templates - Email
    Win10+ - Templates - Endpoint Protection
    Win10+ - Templates - Identity Protection
    Win10+ - Templates - Kiosk
    Win10+ - Templates - MS Defender for Endpoint
    Win10+ - Templates - Network Boundary
    Win10+ - Templates - PKCS Certificate
    Win10+ - Templates - PKCS Imported Certificate
    Win10+ - Templates - SCEP Certificate
    Win10+ - Templates - Secure Assessment (Education)
    Win10+ - Templates - Shared Multi-User Device
    Win10+ - Templates - Trusted Certificate
    Win10+ - Templates - VPN
    Win10+ - Templates - Wi-Fi
    Win10+ - Templates - Windows Health Monitoring
    Win10+ - Templates - Wired Network
    Win8.1+ - Device Restriction
    Win8.1+ - SCEP Certificate
    Win8.1+ - Trusted Certificate
    Win8.1+ - VPN
    Win8.1+ - Wi-Fi
    .EXAMPLE
    Get-TemplateBasedDeviceConfigurationProfile
    Returns any device configuration profiles configured in Intune
    .NOTES
    This function does not retrieve the following device configuration profiles (note: list is non-exhaustive):
    macOS - Settings Catalog
    Win10+ - Settings Catalog
    Win10+ - Templates - Administrative Templates
    Win10+ - Templates - Imported Administrative Templates
    #>

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIModule,
        [Parameter(Mandatory = $false)][Switch]$UseGraphAPIREST
    )

    if (($UseGraphAPIModule.IsPresent) -or ($UseGraphAPIREST.IsPresent -eq $false)) {
        # Either the user specified to use the Graph API Module or the user did not specify
        # to use the Graph API REST interface
        $boolUseGraphAPIModule = $true
    } else {
        $boolUseGraphAPIModule = $false
    }

    if ($boolUseGraphAPIModule) {
        #TODO: Using the Graph API Module approach
        # Get-MgDeviceManagementDeviceConfiguration
    } else {
        # Using the Graph API REST approach
        $strGraphAPIVersion = 'beta'
        $strDCPResource = 'deviceManagement/deviceConfigurations'

        try {
            $strURI = 'https://graph.microsoft.com/' + $strGraphAPIVersion + '/' + $strDCPResource
            $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
            return (Invoke-RestMethod -Uri $strURI -Headers $global:hashtableAuthToken -Method Get).Value
            $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
        } catch {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            if ($versionPowerShell -ge [version]'5.0') {
                Write-Information ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            } else {
                Write-Verbose ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
            }
            return $null
        }
    }
}

####################################################

function Export-JSONData {
    <#
    .SYNOPSIS
    This function is used to export JSON data returned from Graph
    .DESCRIPTION
    This function is used to export JSON data returned from Graph
    .EXAMPLE
    Export-JSONData -JSON $JSON -ExportPath 'C:\Intune_Export' -FileName 'Intune_Export.json'
    Export the JSON inputted on the function
    .NOTES
    NAME: Export-JSONData
    #>

    param (
        [Parameter(Mandatory = $true)]$JSON,
        [Parameter(Mandatory = $true)][string]$ExportPath,
        [Parameter(Mandatory = $true)][string]$FileName
    )

    try {
        if ([string]::IsNullOrEmpty($JSON)) {
            Write-Error 'No JSON specified, please specify valid JSON...'
            return
        } elseif ([string]::IsNullOrEmpty($ExportPath)) {
            Write-Error 'No export path parameter set, please provide a path to export the file'
            return
        } elseif (!(Test-Path $ExportPath)) {
            Write-Error ($ExportPath + ' does not exist, cannot export JSON Data')
            return
        } elseif ([string]::IsNullOrEmpty($FileName)) {
            Write-Error 'No file name specified. Please specify a file name to export the JSON data'
            return
        } else {
            $strJSON = ConvertTo-Json $JSON -Depth 8

            $pscustomobjectConvertedJSON = $strJSON | ConvertFrom-Json

            $strJSON | Set-Content -LiteralPath (Join-Path $ExportPath $FileName)
            Write-Debug ('JSON created in ' + (Join-Path $ExportPath $FileName) + '...')
        }
    } catch {
        $_.Exception
    }
}

####################################################

#region Detect Which Graph API Approach Will Be Used ###############################
if (($UseGraphAPIModule.IsPresent) -or ($UseGraphAPIREST.IsPresent -eq $false)) {
    # Either the user specified to use the Graph API Module or the user did not specify
    # to use the Graph API REST interface
    Write-Verbose 'Using Graph API Module approach...'
    $boolUseGraphAPIModule = $true
} else {
    Write-Verbose 'Using Graph API REST approach...'
    $boolUseGraphAPIModule = $false
}
#endregion Detect Which Graph API Approach Will Be Used ###############################

#TODO: Remove this!
$boolUseGraphAPIModule = $false # Temporary to keep script working while we code Graph API Module approach

#region Detect PowerShell Environment ##############################################
# (i.e., Windows PowerShell, PowerShell 6.0+, Azure Cloud Shell)
$boolAzureCloudShell = $false
$boolNonWindowsPlatform = $false
$boolWindowsPowerShell = $false
$versionPowerShell = $null
$PlatformID = [System.Environment]::OSVersion.Platform
if ($PlatformID -eq [System.PlatformID]::Unix) {
    # Linux / Unix / FreeBSD
    $boolNonWindowsPlatform = $true
    # $boolWindowsPowerShell = $false

    $versionPowerShell = $PSVersionTable.PSVersion

    # Check for Cloud Shell
    $boolAzureCloudShell = $false
    if (Test-Path env:"ACC_CLOUD") {
        if ((Get-Item env:"ACC_CLOUD").Value -eq "PROD") {
            $boolAzureCloudShell = $true
        }
    }
} elseif ($PlatformID -ne [System.PlatformID]::Win32NT) {
    # Not "Unix", i.e., Unix, Linux, or FreeBSD
    # Also not Windows
    $boolNonWindowsPlatform = $true
    # $boolWindowsPowerShell = $false

    if ((Test-Path variable:\PSVersionTable) -eq $true) {
        # $PSVersionTable exists
        $versionPowerShell = $PSVersionTable.PSVersion
    }
} else {
    # Windows OS
    # $boolNonWindowsPlatform = $false

    if ((Test-Path variable:\PSVersionTable) -eq $false) {
        # $PSVersionTable variable does not exist
        # Must be PowerShell v1
        $versionPowerShell = [version]'1.0'
        $boolWindowsPowerShell = $true
    } else {
        # $PSVersionTable variable exists; use it
        $versionPowerShell = $PSVersionTable.PSVersion

        if ($null -eq $PSVersionTable.PSEdition) {
            # No knowledge of "Edition" of PowerShell; must be 5.1 or older
            $boolWindowsPowerShell = $true
        } else {
            if ($PSVersionTable.PSEdition -eq "Desktop") {
                # Windows PowerShell
                $boolWindowsPowerShell = $true
            } else {
                # Must be PowerShell Core or something else
                # $boolWindowsPowerShell = $false
            }
        }
    }
}
#endregion Detect PowerShell Environment ##############################################

#region Quit if PowerShell version is very old #####################################
if ($versionPowerShell -lt [version]'3.0') {
    Write-Warning 'This script requires PowerShell v3 or higher. Please upgrade to PowerShell v3 or higher and try again.'
    return # Quit script
}
#endregion Quit if PowerShell version is very old #####################################

# TODO: Check for script execution policy and quit if set to Restricted

#region Check for required PowerShell modules based on Graph API approach ##########
if ($boolUseGraphAPIModule -eq $true) {
    # Using Graph API Module approach
    $arrModuleGraphAuthentication = @() # Microsoft.Graph.Authentication
    $arrModuleGraphDeviceManagement = @() # Microsoft.Graph.DeviceManagement
    $arrModuleGraphDevicesCorporateManagement = @() # Microsoft.Graph.Devices.CorporateManagement

    Write-Verbose 'Checking for Microsoft.Graph.Authentication module...'
    $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
    $arrModuleGraphAuthentication = @(Get-Module -Name 'Microsoft.Graph.Authentication' -ListAvailable)
    $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
    if ($arrModuleGraphAuthentication.Count -eq 0) {
        Write-Warning ('Microsoft.Graph.Authentication module not found. Please install the full Microsoft.Graph module and then try again.' + [System.Environment]::NewLine + 'You can install the Microsoft.Graph PowerShell module from the PowerShell Gallery by running the following command:' + [System.Environment]::NewLine + 'Install-Module Microsoft.Graph' + [System.Environment]::NewLine + [System.Environment]::NewLine + 'If the installation command fails, you may need to upgrade the version of PowerShellGet. To do so, run the following commands, then restart PowerShell:' + [System.Environment]::NewLine + 'Set-ExecutionPolicy Bypass -Scope Process -Force' + [System.Environment]::NewLine + '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12' + [System.Environment]::NewLine + 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force' + [System.Environment]::NewLine + 'Install-Module PowerShellGet -MinimumVersion 2.2.4 -SkipPublisherCheck -Force -AllowClobber')
        return # Quit script
    }

    Write-Verbose 'Checking for Microsoft.Graph.DeviceManagement module...'
    $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
    $arrModuleGraphDeviceManagement = @(Get-Module -Name 'Microsoft.Graph.DeviceManagement' -ListAvailable)
    $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
    if ($arrModuleGraphDeviceManagement.Count -eq 0) {
        Write-Warning ('Microsoft.Graph.DeviceManagement module not found. Please install the full Microsoft.Graph module and then try again.' + [System.Environment]::NewLine + 'You can install the Microsoft.Graph PowerShell module from the PowerShell Gallery by running the following command:' + [System.Environment]::NewLine + 'Install-Module Microsoft.Graph' + [System.Environment]::NewLine + [System.Environment]::NewLine + 'If the installation command fails, you may need to upgrade the version of PowerShellGet. To do so, run the following commands, then restart PowerShell:' + [System.Environment]::NewLine + 'Set-ExecutionPolicy Bypass -Scope Process -Force' + [System.Environment]::NewLine + '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12' + [System.Environment]::NewLine + 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force' + [System.Environment]::NewLine + 'Install-Module PowerShellGet -MinimumVersion 2.2.4 -SkipPublisherCheck -Force -AllowClobber')
        return # Quit script
    }

    Write-Verbose 'Checking for Microsoft.Graph.Devices.CorporateManagement module...'
    $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
    $arrModuleGraphDevicesCorporateManagement = @(Get-Module -Name 'Microsoft.Graph.Devices.CorporateManagement' -ListAvailable)
    $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
    if ($arrModuleGraphDevicesCorporateManagement.Count -eq 0) {
        Write-Warning ('Microsoft.Graph.Devices.CorporateManagement module not found. Please install the full Microsoft.Graph module and then try again.' + [System.Environment]::NewLine + 'You can install the Microsoft.Graph PowerShell module from the PowerShell Gallery by running the following command:' + [System.Environment]::NewLine + 'Install-Module Microsoft.Graph' + [System.Environment]::NewLine + [System.Environment]::NewLine + 'If the installation command fails, you may need to upgrade the version of PowerShellGet. To do so, run the following commands, then restart PowerShell:' + [System.Environment]::NewLine + 'Set-ExecutionPolicy Bypass -Scope Process -Force' + [System.Environment]::NewLine + '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12' + [System.Environment]::NewLine + 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force' + [System.Environment]::NewLine + 'Install-Module PowerShellGet -MinimumVersion 2.2.4 -SkipPublisherCheck -Force -AllowClobber')
        return # Quit script
    }
} else {
    # Using Graph API REST approach
    $arrModuleAzureAD = @()
    $arrModuleAzureADPreview = @()
    Write-Verbose 'Checking for AzureAD module...'
    $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
    $arrModuleAzureAD = @(Get-Module -Name 'AzureAD' -ListAvailable)
    $VerbosePreference = $script:VerbosePreferenceAtStartOfScript

    if ($arrModuleAzureAD.Count -eq 0) {
        Write-Verbose 'AzureAD PowerShell module not found, looking for AzureADPreview'
        $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
        $arrModuleAzureADPreview = @(Get-Module -Name 'AzureADPreview' -ListAvailable)
        $VerbosePreference = $script:VerbosePreferenceAtStartOfScript
    }

    if (($arrModuleAzureAD.Count -eq 0) -and ($arrModuleAzureADPreview.Count -eq 0)) {
        Write-Warning ('This script requires the AzureAD or AzureADPreview Powershell module. Please install one and then try again.' + [System.Environment]::NewLine + 'You can install the AzureAD PowerShell module from the PowerShell Gallery by running the following command:' + [System.Environment]::NewLine + 'Install-Module AzureAD' + [System.Environment]::NewLine + [System.Environment]::NewLine + 'If the installation command fails, you may need to upgrade the version of PowerShellGet. To do so, run the following commands, then restart PowerShell:' + [System.Environment]::NewLine + 'Set-ExecutionPolicy Bypass -Scope Process -Force' + [System.Environment]::NewLine + '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12' + [System.Environment]::NewLine + 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force' + [System.Environment]::NewLine + 'Install-Module PowerShellGet -MinimumVersion 2.2.4 -SkipPublisherCheck -Force -AllowClobber')
        return # Quit script
    }
}
#endregion Check for required PowerShell modules based on Graph API approach ##########

#region Check for PowerShell version compatibility with required modules ###########
if ($boolUseGraphAPIModule -eq $true) {
    if ($versionPowerShell -lt [version]'5.1') {
        Write-Warning 'This script requires PowerShell v5.1 or higher. Please upgrade to PowerShell v5.1 or higher and try again.'
        return # Quit script
    }
} else {
    # Graph API REST approach
    # Check for PowerShell version compatible with AzureAD module ################
    if ($boolWindowsPowerShell -eq $false -and $boolAzureCloudShell -eq $false) {
        if ($boolNonWindowsPlatform) {
            Write-Warning 'This script is only compatible with Windows or an Azure Cloud Shell environment. Please switch to one of these platforms and try again.'
            return # Quit script
        } else {
            # Windows platform, but not Windows PowerShell
            Write-Warning 'This script is designed to run from Windows PowerShell. Please switch to Windows PowerShell and try again.'
            return # Quit script
        }
    }
}
#endregion Check for PowerShell version compatibility with required modules ###########

#region Check for PowerShell module updates ########################################
if ($DoNotCheckForModuleUpdates.IsPresent -eq $false) {
    if ($boolUseGraphAPIModule -eq $true) {
        #TODO: Code Graph API Module approach
    } else {
        Write-Verbose 'Checking for module updates...'
        $versionNewestInstalledAzureADModule = (($arrModuleAzureAD + $arrModuleAzureADPreview) | ForEach-Object { [version]($_.Version) } | Sort-Object)[-1]

        $arrModuleNewestInstalledAzureAD = @(($arrModuleAzureAD + $arrModuleAzureADPreview) | Where-Object { ([version]($_.Version)) -eq $versionNewestInstalledAzureADModule })

        # In the event there are multiple installations of the same version, reduce to a
        # single instance of the module
        if ($arrModuleNewestInstalledAzureAD.Count -gt 1) {
            $moduleNewestInstalledAzureAD = @($arrModuleNewestInstalledAzureAD | Select-Object -Unique)[0]
        } else {
            $moduleNewestInstalledAzureAD = $arrModuleNewestInstalledAzureAD[0]
        }

        $VerbosePreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
        $moduleNewestAvailableAzureAD = Find-Module -Name 'AzureAD' -ErrorAction SilentlyContinue
        $moduleNewestAvailableAzureADPreview = Find-Module -Name 'AzureADPreview' -ErrorAction SilentlyContinue
        $VerbosePreference = $script:VerbosePreferenceAtStartOfScript

        if ($null -ne $moduleNewestAvailableAzureAD) {
            if ($moduleNewestAvailableAzureAD.Version -gt $moduleNewestInstalledAzureAD.Version) {
                Write-Warning ('A newer version of the AzureAD PowerShell module is available. Script execution will continue, but please consider updating it by running the following command:' + [System.Environment]::NewLine + 'Install-Module AzureAD -Force' + [System.Environment]::NewLine + [System.Environment]::NewLine + 'If the installation command fails, you may need to upgrade the version of PowerShellGet. To do so, run the following commands, then restart PowerShell:' + [System.Environment]::NewLine + 'Set-ExecutionPolicy Bypass -Scope Process -Force' + [System.Environment]::NewLine + '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12' + [System.Environment]::NewLine + 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force' + [System.Environment]::NewLine + 'Install-Module PowerShellGet -MinimumVersion 2.2.4 -SkipPublisherCheck -Force -AllowClobber')
            } elseif ($moduleNewestAvailableAzureAD.Version -eq $moduleNewestInstalledAzureAD.Version) {
                # Currently installed AzureAD module is the newest production release available
                if ($null -ne $moduleNewestAvailableAzureADPreview) {
                    if ($moduleNewestAvailableAzureADPreview.Version -gt $moduleNewestInstalledAzureAD.Version) {
                        Write-Warning ('While your system has the current production release of the AzureAD module installed, it may benefit from installing the newer, preview release of the AzureADPreview module. Script execution will continue, but you may consider installing the preview module by running the following command:' + [System.Environment]::NewLine + 'Install-Module AzureADPreview -Force' + [System.Environment]::NewLine + [System.Environment]::NewLine + 'If the installation command fails, you may need to upgrade the version of PowerShellGet. To do so, run the following commands, then restart PowerShell:' + [System.Environment]::NewLine + 'Set-ExecutionPolicy Bypass -Scope Process -Force' + [System.Environment]::NewLine + '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12' + [System.Environment]::NewLine + 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force' + [System.Environment]::NewLine + 'Install-Module PowerShellGet -MinimumVersion 2.2.4 -SkipPublisherCheck -Force -AllowClobber')
                    }
                }
            } else {
                # Currently installed AzureAD module is newer than the newest production release available
                # Therefore, the user is using the AzureADPreview release
                if ($null -ne $moduleNewestAvailableAzureADPreview) {
                    if ($moduleNewestAvailableAzureADPreview.Version -gt $moduleNewestInstalledAzureAD.Version) {
                        Write-Warning ('A newer version of the AzureADPreview PowerShell module is available. Script execution will continue, but please consider updating it by running the following command:' + [System.Environment]::NewLine + 'Install-Module AzureAD -Force' + [System.Environment]::NewLine + [System.Environment]::NewLine + 'If the installation command fails, you may need to upgrade the version of PowerShellGet. To do so, run the following commands, then restart PowerShell:' + [System.Environment]::NewLine + 'Set-ExecutionPolicy Bypass -Scope Process -Force' + [System.Environment]::NewLine + '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12' + [System.Environment]::NewLine + 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force' + [System.Environment]::NewLine + 'Install-Module PowerShellGet -MinimumVersion 2.2.4 -SkipPublisherCheck -Force -AllowClobber')
                    }
                }
            }
        } else {
            # Couldn't find the AzureAD module in the PowerShell Gallery
            if ($null -ne $moduleNewestAvailableAzureADPreview) {
                if ($moduleNewestAvailableAzureADPreview.Version -gt $moduleNewestInstalledAzureAD.Version) {
                    Write-Warning ('A newer version of the AzureADPreview PowerShell module is available. Script execution will continue, but please consider updating it by running the following command:' + [System.Environment]::NewLine + 'Install-Module AzureAD -Force' + [System.Environment]::NewLine + [System.Environment]::NewLine + 'If the installation command fails, you may need to upgrade the version of PowerShellGet. To do so, run the following commands, then restart PowerShell:' + [System.Environment]::NewLine + 'Set-ExecutionPolicy Bypass -Scope Process -Force' + [System.Environment]::NewLine + '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12' + [System.Environment]::NewLine + 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force' + [System.Environment]::NewLine + 'Install-Module PowerShellGet -MinimumVersion 2.2.4 -SkipPublisherCheck -Force -AllowClobber')
                }
            }
        }
    }
}
#endregion Check for PowerShell module updates ########################################

#region Authentication #############################################################
if ($boolUseGraphAPIModule -eq $true) {
    #TODO: Code Graph API Module approach
} else {
    # Graph API REST approach
    # Checking if hashtableAuthToken exists before running authentication
    if ($global:hashtableAuthToken) {

        # Setting DateTime to Universal time to work in all timezones
        $datetimeUTC = (Get-Date).ToUniversalTime()

        # If the hashtableAuthToken exists checking when it expires
        $intMinutesSinceTokenExpiration = ($datetimeUTC - $hashtableAuthToken.ExpiresOn.Datetime).Minutes

        if ($intMinutesSinceTokenExpiration -ge 0) {
            Write-Output ('Authentication Token expired ' + $intMinutesSinceTokenExpiration + ' minutes ago')

            # Defining User Principal Name if not present

            while ([string]::IsNullOrEmpty($UserPrincipalName)) {
                $UserPrincipalName = Read-Host -Prompt 'Please specify your user principal name for Azure authentication'
            }

            $global:hashtableAuthToken = Get-AuthToken -User $UserPrincipalName
        }
    } else {
        # Authentication doesn't exist, calling Get-AuthToken function

        while ([string]::IsNullOrEmpty($UserPrincipalName)) {
            $UserPrincipalName = Read-Host -Prompt 'Please specify your user principal name for Azure authentication'
        }

        # Getting the authorization token
        $global:hashtableAuthToken = Get-AuthToken -User $UserPrincipalName
    }
}
#endregion Authentication #############################################################

#region GetExportPath ##############################################################
$strExportPath = $null
if ([string]::IsNullOrEmpty($ExportPath) -eq $false) {
    # Replace quotes for Test-Path
    $ExportPath = $ExportPath.Replace('"', '')
    if (Test-Path -Path $ExportPath -Type Container) {
        $strExportPath = $ExportPath
    } else {
        Write-Output ('Path "' + $ExportPath + '" does not exist, do you want to attempt to create this directory (Y/N)?')

        $strConfirmation = Read-Host

        if ($strConfirmation -eq 'y' -or $strConfirmation -eq 'yes') {
            New-Item -ItemType Directory -Path $ExportPath -ErrorAction SilentlyContinue | Out-Null
            if (Test-Path -Path $ExportPath -Type Container) {
                $strExportPath = $ExportPath
            } else {
                Write-Warning 'Creation of directory path failed...'
            }
        } else {
            Write-Warning 'Creation of directory path was cancelled...'
            break
        }
    }
}
while ($null -eq $strExportPath) {
    $ExportPath = Read-Host -Prompt 'Please specify a path to export the policy data to e.g. C:\IntuneOutput'
    if ([string]::IsNullOrEmpty($ExportPath) -eq $false) {
        # Replace quotes for Test-Path
        $ExportPath = $ExportPath.Replace('"', '')
        if (Test-Path -Path $ExportPath -Type Container) {
            $strExportPath = $ExportPath
        } else {
            Write-Output ('Path "' + $ExportPath + '" does not exist, do you want to attempt to create this directory (Y/N)?')

            $strConfirmation = Read-Host

            if ($strConfirmation -eq 'y' -or $strConfirmation -eq 'yes') {
                New-Item -ItemType Directory -Path $ExportPath -ErrorAction SilentlyContinue | Out-Null
                if (Test-Path -Path $ExportPath -Type Container) {
                    $strExportPath = $ExportPath
                } else {
                    Write-Warning 'Creation of directory path failed...'
                }
            } else {
                Write-Warning 'Creation of directory path was cancelled...'
                break
            }
        }
    }
    if ($null -eq $strExportPath) {
        Write-Warning 'Invalid path! Please try again...'
    }
}
#endregion GetExportPath ##############################################################

#region CreateSubfoldersIfNecessary ################################################
$strAndroidEnterpriseOEMConfigProfilesSubfolder = Join-Path $strExportPath 'AndroidEnterpriseOEMConfig'
$strSettingsCatalogBasedProfilesSubfolder = Join-Path $strExportPath 'SettingsCatalogBased'
$strGroupPolicyBasedProfilesSubfolder = Join-Path $strExportPath 'GroupPolicyBased'
$strTemplateBasedProfilesSubfolder = Join-Path $strExportPath 'TemplateBased'

if (-not (Test-Path -Path $strAndroidEnterpriseOEMConfigProfilesSubfolder -Type Container)) {
    New-Item -ItemType Directory -Path $strAndroidEnterpriseOEMConfigProfilesSubfolder -ErrorAction SilentlyContinue | Out-Null
}
if (-not (Test-Path -Path $strSettingsCatalogBasedProfilesSubfolder -Type Container)) {
    New-Item -ItemType Directory -Path $strSettingsCatalogBasedProfilesSubfolder -ErrorAction SilentlyContinue | Out-Null
}
if (-not (Test-Path -Path $strGroupPolicyBasedProfilesSubfolder -Type Container)) {
    New-Item -ItemType Directory -Path $strGroupPolicyBasedProfilesSubfolder -ErrorAction SilentlyContinue | Out-Null
}
if (-not (Test-Path -Path $strTemplateBasedProfilesSubfolder -Type Container)) {
    New-Item -ItemType Directory -Path $strTemplateBasedProfilesSubfolder -ErrorAction SilentlyContinue | Out-Null
}

if (-not (Test-Path -Path $strAndroidEnterpriseOEMConfigProfilesSubfolder -Type Container)) {
    Write-Warning ('Creation of Android Enterprise OEMConfig profiles subfolder failed... unable to proceed. Please create the folder "' + $strAndroidEnterpriseOEMConfigProfilesSubfolder + '" manually and try again.')
    return
}

if (-not (Test-Path -Path $strSettingsCatalogBasedProfilesSubfolder -Type Container)) {
    Write-Warning ('Creation of settings catalog-based profiles subfolder failed... unable to proceed. Please create the folder "' + $strSettingsCatalogBasedProfilesSubfolder + '" manually and try again.')
    return
}

if (-not (Test-Path -Path $strGroupPolicyBasedProfilesSubfolder -Type Container)) {
    Write-Warning ('Creation of Group Policy-based profiles subfolder failed... unable to proceed. Please create the folder "' + $strGroupPolicyBasedProfilesSubfolder + '" manually and try again.')
    return
}

if (-not (Test-Path -Path $strTemplateBasedProfilesSubfolder -Type Container)) {
    Write-Warning ('Creation of template-based profiles subfolder failed... unable to proceed. Please create the folder "' + $strTemplateBasedProfilesSubfolder + '" manually and try again.')
    return
}
#endregion CreateSubfoldersIfNecessary ################################################

#region GetProfiles ################################################################
if ($boolUseGraphAPIModule -eq $true) {
    #TODO: Code Graph API Module approach
} else {
    # Graph API REST approach

    $datetimeNow = Get-Date
    $strISO8601DateTimeNow = $datetimeNow.ToUniversalTime().ToString('o')

    # Get all the device configuration profiles
    $arrPSCustomObjectAndroidEnterpriseOEMConfigProfiles = @(Get-AndroidEnterpriseOEMConfigDeviceConfigurationProfile -UseGraphAPIREST)
    $arrPSCustomObjectSettingsCatalogBasedProfiles = @(Get-SettingsCatalogBasedDeviceConfigurationProfile -UseGraphAPIREST)
    $arrPSCustomObjectGroupPolicyBasedProfiles = @(Get-GroupPolicyBasedDeviceConfigurationProfile -UseGraphAPIREST)
    $arrPSCustomObjectTemplateBasedProfiles = @(Get-TemplateBasedDeviceConfigurationProfile -UseGraphAPIREST)
}
#endregion GetProfiles ################################################################

#region DetermineFileNamesAndDealWithDuplicates ####################################
if ($boolUseGraphAPIModule -eq $true) {
    #TODO: Code Graph API Module approach
} else {
    # Graph API REST approach

    # Check for duplicates and warn when one is found
    $hashtableAllDeviceConfigProfileFileNames = @{}
    $hashtableAllDuplicateDeviceConfigProfileOriginalFileNames = @{}
    $hashtableAndroidEnterpriseOEMConfigProfileFileNames = @{}
    $hashtableSettingsCatalogBasedProfileFileNames = @{}
    $hashtableGroupPolicyBasedProfileFileNames = @{}
    $hashtableTemplateBasedProfileFileNames = @{}

    foreach ($pscustomobjectDeviceConfigProfile in $arrPSCustomObjectAndroidEnterpriseOEMConfigProfiles) {
        $refSubHashtable = [ref]$hashtableAndroidEnterpriseOEMConfigProfileFileNames
        $intThisHashtableNumber = 1 # 1 = Android Enterprise OEMConfig profiles, $hashtableAndroidEnterpriseOEMConfigProfileFileNames

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.displayName) -eq $false) {
            $strDisplayName = $pscustomobjectDeviceConfigProfile.displayName
        } else {
            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.name) -eq $false) {
                $strDisplayName = $pscustomobjectDeviceConfigProfile.name
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
                    $strDisplayName = $pscustomobjectDeviceConfigProfile.id
                } else {
                    $strDisplayName = ([guid]::NewGuid()).Guid.ToLower()
                }
            }
        }

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
            $strId = $pscustomobjectDeviceConfigProfile.id
        } else {
            $strId = ([guid]::NewGuid()).Guid.ToLower()
        }

        if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
            $strFileName = $strDisplayName + '_' + $strISO8601DateTimeNow
        } else {
            $strFileName = $strDisplayName
        }

        #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
        $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
        $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
        $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
        $strFileName = $strFileName + '.json'

        if ($hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.ContainsKey($strFileName) -eq $true) {
            # This device configuration profile is already flagged as a duplicate
            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileName = $strDisplayName + '_' + $strId + '_' + $strISO8601DateTimeNow
            } else {
                $strFileName = $strDisplayName + '_' + $strId
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
            $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
            $strFileName = $strFileName + '.json'

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)
            }
        } elseif ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName) -eq $true) {
            Write-Verbose ('Duplicate device config profile found named "' + $strFileName + '" Changing the planned file names to incorporate a GUID to allow duplicates to be exported.')
            if ($hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.ContainsKey($strFileName) -eq $false) {
                $hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.Add($strFileName, $null)
            }

            # First, remove the existing item from the hashtable and update its file name to incorporate its GUID
            $intDeviceConfigProfileToRenameHashtableNumber = $hashtableAllDeviceConfigProfileFileNames.Item($strFileName)
            $hashtableAllDeviceConfigProfileFileNames.Remove($strFileName)
            switch ($intDeviceConfigProfileToRenameHashtableNumber) {
                1 {
                    $refSubHashtableForRename = [ref]$hashtableAndroidEnterpriseOEMConfigProfileFileNames
                }
                2 {
                    $refSubHashtableForRename = [ref]$hashtableSettingsCatalogBasedProfileFileNames
                }
                3 {
                    $refSubHashtableForRename = [ref]$hashtableGroupPolicyBasedProfileFileNames
                }
                4 {
                    $refSubHashtableForRename = [ref]$hashtableTemplateBasedProfileFileNames
                }
            }
            $pscustomobjectDeviceConfigProfileToRename = ($refSubHashtableForRename.Value).Item($strFileName)
            ($refSubHashtableForRename.Value).Remove($strFileName)

            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.displayName) -eq $false) {
                $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.displayName
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.name) -eq $false) {
                    $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.name
                } else {
                    if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.id) -eq $false) {
                        $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.id
                    } else {
                        $strDisplayNameForItemToRename = ([guid]::NewGuid()).Guid.ToLower()
                    }
                }
            }

            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.id) -eq $false) {
                $strIdForItemToRename = $pscustomobjectDeviceConfigProfileToRename.id
            } else {
                $strIdForItemToRename = ([guid]::NewGuid()).Guid.ToLower()
            }

            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileNameForItemToRename = $strDisplayNameForItemToRename + '_' + $strIdForItemToRename + '_' + $strISO8601DateTimeNow
            } else {
                $strFileNameForItemToRename = $strDisplayNameForItemToRename + '_' + $strIdForItemToRename
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace ([regex]::Escape('.')), '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace ([regex]::Escape(' ')), '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename + '.json'

            if (($refSubHashtableForRename.Value).ContainsKey($strFileNameForItemToRename)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtableForRename.Value).Add($strFileNameForItemToRename, $pscustomobjectDeviceConfigProfileToRename)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileNameForItemToRename)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileNameForItemToRename, $intDeviceConfigProfileToRenameHashtableNumber)
            }

            # Now, with the existing item renamed, incorporate the GUID into the new
            # item's file name and then add it
            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileName = $strDisplayName + '_' + $strId + '_' + $strISO8601DateTimeNow
            } else {
                $strFileName = $strDisplayName + '_' + $strId
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
            $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
            $strFileName = $strFileName + '.json'

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)
            }
        } else {
            $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('The subordinate hashtable already contained the following file name even though the hashtable of all file names did not. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }
        }
    }

    foreach ($pscustomobjectDeviceConfigProfile in $arrPSCustomObjectSettingsCatalogBasedProfiles) {
        $refSubHashtable = [ref]$hashtableSettingsCatalogBasedProfileFileNames
        $intThisHashtableNumber = 2 # 2 = Settings Catalog-Based Device Configuration Profiles, $hashtableSettingsCatalogBasedProfileFileNames

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.displayName) -eq $false) {
            $strDisplayName = $pscustomobjectDeviceConfigProfile.displayName
        } else {
            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.name) -eq $false) {
                $strDisplayName = $pscustomobjectDeviceConfigProfile.name
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
                    $strDisplayName = $pscustomobjectDeviceConfigProfile.id
                } else {
                    $strDisplayName = ([guid]::NewGuid()).Guid.ToLower()
                }
            }
        }

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
            $strId = $pscustomobjectDeviceConfigProfile.id
        } else {
            $strId = ([guid]::NewGuid()).Guid.ToLower()
        }

        if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
            $strFileName = $strDisplayName + '_' + $strISO8601DateTimeNow
        } else {
            $strFileName = $strDisplayName
        }
        #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
        $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
        $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
        $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
        $strFileName = $strFileName + '.json'

        if ($hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.ContainsKey($strFileName) -eq $true) {
            # This device configuration profile is already flagged as a duplicate
            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileName = $strDisplayName + '_' + $strId + '_' + $strISO8601DateTimeNow
            } else {
                $strFileName = $strDisplayName + '_' + $strId
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
            $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
            $strFileName = $strFileName + '.json'

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)
            }
        } elseif ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName) -eq $true) {
            Write-Verbose ('Duplicate device config profile found named "' + $strFileName + '" Changing the planned file names to incorporate a GUID to allow duplicates to be exported.')
            if ($hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.ContainsKey($strFileName) -eq $false) {
                $hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.Add($strFileName, $null)
            }

            # First, remove the existing item from the hashtable and update its file name to incorporate its GUID
            $intDeviceConfigProfileToRenameHashtableNumber = $hashtableAllDeviceConfigProfileFileNames.Item($strFileName)
            $hashtableAllDeviceConfigProfileFileNames.Remove($strFileName)
            switch ($intDeviceConfigProfileToRenameHashtableNumber) {
                1 {
                    $refSubHashtableForRename = [ref]$hashtableAndroidEnterpriseOEMConfigProfileFileNames
                }
                2 {
                    $refSubHashtableForRename = [ref]$hashtableSettingsCatalogBasedProfileFileNames
                }
                3 {
                    $refSubHashtableForRename = [ref]$hashtableGroupPolicyBasedProfileFileNames
                }
                4 {
                    $refSubHashtableForRename = [ref]$hashtableTemplateBasedProfileFileNames
                }
            }
            $pscustomobjectDeviceConfigProfileToRename = ($refSubHashtableForRename.Value).Item($strFileName)
            ($refSubHashtableForRename.Value).Remove($strFileName)

            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.displayName) -eq $false) {
                $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.displayName
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.name) -eq $false) {
                    $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.name
                } else {
                    if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.id) -eq $false) {
                        $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.id
                    } else {
                        $strDisplayNameForItemToRename = ([guid]::NewGuid()).Guid.ToLower()
                    }
                }
            }

            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.id) -eq $false) {
                $strIdForItemToRename = $pscustomobjectDeviceConfigProfileToRename.id
            } else {
                $strIdForItemToRename = ([guid]::NewGuid()).Guid.ToLower()
            }

            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileNameForItemToRename = $strDisplayNameForItemToRename + '_' + $strIdForItemToRename + '_' + $strISO8601DateTimeNow
            } else {
                $strFileNameForItemToRename = $strDisplayNameForItemToRename + '_' + $strIdForItemToRename
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace ([regex]::Escape('.')), '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace ([regex]::Escape(' ')), '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename + '.json'

            if (($refSubHashtableForRename.Value).ContainsKey($strFileNameForItemToRename)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtableForRename.Value).Add($strFileNameForItemToRename, $pscustomobjectDeviceConfigProfileToRename)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileNameForItemToRename)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileNameForItemToRename, $intDeviceConfigProfileToRenameHashtableNumber)
            }

            # Now, with the existing item renamed, incorporate the GUID into the new
            # item's file name and then add it
            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileName = $strDisplayName + '_' + $strId + '_' + $strISO8601DateTimeNow
            } else {
                $strFileName = $strDisplayName + '_' + $strId
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
            $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
            $strFileName = $strFileName + '.json'

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)
            }
        } else {
            $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('The subordinate hashtable already contained the following file name even though the hashtable of all file names did not. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }
        }
    }

    foreach ($pscustomobjectDeviceConfigProfile in $arrPSCustomObjectGroupPolicyBasedProfiles) {
        $refSubHashtable = [ref]$hashtableGroupPolicyBasedProfileFileNames
        $intThisHashtableNumber = 3 # 3 = Group Policy-Based Device Configuration Profiles, $hashtableGroupPolicyBasedProfileFileNames

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.displayName) -eq $false) {
            $strDisplayName = $pscustomobjectDeviceConfigProfile.displayName
        } else {
            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.name) -eq $false) {
                $strDisplayName = $pscustomobjectDeviceConfigProfile.name
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
                    $strDisplayName = $pscustomobjectDeviceConfigProfile.id
                } else {
                    $strDisplayName = ([guid]::NewGuid()).Guid.ToLower()
                }
            }
        }

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
            $strId = $pscustomobjectDeviceConfigProfile.id
        } else {
            $strId = ([guid]::NewGuid()).Guid.ToLower()
        }

        if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
            $strFileName = $strDisplayName + '_' + $strISO8601DateTimeNow
        } else {
            $strFileName = $strDisplayName
        }
        #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
        $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
        $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
        $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
        $strFileName = $strFileName + '.json'

        if ($hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.ContainsKey($strFileName) -eq $true) {
            # This device configuration profile is already flagged as a duplicate
            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileName = $strDisplayName + '_' + $strId + '_' + $strISO8601DateTimeNow
            } else {
                $strFileName = $strDisplayName + '_' + $strId
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
            $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
            $strFileName = $strFileName + '.json'

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)
            }
        } elseif ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName) -eq $true) {
            Write-Verbose ('Duplicate device config profile found named "' + $strFileName + '" Changing the planned file names to incorporate a GUID to allow duplicates to be exported.')
            if ($hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.ContainsKey($strFileName) -eq $false) {
                $hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.Add($strFileName, $null)
            }

            # First, remove the existing item from the hashtable and update its file name to incorporate its GUID
            $intDeviceConfigProfileToRenameHashtableNumber = $hashtableAllDeviceConfigProfileFileNames.Item($strFileName)
            $hashtableAllDeviceConfigProfileFileNames.Remove($strFileName)
            switch ($intDeviceConfigProfileToRenameHashtableNumber) {
                1 {
                    $refSubHashtableForRename = [ref]$hashtableAndroidEnterpriseOEMConfigProfileFileNames
                }
                2 {
                    $refSubHashtableForRename = [ref]$hashtableSettingsCatalogBasedProfileFileNames
                }
                3 {
                    $refSubHashtableForRename = [ref]$hashtableGroupPolicyBasedProfileFileNames
                }
                4 {
                    $refSubHashtableForRename = [ref]$hashtableTemplateBasedProfileFileNames
                }
            }
            $pscustomobjectDeviceConfigProfileToRename = ($refSubHashtableForRename.Value).Item($strFileName)
            ($refSubHashtableForRename.Value).Remove($strFileName)

            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.displayName) -eq $false) {
                $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.displayName
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.name) -eq $false) {
                    $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.name
                } else {
                    if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.id) -eq $false) {
                        $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.id
                    } else {
                        $strDisplayNameForItemToRename = ([guid]::NewGuid()).Guid.ToLower()
                    }
                }
            }

            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.id) -eq $false) {
                $strIdForItemToRename = $pscustomobjectDeviceConfigProfileToRename.id
            } else {
                $strIdForItemToRename = ([guid]::NewGuid()).Guid.ToLower()
            }

            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileNameForItemToRename = $strDisplayNameForItemToRename + '_' + $strIdForItemToRename + '_' + $strISO8601DateTimeNow
            } else {
                $strFileNameForItemToRename = $strDisplayNameForItemToRename + '_' + $strIdForItemToRename
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace ([regex]::Escape('.')), '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace ([regex]::Escape(' ')), '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename + '.json'

            if (($refSubHashtableForRename.Value).ContainsKey($strFileNameForItemToRename)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtableForRename.Value).Add($strFileNameForItemToRename, $pscustomobjectDeviceConfigProfileToRename)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileNameForItemToRename)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileNameForItemToRename, $intDeviceConfigProfileToRenameHashtableNumber)
            }

            # Now, with the existing item renamed, incorporate the GUID into the new
            # item's file name and then add it
            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileName = $strDisplayName + '_' + $strId + '_' + $strISO8601DateTimeNow
            } else {
                $strFileName = $strDisplayName + '_' + $strId
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
            $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
            $strFileName = $strFileName + '.json'

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)
            }
        } else {
            $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('The subordinate hashtable already contained the following file name even though the hashtable of all file names did not. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }
        }
    }

    foreach ($pscustomobjectDeviceConfigProfile in $arrPSCustomObjectTemplateBasedProfiles) {
        $refSubHashtable = [ref]$hashtableTemplateBasedProfileFileNames
        $intThisHashtableNumber = 4 # 4 = Template-Based Device Configuration Profiles, $hashtableTemplateBasedProfileFileNames

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.displayName) -eq $false) {
            $strDisplayName = $pscustomobjectDeviceConfigProfile.displayName
        } else {
            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.name) -eq $false) {
                $strDisplayName = $pscustomobjectDeviceConfigProfile.name
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
                    $strDisplayName = $pscustomobjectDeviceConfigProfile.id
                } else {
                    $strDisplayName = ([guid]::NewGuid()).Guid.ToLower()
                }
            }
        }

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
            $strId = $pscustomobjectDeviceConfigProfile.id
        } else {
            $strId = ([guid]::NewGuid()).Guid.ToLower()
        }

        if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
            $strFileName = $strDisplayName + '_' + $strISO8601DateTimeNow
        } else {
            $strFileName = $strDisplayName
        }
        #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
        $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
        $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
        $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
        $strFileName = $strFileName + '.json'

        if ($hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.ContainsKey($strFileName) -eq $true) {
            # This device configuration profile is already flagged as a duplicate
            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileName = $strDisplayName + '_' + $strId + '_' + $strISO8601DateTimeNow
            } else {
                $strFileName = $strDisplayName + '_' + $strId
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
            $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
            $strFileName = $strFileName + '.json'

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)
            }
        } elseif ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName) -eq $true) {
            Write-Verbose ('Duplicate device config profile found named "' + $strFileName + '" Changing the planned file names to incorporate a GUID to allow duplicates to be exported.')
            if ($hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.ContainsKey($strFileName) -eq $false) {
                $hashtableAllDuplicateDeviceConfigProfileOriginalFileNames.Add($strFileName, $null)
            }

            # First, remove the existing item from the hashtable and update its file name to incorporate its GUID
            $intDeviceConfigProfileToRenameHashtableNumber = $hashtableAllDeviceConfigProfileFileNames.Item($strFileName)
            $hashtableAllDeviceConfigProfileFileNames.Remove($strFileName)
            switch ($intDeviceConfigProfileToRenameHashtableNumber) {
                1 {
                    $refSubHashtableForRename = [ref]$hashtableAndroidEnterpriseOEMConfigProfileFileNames
                }
                2 {
                    $refSubHashtableForRename = [ref]$hashtableSettingsCatalogBasedProfileFileNames
                }
                3 {
                    $refSubHashtableForRename = [ref]$hashtableGroupPolicyBasedProfileFileNames
                }
                4 {
                    $refSubHashtableForRename = [ref]$hashtableTemplateBasedProfileFileNames
                }
            }
            $pscustomobjectDeviceConfigProfileToRename = ($refSubHashtableForRename.Value).Item($strFileName)
            ($refSubHashtableForRename.Value).Remove($strFileName)

            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.displayName) -eq $false) {
                $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.displayName
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.name) -eq $false) {
                    $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.name
                } else {
                    if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.id) -eq $false) {
                        $strDisplayNameForItemToRename = $pscustomobjectDeviceConfigProfileToRename.id
                    } else {
                        $strDisplayNameForItemToRename = ([guid]::NewGuid()).Guid.ToLower()
                    }
                }
            }

            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfileToRename.id) -eq $false) {
                $strIdForItemToRename = $pscustomobjectDeviceConfigProfileToRename.id
            } else {
                $strIdForItemToRename = ([guid]::NewGuid()).Guid.ToLower()
            }

            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileNameForItemToRename = $strDisplayNameForItemToRename + '_' + $strIdForItemToRename + '_' + $strISO8601DateTimeNow
            } else {
                $strFileNameForItemToRename = $strDisplayNameForItemToRename + '_' + $strIdForItemToRename
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace ([regex]::Escape('.')), '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename -replace ([regex]::Escape(' ')), '_'
            $strFileNameForItemToRename = $strFileNameForItemToRename + '.json'

            if (($refSubHashtableForRename.Value).ContainsKey($strFileNameForItemToRename)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtableForRename.Value).Add($strFileNameForItemToRename, $pscustomobjectDeviceConfigProfileToRename)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileNameForItemToRename)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileNameForItemToRename, $intDeviceConfigProfileToRenameHashtableNumber)
            }

            # Now, with the existing item renamed, incorporate the GUID into the new
            # item's file name and then add it
            if ($DoNotIncludeDateInFileNames.IsPresent -eq $false) {
                $strFileName = $strDisplayName + '_' + $strId + '_' + $strISO8601DateTimeNow
            } else {
                $strFileName = $strDisplayName + '_' + $strId
            }
            #TODO: [IO.Path]::GetInvalidFileNameChars() and [IO.Path]::GetInvalidPathChars() to remove invalid characters from the file name
            $strFileName = $strFileName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $strFileName = $strFileName -replace ([regex]::Escape('.')), '_'
            $strFileName = $strFileName -replace ([regex]::Escape(' ')), '_'
            $strFileName = $strFileName + '.json'

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }

            if ($hashtableAllDeviceConfigProfileFileNames.ContainsKey($strFileName)) {
                Write-Warning ('Despite incorporating a GUID into the file name, a duplicate file name was still detected. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)
            }
        } else {
            $hashtableAllDeviceConfigProfileFileNames.Add($strFileName, $intThisHashtableNumber)

            if (($refSubHashtable.Value).ContainsKey($strFileName)) {
                Write-Warning ('The subordinate hashtable already contained the following file name even though the hashtable of all file names did not. This should never happen. Skipping processing on file "' + $strFileName + '".')
            } else {
                ($refSubHashtable.Value).Add($strFileName, $pscustomobjectDeviceConfigProfile)
            }
        }
    }
}
#endregion DetermineFileNamesAndDealWithDuplicates ####################################

#region WriteOutput ################################################################
if ($boolUseGraphAPIModule -eq $true) {
    #TODO: Code Graph API Module approach
} else {
    # Graph API REST approach

    # Write output for Android Enterprise OEMConfig-based profiles
    $strSubfolder = $strAndroidEnterpriseOEMConfigProfilesSubfolder
    foreach ($strFileName in ($hashtableAndroidEnterpriseOEMConfigProfileFileNames.Keys)) {
        $pscustomobjectDeviceConfigProfile = $hashtableAndroidEnterpriseOEMConfigProfileFileNames.Item($strFileName)

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.displayName) -eq $false) {
            $strDisplayName = $pscustomobjectDeviceConfigProfile.displayName
        } else {
            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.name) -eq $false) {
                $strDisplayName = $pscustomobjectDeviceConfigProfile.name
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
                    $strDisplayName = $pscustomobjectDeviceConfigProfile.id
                } else {
                    $strDisplayName = ''
                }
            }
        }

        Write-Verbose ('Exporting device configuration policy "' + $strDisplayName + '" to file "' + $strFileName + '".')
        Export-JSONData -JSON $pscustomobjectDeviceConfigProfile -ExportPath $strSubfolder -FileName $strFileName
    }

    # Write output for settings catalog based profiles
    $strSubfolder = $strSettingsCatalogBasedProfilesSubfolder
    foreach ($strFileName in ($hashtableSettingsCatalogBasedProfileFileNames.Keys)) {
        $pscustomobjectDeviceConfigProfile = $hashtableSettingsCatalogBasedProfileFileNames.Item($strFileName)

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.displayName) -eq $false) {
            $strDisplayName = $pscustomobjectDeviceConfigProfile.displayName
        } else {
            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.name) -eq $false) {
                $strDisplayName = $pscustomobjectDeviceConfigProfile.name
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
                    $strDisplayName = $pscustomobjectDeviceConfigProfile.id
                } else {
                    $strDisplayName = ''
                }
            }
        }

        Write-Verbose ('Exporting device configuration policy "' + $strDisplayName + '" to file "' + $strFileName + '".')
        Export-JSONData -JSON $pscustomobjectDeviceConfigProfile -ExportPath $strSubfolder -FileName $strFileName
    }

    # Write output for Group Policy-based profiles
    $strSubfolder = $strGroupPolicyBasedProfilesSubfolder
    foreach ($strFileName in ($hashtableGroupPolicyBasedProfileFileNames.Keys)) {
        $pscustomobjectDeviceConfigProfile = $hashtableGroupPolicyBasedProfileFileNames.Item($strFileName)

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.displayName) -eq $false) {
            $strDisplayName = $pscustomobjectDeviceConfigProfile.displayName
        } else {
            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.name) -eq $false) {
                $strDisplayName = $pscustomobjectDeviceConfigProfile.name
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
                    $strDisplayName = $pscustomobjectDeviceConfigProfile.id
                } else {
                    $strDisplayName = ''
                }
            }
        }

        Write-Verbose ('Exporting device configuration policy "' + $strDisplayName + '" to file "' + $strFileName + '".')
        Export-JSONData -JSON $pscustomobjectDeviceConfigProfile -ExportPath $strSubfolder -FileName $strFileName
    }

    # Write output for template-based profiles
    $strSubfolder = $strTemplateBasedProfilesSubfolder
    foreach ($strFileName in ($hashtableTemplateBasedProfileFileNames.Keys)) {
        $pscustomobjectDeviceConfigProfile = $hashtableTemplateBasedProfileFileNames.Item($strFileName)

        if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.displayName) -eq $false) {
            $strDisplayName = $pscustomobjectDeviceConfigProfile.displayName
        } else {
            if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.name) -eq $false) {
                $strDisplayName = $pscustomobjectDeviceConfigProfile.name
            } else {
                if ([string]::IsNullOrEmpty($pscustomobjectDeviceConfigProfile.id) -eq $false) {
                    $strDisplayName = $pscustomobjectDeviceConfigProfile.id
                } else {
                    $strDisplayName = ''
                }
            }
        }

        Write-Verbose ('Exporting device configuration policy "' + $strDisplayName + '" to file "' + $strFileName + '".')
        Export-JSONData -JSON $pscustomobjectDeviceConfigProfile -ExportPath $strSubfolder -FileName $strFileName
    }
}
#endregion WriteOutput ################################################################

if ($null -ne $script:versionPowerShell) {
    if ($script:versionPowerShell -ge [version]'5.0') {
        Write-Information 'Device configuration policy export script completed.'
    } else {
        Write-Output 'Device configuration policy export script completed.'
    }
} else {
    Write-Output 'Device configuration policy export script completed.'
}
