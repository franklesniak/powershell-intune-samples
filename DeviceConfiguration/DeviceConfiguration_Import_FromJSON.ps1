
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
[cmdletbinding()]
param (
    [Parameter(Mandatory = $false)][String]$FileName,
    [Parameter(Mandatory = $false)][String]$FilePath,
    [Parameter(Mandatory = $false)][String]$UserPrincipalName,
    [Parameter(Mandatory = $false)][Switch]$UseGraphAPIModule,
    [Parameter(Mandatory = $false)][Switch]$UseGraphAPIREST,
    [Parameter(Mandatory = $false)][Switch]$DoNotCheckForModuleUpdates
)
# FilePath parameter is preferable becasue it's more clear, but FileName is kept for backward compatibility

$strThisScriptVersionNumber = [version]'1.1.20220903.0'

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

function Add-DeviceConfigurationPolicy {
    <#
    .SYNOPSIS
    This function is used to add an device configuration policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device configuration policy
    .EXAMPLE
    Add-DeviceConfigurationPolicy -JSON $strJSON
    Adds a device configuration policy in Intune
    .NOTES
    NAME: Add-DeviceConfigurationPolicy
    #>

    [cmdletbinding()]

    param (
        $JSON
    )

    $strGraphAPIVersion = 'Beta'
    $strDCPResource = 'deviceManagement/deviceConfigurations'
    Write-Verbose ('Resource: ' + $strDCPResource)

    try {
        if ([string]::IsNullOrEmpty($JSON)) {
            Write-Output 'Error: No JSON specified, please specify valid JSON for the Device Configuration Policy...'
        } else {
            $boolResult = Test-JSON -JSON $JSON
            if ($boolResult) {
                $strURI = 'https://graph.microsoft.com/' + $strGraphAPIVersion + '/' + $strDCPResource
                Invoke-RestMethod -Uri $strURI -Headers $global:hashtableAuthToken -Method Post -Body $JSON -ContentType 'application/json'
            } else {
                Write-Output 'Error: JSON is not valid, please specify valid JSON for the Device Configuration Policy...'
            }
        }
    } catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Error ('Request to ' + $strURI + ' failed with HTTP Status ' + $ex.Response.StatusCode + ' ' + $ex.Response.StatusDescription + ' - the response content was: ' + "`n" + $responseBody)
        break
    }
}

#region DefineTestJSONIfNotAlreadyDefined ##########################################

$strTestJSONFunctionDefinition = @'
function Test-JSON {
    <#
    .SYNOPSIS
    This function is used to test if the JSON passed to a REST Post request is valid
    .DESCRIPTION
    The function tests if the JSON passed to the REST Post is valid
    .EXAMPLE
    Test-JSON -JSON $strJSON
    Test if the JSON is valid before calling the Graph REST interface
    .NOTES
    NAME: Test-AuthHeader
    #>

    param (
        $JSON
    )

    try {
        $JSONTest = ConvertFrom-Json $JSON -ErrorAction Stop
        $boolValidJSON = $true
    } catch {
        $boolValidJSON = $false
        # $_.Exception
    }

    return $boolValidJSON
}
'@

$scriptBlockTestJSONFunctionDefinition = [scriptblock]::Create($strTestJSONFunctionDefinition)

$arrTestJSONCommands = @(Get-Command -Name 'Test-JSON' -ErrorAction SilentlyContinue)

if ($arrTestJSONCommands.Count -eq 0) {
    # Test-JSON function is not defined
    # Run the scriptblock in the current context
    . $scriptBlockTestJSONFunctionDefinition
}

#endregion DefineTestJSONIfNotAlreadyDefined ##########################################

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

#region GetImportPath ##############################################################
$strImportPath = $null
if ([string]::IsNullOrEmpty($FilePath)) {
    # FilePath parameter was not specified; check FileName parameter
    if ([string]::IsNullOrEmpty($FileName) -eq $false) {
        $FilePath = $FileName
    }
}
if ([string]::IsNullOrEmpty($FilePath) -eq $false) {
    # Replace quotes for Test-Path
    $FilePath = $FilePath.Replace('"', '')
    if (Test-Path -Path $FilePath -Type Leaf) {
        $strImportPath = $FilePath
    }
}
while ($null -eq $strImportPath) {
    $FilePath = Read-Host -Prompt 'Please specify a path to a JSON file to import data from e.g. C:\IntuneOutput\Policies\policy.json'
    if ([string]::IsNullOrEmpty($FilePath) -eq $false) {
        # Replace quotes for Test-Path
        $FilePath = $FilePath.Replace('"', '')
        if (Test-Path -Path $FilePath -Type Leaf) {
            $strImportPath = $FilePath
        }
    }
    if ($null -eq $strImportPath) {
        Write-Warning 'Invalid path! Please try again...'
    }
}

if (!(Test-Path $strImportPath)) {
    Write-Error 'Import Path for JSON file does not exist... script cannot continue!'
    break
}
#endregion GetImportPath ##############################################################

#region PerformImport ##############################################################
if ($boolUseGraphAPIModule -eq $true) {
    #TODO: Code Graph API Module approach
} else {
    # Graph API REST approach
    $strJSON = Get-Content $strImportPath

    # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
    $pscustomobjectConvertedJSON = $strJSON | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags

    $strDisplayName = $pscustomobjectConvertedJSON.displayName

    $strJSONOutput = $pscustomobjectConvertedJSON | ConvertTo-Json -Depth 8

    Write-Verbose ('Device Configuration Policy "' + $strDisplayName + '" Found...')
    Write-Debug $strJSONOutput
    Write-Verbose ('Adding Device Configuration Policy "' + $strDisplayName + '"')
    Add-DeviceConfigurationPolicy -JSON $strJSONOutput
}
#endregion PerformImport ##############################################################

if ($null -ne $script:versionPowerShell) {
    if ($script:versionPowerShell -ge [version]'5.0') {
        Write-Information ('Done adding Device Configuration Policy "' + $strDisplayName + '"')
    } else {
        Write-Output ('Done adding Device Configuration Policy "' + $strDisplayName + '"')
    }
} else {
    Write-Output ('Done adding Device Configuration Policy "' + $strDisplayName + '"')
}
