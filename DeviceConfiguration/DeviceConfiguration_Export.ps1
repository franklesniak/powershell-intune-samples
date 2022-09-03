
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
[cmdletbinding()]
param (
    [Parameter(Mandatory = $false)][String]$ExportPath,
    [Parameter(Mandatory = $false)][String]$UserPrincipalName
)

$strThisScriptVersionNumber = [version]'1.1.20220903.0'

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

    $arrModuleAzureAD = @(Get-Module -Name 'AzureAD' -ListAvailable)

    if ($arrModuleAzureAD.Count -eq 0) {
        Write-Verbose 'AzureAD PowerShell module not found, looking for AzureADPreview'
        $arrModuleAzureAD = @(Get-Module -Name 'AzureADPreview' -ListAvailable)
    }

    if ($arrModuleAzureAD.Count -eq 0) {
        Write-Error ('AzureAD Powershell module not installed...' + "`n" + 'Install by running "Install-Module AzureAD" or "Install-Module AzureADPreview" from an elevated PowerShell prompt' + "`n" + 'Script cannot continue...')
        exit
    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if ($arrModuleAzureAD.Count -gt 1) {

        $versionNewestInstalledAzureADModule = ($arrModuleAzureAD | Select-Object Version | Sort-Object)[-1]

        $arrModuleNewestAzureAD = @($arrModuleAzureAD | Where-Object { $_.Version -eq $versionNewestInstalledAzureADModule.Version })

        # Checking if there are multiple versions of the same module found

        if ($arrModuleNewestAzureAD.Count -gt 1) {
            $moduleAzureAD = @($arrModuleNewestAzureAD | Select-Object -Unique)[0]
        } else {
            $moduleAzureAD = $arrModuleNewestAzureAD[0]
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

function Get-DeviceConfigurationPolicy {
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicy
    #>

    [cmdletbinding()]

    $strGraphAPIVersion = 'Beta'
    $strDCPResource = 'deviceManagement/deviceConfigurations'

    try {
        $strURI = 'https://graph.microsoft.com/' + $strGraphAPIVersion + '/' + $strDCPResource
        (Invoke-RestMethod -Uri $strURI -Headers $global:hashtableAuthToken -Method Get).Value
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

####################################################

function Export-JSONData {
    <#
    .SYNOPSIS
    This function is used to export JSON data returned from Graph
    .DESCRIPTION
    This function is used to export JSON data returned from Graph
    .EXAMPLE
    Export-JSONData -JSON $JSON
    Export the JSON inputted on the function
    .NOTES
    NAME: Export-JSONData
    #>

    param (
        $JSON,
        $ExportPath
    )

    try {

        if ([string]::IsNullOrEmpty($JSON)) {
            Write-Error 'No JSON specified, please specify valid JSON...'
        } elseif (!$ExportPath) {
            Write-Error 'No export path parameter set, please provide a path to export the file'
        } elseif (!(Test-Path $ExportPath)) {
            Write-Error ($ExportPath + ' does not exist, cannot export JSON Data')
        } else {
            $strJSON = ConvertTo-Json $JSON -Depth 5

            $pscustomobjectConvertedJSON = $strJSON | ConvertFrom-Json

            $strDisplayName = $pscustomobjectConvertedJSON.displayName

            # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
            $strDisplayName = $strDisplayName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'

            $strJSONExportFileName = $strDisplayName + '_' + (Get-Date -Format 'yyyy-MM-dd-HH-mm-ss') + '.json'

            Write-Verbose ('Export Path: "' + $ExportPath + '"')

            $strJSON | Set-Content -LiteralPath ($ExportPath + '\' + $strJSONExportFileName)
            Write-Verbose ('JSON created in ' + $ExportPath + '\' + $strJSONExportFileName + '...')
        }
    } catch {
        $_.Exception
    }
}

####################################################

#region Authentication #############################################################

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

# Filtering out iOS and Windows Software Update Policies
$arrPSCustomObjectDeviceConfigurationPolicies = @(Get-DeviceConfigurationPolicy | Where-Object { ($_.'@odata.type' -ne '#microsoft.graph.iosUpdateConfiguration') -and ($_.'@odata.type' -ne '#microsoft.graph.windowsUpdateForBusinessConfiguration') })
foreach ($pscustomobjectDeviceConfigurationPolicy in $arrPSCustomObjectDeviceConfigurationPolicies) {
    Write-Verbose ('Device Configuration Policy: ' + $pscustomobjectDeviceConfigurationPolicy.displayName)
    Export-JSONData -JSON $pscustomobjectDeviceConfigurationPolicy -ExportPath $strExportPath
}

Write-Output 'Device configuration policy export script completed.'
