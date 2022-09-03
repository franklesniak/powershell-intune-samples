
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
[cmdletbinding()]
param ( [Parameter(Mandatory = $false)][String]$FileName )
# TODO: $FilePath would make more sense than $FileName

$strThisScriptVersionNumber = [version]'1.0.20220903.0'

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
                'Authorization' = "Bearer " + $authResult.AccessToken
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

#region Authentication

# Checking if hashtableAuthToken exists before running authentication
if ($global:hashtableAuthToken) {

    # Setting DateTime to Universal time to work in all timezones
    $datetimeUTC = (Get-Date).ToUniversalTime()

    # If the hashtableAuthToken exists checking when it expires
    $intMinutesSinceTokenExpiration = ($datetimeUTC - $hashtableAuthToken.ExpiresOn.Datetime).Minutes

    if ($intMinutesSinceTokenExpiration -ge 0) {
        Write-Output ('Authentication Token expired ' + $intMinutesSinceTokenExpiration + ' minutes ago')

        # Defining User Principal Name if not present

        if ([string]::IsNullOrEmpty($strUPN)) {
            $strUPN = Read-Host -Prompt 'Please specify your user principal name for Azure authentication'
        }

        $global:hashtableAuthToken = Get-AuthToken -User $strUPN
    }
} else {
    # Authentication doesn't exist, calling Get-AuthToken function

    if ([string]::IsNullOrEmpty($strUPN)) {
        $strUPN = Read-Host -Prompt 'Please specify your user principal name for Azure authentication'
    }

    # Getting the authorization token
    $global:hashtableAuthToken = Get-AuthToken -User $strUPN
}

#endregion

####################################################

$strImportPath = $null
if ([string]::IsNullOrEmpty($FileName) -eq $false) {
    # Replace quotes for Test-Path
    $FileName = $FileName.Replace('"', '')
    if (Test-Path -Path $FileName -Type Leaf) {
        $strImportPath = $FileName
    }
}
while ($null -eq $strImportPath) {
    $FileName = Read-Host -Prompt 'Please specify a path to a JSON file to import data from e.g. C:\IntuneOutput\Policies\policy.json'
    if ([string]::IsNullOrEmpty($FileName) -eq $false) {
        # Replace quotes for Test-Path
        $FileName = $FileName.Replace('"', '')
        if (Test-Path -Path $FileName -Type Leaf) {
            $strImportPath = $FileName
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

####################################################

$strJSON = Get-Content $strImportPath

# Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
$pscustomobjectConvertedJSON = $strJSON | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags

$strDisplayName = $pscustomobjectConvertedJSON.displayName

$strJSONOutput = $pscustomobjectConvertedJSON | ConvertTo-Json -Depth 5

Write-Verbose ('Device Configuration Policy "' + $strDisplayName + '" Found...')
Write-Debug $strJSONOutput
Write-Verbose ('Adding Device Configuration Policy "' + $strDisplayName + '"')
Add-DeviceConfigurationPolicy -JSON $strJSONOutput
Write-Output ('Done adding Device Configuration Policy "' + $strDisplayName + '"')
