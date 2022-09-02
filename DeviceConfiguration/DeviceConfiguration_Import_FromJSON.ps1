
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>
[cmdletbinding()]
param ( [Parameter(Mandatory = $false)][String]$fileName )

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

    param (
        [Parameter(Mandatory = $true)]
        $user
    )

    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

    $tenant = $userUpn.Host

    Write-Host "Checking for AzureAD module..."

    $aadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($null -eq $aadModule) {
        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $aadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    }

    if ($null -eq $aadModule) {
        Write-Host
        Write-Host "AzureAD Powershell module not installed..." -ForegroundColor Red
        Write-Host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -ForegroundColor Yellow
        Write-Host "Script can't continue..." -ForegroundColor Red
        Write-Host
        exit
    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if ($aadModule.count -gt 1) {

        $latestVersion = ($aadModule | Select-Object Version | Sort-Object)[-1]

        $aadModule = $aadModule | Where-Object { $_.Version -eq $latestVersion.version }

        # Checking if there are multiple versions of the same module found

        if ($aadModule.Count -gt 1) {
            $aadModule = $aadModule | Select-Object -Unique
        }

        $adal = Join-Path $aadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $aadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    } else {
        $adal = Join-Path $aadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $aadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    }

    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    $resourceAppIdURI = "https://graph.microsoft.com"

    $authority = "https://login.microsoftonline.com/$Tenant"

    try {
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($user, "OptionalDisplayableId")

        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result

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
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host $_.Exception.ItemName -ForegroundColor Red
        Write-Host
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
    Add-DeviceConfigurationPolicy -JSON $JSON
    Adds a device configuration policy in Intune
    .NOTES
    NAME: Add-DeviceConfigurationPolicy
    #>

    [cmdletbinding()]

    param (
        $json
    )

    $graphApiVersion = "Beta"
    $dcpResource = "deviceManagement/deviceConfigurations"
    Write-Verbose "Resource: $dcpResource"

    try {
        if ([string]::IsNullOrEmpty($json)) {
            Write-Host "No JSON specified, please specify valid JSON for the Device Configuration Policy..." -ForegroundColor Red
        } else {
            Test-JSON -JSON $json

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($dcpResource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $json -ContentType "application/json"
        }
    } catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -ForegroundColor Red
        Write-Error "Request to $uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    }
}

#region DefineTestJSONIfNotAlreadyDefined ##########################################

#TODO: Make Test-JSON return a true/false value instead of just writing a message to the screen
$strTestJSONFunctionDefinition = @'
function Test-JSON {
    <#
    .SYNOPSIS
    This function is used to test if the JSON passed to a REST Post request is valid
    .DESCRIPTION
    The function tests if the JSON passed to the REST Post is valid
    .EXAMPLE
    Test-JSON -JSON $json
    Test if the JSON is valid before calling the Graph REST interface
    .NOTES
    NAME: Test-AuthHeader
    #>

    param (
        $json
    )

    try {
        $testJSON = ConvertFrom-Json $json -ErrorAction Stop
        $validJSON = $true
    } catch {
        $validJSON = $false
        $_.Exception
    }

    if (!$validJSON) {
        Write-Host "Provided JSON isn't in valid JSON format" -f Red
        break
    }
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

Write-Host

# Checking if authToken exists before running authentication
if ($global:authToken) {

    # Setting DateTime to Universal time to work in all timezones
    $datetime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $tokenExpires = ($authToken.ExpiresOn.Datetime - $datetime).Minutes

    if ($tokenExpires -le 0) {
        Write-Host ("Authentication Token expired" + $tokenExpires + "minutes ago") -ForegroundColor Yellow
        Write-Host

        # Defining User Principal Name if not present

        if ([string]::IsNullOrEmpty($user)) {
            $user = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host
        }

        $global:authToken = Get-AuthToken -User $user
    }
} else {
    # Authentication doesn't exist, calling Get-AuthToken function

    if ($null -eq $user -or $user -eq "") {
        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        Write-Host
    }

    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $user
}

#endregion

####################################################

$importPath = $null
if ([string]::IsNullOrEmpty($fileName) -eq $false) {
    if (Test-Path -Path $fileName -Type Leaf) {
        $importPath = $fileName
    }
}
while ($null -eq $importPath) {
    $fileName = Read-Host -Prompt 'Please specify a path to a JSON file to import data from e.g. C:\IntuneOutput\Policies\policy.json'
    if ([string]::IsNullOrEmpty($fileName) -eq $false) {
        if (Test-Path -Path $fileName -Type Leaf) {
            $importPath = $fileName
        }
    }
    if ($null -eq $importPath) {
        Write-Warning 'Invalid path! Please try again...'
    }
}

# Replacing quotes for Test-Path
$importPath = $importPath.Replace('"', '')

if (!(Test-Path "$importPath")) {
    Write-Host "Import Path for JSON file doesn't exist..." -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break
}

####################################################

$jsonData = Get-Content "$importPath"

# Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
$jsonConvert = $jsonData | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, supportsScopeTags

$displayName = $jsonConvert.displayName

$jsonOutput = $jsonConvert | ConvertTo-Json -Depth 5

Write-Host
Write-Host "Device Configuration Policy '$DisplayName' Found..." -ForegroundColor Yellow
Write-Host
$jsonOutput
Write-Host
Write-Host "Adding Device Configuration Policy '$DisplayName'" -ForegroundColor Yellow
Add-DeviceConfigurationPolicy -JSON $jsonOutput
