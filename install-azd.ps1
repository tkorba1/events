#!/usr/bin/env pwsh
<#
.SYNOPSIS
Download and install azd on the local machine.

.DESCRIPTION
Downloads and installs azd on the local machine. Includes ability to configure
download and install locations.

.PARAMETER BaseUrl
Specifies the base URL to use when downloading. Default is
https://azd-release-gfgac2cmf7b8cuay.b02.azurefd.net/azd/standalone/release

.PARAMETER Version
Specifies the version to use. Default is `latest`. Valid values include a
SemVer version number (e.g. 1.0.0 or 1.1.0-beta.1), `latest`, `daily`

.PARAMETER DryRun
Print the download URL and quit. Does not download or install.

.PARAMETER InstallFolder
Location to install azd.

.PARAMETER SymlinkFolder
(Mac/Linux only) Folder to symlink 

.PARAMETER DownloadTimeoutSeconds
Download timeout in seconds. Default is 120 (2 minutes).

.PARAMETER SkipVerify
Skips verification of the downloaded file.

.PARAMETER InstallShScriptUrl
(Mac/Linux only) URL to the install-azd.sh script. Default is https://aka.ms/install-azd.sh

.EXAMPLE
powershell -ex AllSigned -c "Invoke-RestMethod 'https://aka.ms/install-azd.ps1' | Invoke-Expression"

Install the azd CLI from a Windows shell

The use of `-ex AllSigned` is intended to handle the scenario where a machine's
default execution policy is restricted such that modules used by
`install-azd.ps1` cannot be loaded. Because this syntax is piping output from
`Invoke-RestMethod` to `Invoke-Expression` there is no direct valication of the
`install-azd.ps1` script's signature. Validation of the script can be
accomplished by downloading the script to a file and executing the script file.

.EXAMPLE
Invoke-RestMethod 'https://aka.ms/install-azd.ps1' -OutFile 'install-azd.ps1'
PS > ./install-azd.ps1

Download the installer and execute from PowerShell

.EXAMPLE
Invoke-RestMethod 'https://aka.ms/install-azd.ps1' -OutFile 'install-azd.ps1'
PS > ./install-azd.ps1 -Version daily

Download the installer and install the "daily" build
#>

param(
    [string] $BaseUrl = "https://azd-release-gfgac2cmf7b8cuay.b02.azurefd.net/azd/standalone/release",
    [string] $Version = "stable",
    [switch] $DryRun,
    [string] $InstallFolder,
    [string] $SymlinkFolder,
    [switch] $SkipVerify,
    [int] $DownloadTimeoutSeconds = 120,
    [switch] $NoTelemetry,
    [string] $InstallShScriptUrl = "https://aka.ms/install-azd.sh"
)

function isLinuxOrMac {
    return $IsLinux -or $IsMacOS
}

# Does some very basic parsing of /etc/os-release to output the value present in
# the file. Since only lines that start with '#' are to be treated as comments
# according to `man os-release` there is no additional parsing of comments
# Options like:
# bash -c "set -o allexport; source /etc/os-release;set +o allexport; echo $VERSION_ID"
# were considered but it's possible that bash is not installed on the system and
# these commands would not be available.
function getOsReleaseValue($key) {
    $value = $null
    foreach ($line in Get-Content '/etc/os-release') {
        if ($line -like "$key=*") {
            # 'ID="value" -> @('ID', '"value"')
            $splitLine = $line.Split('=', 2)

            # Remove surrounding whitespaces and quotes
            # ` "value" ` -> `value`
            # `'value'` -> `value`
            $value = $splitLine[1].Trim().Trim(@("`"", "'"))
        }
    }
    return $value
}

function getOs {
    $os = [Environment]::OSVersion.Platform.ToString()
    try {
        if (isLinuxOrMac) {
            if ($IsLinux) {
                $os = getOsReleaseValue 'ID'
            } elseif ($IsMacOs) {
                $os = sw_vers -productName
            }
        }
    } catch {
        Write-Error "Error getting OS name $_"
        $os = "error"
    }
    return $os
}

function getOsVersion {
    $version = [Environment]::OSVersion.Version.ToString()
    try {
        if (isLinuxOrMac) {
            if ($IsLinux) {
                $version = getOsReleaseValue 'VERSION_ID'
            } elseif ($IsMacOS) {
                $version = sw_vers -productVersion
            }
        }
    } catch {
        Write-Error "Error getting OS version $_"
        $version = "error"
    }
    return $version
}

function isWsl {
    $isWsl = $false
    if ($IsLinux) {
        $kernelRelease = uname --kernel-release
        if ($kernelRelease -like '*wsl*') {
            $isWsl = $true
        }
    }
    return $isWsl
}

function getTerminal {
    return (Get-Process -Id $PID).ProcessName
}

function getExecutionEnvironment {
    $executionEnvironment = 'Desktop'
    if ($env:GITHUB_ACTIONS) {
        $executionEnvironment = 'GitHub Actions'
    } elseif ($env:SYSTEM_TEAMPROJECTID) {
        $executionEnvironment = 'Azure DevOps'
    }
    return $executionEnvironment
}

function promptForTelemetry {
    # UserInteractive may return $false if the session is not interactive
    # but this does not work in 100% of cases. For example, running:
    # "powershell -NonInteractive -c '[Environment]::UserInteractive'"
    # results in output of "True" even though the shell is not interactive.
    if (![Environment]::UserInteractive) {
        return $false
    }

    Write-Host "Answering 'yes' below will send data to Microsoft. To learn more about data collection see:"
    Write-Host "https://go.microsoft.com/fwlink/?LinkId=521839"
    Write-Host ""
    Write-Host "You can also file an issue at https://github.com/Azure/azure-dev/issues/new?assignees=&labels=&template=issue_report.md&title=%5BIssue%5D"

    try {
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription `
            "&Yes", `
            "Sends failure report to Microsoft"
        $no = New-Object System.Management.Automation.Host.ChoiceDescription `
            "&No", `
            "Exits the script without sending a failure report to Microsoft (Default)"
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $decision = $Host.UI.PromptForChoice( `
            'Confirm issue report', `
            'Do you want to send diagnostic data about the failure to Microsoft?', `
            $options, `
            1 `                     # Default is 'No'
        )

        # Return $true if user consents
        return $decision -eq 0
    } catch {
        # Failure to prompt generally indicates that the environment is not
        # interactive and the default resposne can be assumed.
        return $false
    }
}

function reportTelemetryIfEnabled($eventName, $reason='', $additionalProperties = @{}) {
    if ($NoTelemetry -or $env:AZURE_DEV_COLLECT_TELEMETRY -eq 'no') {
        Write-Verbose "Telemetry disabled. No telemetry reported." -Verbose:$Verbose
        return
    }

    $IKEY = 'a9e6fa10-a9ac-4525-8388-22d39336ecc2'

    $telemetryObject = @{
        iKey = $IKEY;
        name = "Microsoft.ApplicationInsights.$($IKEY.Replace('-', '')).Event";
        time = (Get-Date).ToUniversalTime().ToString('o');
        data = @{
            baseType = 'EventData';
            baseData = @{
                ver = 2;
                name = $eventName;
                properties = @{
                    installVersion = $Version;
                    reason = $reason;
                    os = getOs;
                    osVersion = getOsVersion;
                    isWsl = isWsl;
                    terminal = getTerminal;
                    executionEnvironment = getExecutionEnvironment;
                };
            }
        }
    }

    # Add entries from $additionalProperties. These may overwrite existing
    # entries in the properties field.
    if ($additionalProperties -and $additionalProperties.Count) {
        foreach ($entry in $additionalProperties.GetEnumerator()) {
            $telemetryObject.data.baseData.properties[$entry.Name] = $entry.Value
        }
    }

    Write-Host "An error was encountered during install: $reason"
    Write-Host "Error data collected:"
    $telemetryDataTable = $telemetryObject.data.baseData.properties | Format-Table | Out-String
    Write-Host $telemetryDataTable
    if (!(promptForTelemetry)) {
        # The user responded 'no' to the telemetry prompt or is in a
        # non-interactive session. Do not send telemetry.
        return
    }

    try {
        Invoke-RestMethod `
            -Uri 'https://centralus-2.in.applicationinsights.azure.com/v2/track' `
            -ContentType 'application/json' `
            -Method Post `
            -Body (ConvertTo-Json -InputObject $telemetryObject -Depth 100 -Compress) | Out-Null
        Write-Verbose -Verbose:$Verbose "Telemetry posted"
    } catch {
        Write-Host $_
        Write-Verbose -Verbose:$Verbose "Telemetry post failed"
    }
}

if (isLinuxOrMac) {
    if (!(Get-Command curl)) { 
        Write-Error "Command could not be found: curl."
        exit 1
    }
    if (!(Get-Command bash)) { 
        Write-Error "Command could not be found: bash."
        exit 1
    }

    $params = @(
        '--base-url', "'$BaseUrl'", 
        '--version', "'$Version'"
    )

    if ($InstallFolder) {
        $params += '--install-folder', "'$InstallFolder'"
    }

    if ($SymlinkFolder) {
        $params += '--symlink-folder', "'$SymlinkFolder'"
    }

    if ($SkipVerify) { 
        $params += '--skip-verify'
    }

    if ($DryRun) {
        $params += '--dry-run'
    }

    if ($NoTelemetry) {
        $params += '--no-telemetry'
    }

    if ($VerbosePreference -eq 'Continue') {
        $params += '--verbose'
    }

    $bashParameters = $params -join ' '
    Write-Verbose "Running: curl -fsSL $InstallShScriptUrl | bash -s -- $bashParameters" -Verbose:$Verbose
    bash -c "curl -fsSL $InstallShScriptUrl | bash -s -- $bashParameters"
    exit $LASTEXITCODE
}

try {
    $packageFilename = "azd-windows-amd64.msi"

    $downloadUrl = "$BaseUrl/$packageFilename"
    if ($Version) {
        $downloadUrl = "$BaseUrl/$Version/$packageFilename"
    }

    if ($DryRun) {
        Write-Host $downloadUrl
        exit 0
    }

    $tempFolder = "$([System.IO.Path]::GetTempPath())$([System.IO.Path]::GetRandomFileName())"
    Write-Verbose "Creating temporary folder for downloading package: $tempFolder"
    New-Item -ItemType Directory -Path $tempFolder | Out-Null

    Write-Verbose "Downloading build from $downloadUrl" -Verbose:$Verbose
    $releaseArtifactFilename = Join-Path $tempFolder $packageFilename
    try {
        $global:LASTEXITCODE = 0
        Invoke-WebRequest -Uri $downloadUrl -OutFile $releaseArtifactFilename -TimeoutSec $DownloadTimeoutSeconds
        if ($LASTEXITCODE) {
            throw "Invoke-WebRequest failed with nonzero exit code: $LASTEXITCODE"
        }
    } catch {
        Write-Error -ErrorRecord $_
        reportTelemetryIfEnabled 'InstallFailed' 'DownloadFailed' @{ downloadUrl = $downloadUrl }
        exit 1
    }
   

    try {
        if (!$SkipVerify) {
            try {
                Write-Verbose "Verifying signature of $releaseArtifactFilename" -Verbose:$Verbose
                $signature = Get-AuthenticodeSignature $releaseArtifactFilename
                if ($signature.Status -ne 'Valid') {
                    Write-Error "Signature of $releaseArtifactFilename is not valid"
                    reportTelemetryIfEnabled 'InstallFailed' 'SignatureVerificationFailed'
                    exit 1
                }
            } catch {
                Write-Error -ErrorRecord $_
                reportTelemetryIfEnabled 'InstallFailed' 'SignatureVerificationFailed'
                exit 1
            }
        }

        Write-Verbose "Installing MSI" -Verbose:$Verbose
        $MSIEXEC = "${env:SystemRoot}\System32\msiexec.exe"
        $installProcess = Start-Process $MSIEXEC `
            -ArgumentList @("/i", "`"$releaseArtifactFilename`"", "/qn", "INSTALLDIR=`"$InstallFolder`"", "INSTALLEDBY=`"install-azd.ps1`"") `
            -PassThru `
            -Wait

        if ($installProcess.ExitCode) {
            if ($installProcess.ExitCode -eq 1603) {
                Write-Host "A later version of Azure Developer CLI may already be installed. Use 'Add or remove programs' to uninstall that version and try again."
            }

            Write-Error "Could not install MSI at $releaseArtifactFilename. msiexec.exe returned exit code: $($installProcess.ExitCode)"

            reportTelemetryIfEnabled 'InstallFailed' 'MsiFailure' @{ msiExitCode = $installProcess.ExitCode }
            exit 1
        }
    } catch {
        Write-Error -ErrorRecord $_
        reportTelemetryIfEnabled 'InstallFailed' 'GeneralInstallFailure'
        exit 1
    }

    Write-Verbose "Cleaning temporary install directory: $tempFolder" -Verbose:$Verbose
    Remove-Item $tempFolder -Recurse -Force | Out-Null

    if (!(isLinuxOrMac)) {
        # Installed on Windows
        Write-Host "Successfully installed azd"
        Write-Host "Azure Developer CLI (azd) installed successfully. You may need to restart running programs for installation to take effect."
        Write-Host "- For Windows Terminal, start a new Windows Terminal instance."
        Write-Host "- For VSCode, close all instances of VSCode and then restart it."
    }
    Write-Host ""
    Write-Host "The Azure Developer CLI collects usage data and sends that usage data to Microsoft in order to help us improve your experience."
    Write-Host "You can opt-out of telemetry by setting the AZURE_DEV_COLLECT_TELEMETRY environment variable to 'no' in the shell you use."
    Write-Host ""
    Write-Host "Read more about Azure Developer CLI telemetry: https://github.com/Azure/azure-dev#data-collection"

    exit 0
} catch {
    Write-Error -ErrorRecord $_
    reportTelemetryIfEnabled 'InstallFailed' 'UnhandledError' @{ exceptionName = $_.Exception.GetType().Name; }
    exit 1
}
# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3QuFtgwQ9h0uU
# CgLS60IDF9nfUsmrftHmEuvtFO8CE6CCDXYwggX0MIID3KADAgECAhMzAAAEBGx0
# Bv9XKydyAAAAAAQEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjQwOTEyMjAxMTE0WhcNMjUwOTExMjAxMTE0WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC0KDfaY50MDqsEGdlIzDHBd6CqIMRQWW9Af1LHDDTuFjfDsvna0nEuDSYJmNyz
# NB10jpbg0lhvkT1AzfX2TLITSXwS8D+mBzGCWMM/wTpciWBV/pbjSazbzoKvRrNo
# DV/u9omOM2Eawyo5JJJdNkM2d8qzkQ0bRuRd4HarmGunSouyb9NY7egWN5E5lUc3
# a2AROzAdHdYpObpCOdeAY2P5XqtJkk79aROpzw16wCjdSn8qMzCBzR7rvH2WVkvF
# HLIxZQET1yhPb6lRmpgBQNnzidHV2Ocxjc8wNiIDzgbDkmlx54QPfw7RwQi8p1fy
# 4byhBrTjv568x8NGv3gwb0RbAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU8huhNbETDU+ZWllL4DNMPCijEU4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMjkyMzAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAIjmD9IpQVvfB1QehvpC
# Ge7QeTQkKQ7j3bmDMjwSqFL4ri6ae9IFTdpywn5smmtSIyKYDn3/nHtaEn0X1NBj
# L5oP0BjAy1sqxD+uy35B+V8wv5GrxhMDJP8l2QjLtH/UglSTIhLqyt8bUAqVfyfp
# h4COMRvwwjTvChtCnUXXACuCXYHWalOoc0OU2oGN+mPJIJJxaNQc1sjBsMbGIWv3
# cmgSHkCEmrMv7yaidpePt6V+yPMik+eXw3IfZ5eNOiNgL1rZzgSJfTnvUqiaEQ0X
# dG1HbkDv9fv6CTq6m4Ty3IzLiwGSXYxRIXTxT4TYs5VxHy2uFjFXWVSL0J2ARTYL
# E4Oyl1wXDF1PX4bxg1yDMfKPHcE1Ijic5lx1KdK1SkaEJdto4hd++05J9Bf9TAmi
# u6EK6C9Oe5vRadroJCK26uCUI4zIjL/qG7mswW+qT0CW0gnR9JHkXCWNbo8ccMk1
# sJatmRoSAifbgzaYbUz8+lv+IXy5GFuAmLnNbGjacB3IMGpa+lbFgih57/fIhamq
# 5VhxgaEmn/UjWyr+cPiAFWuTVIpfsOjbEAww75wURNM1Imp9NJKye1O24EspEHmb
# DmqCUcq7NqkOKIG4PVm3hDDED/WQpzJDkvu4FrIbvyTGVU01vKsg4UfcdiZ0fQ+/
# V0hf8yrtq9CkB8iIuk5bBxuPMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGg0wghoJAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAQEbHQG/1crJ3IAAAAABAQwDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBdIf+kRp9nbhoLN1e1+WBs/
# Gx1yWTpIxENQSlL2GdjAMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAgqDFJEh3psKNBqt8tjcH+SgRsx/BNA+lwh3B0Qlt6MSnC0jzAvZ2a5SJ
# uRUmMYAmnYLQp7EAAnvay5umolaqNxgpjjNwp9YAUvcZl1Q7LhCWVNITEfJaLR2b
# lHIRpUDpEMPn8m71Ck+rsuJDLl/wNPDZxDpYRoBUIcN0XBdowXGN4vD55Sg8XsI/
# TVOXFzAXVZr8z1gx6T36O2+V4uTWPzNX2w+4X7bxnqTkhImVgm4KoHke/JqyFA9y
# 7HrXlpjcRWWfT8S33dfLdbte3GdQid/H05tOryD+N+3OV/LpOTkfLwGxVPc/8uB1
# D5B8zzWIGJ/+PuEml+XGN7+bUYQWKaGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBc1x1G3Bg8sxjRtbzJQYBq7o8BSeMd0h2U2cN6Uz9PPQIGZ1rLP74j
# GBMyMDI1MDEwODAwMTgyNS4xNzhaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTYwMC0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAe+JP1ahWMyo2gABAAAB7zANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMzEyMDYxODQ1
# NDhaFw0yNTAzMDUxODQ1NDhaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTYwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCjC1jinwzgHwhOakZqy17oE4BIBKsm5kX4DUmCBWI0
# lFVpEiK5mZ2Kh59soL4ns52phFMQYGG5kypCipungwP9Nob4VGVE6aoMo5hZ9Nyt
# XR5ZRgb9Z8NR6EmLKICRhD4sojPMg/RnGRTcdf7/TYvyM10jLjmLyKEegMHfvIwP
# mM+AP7hzQLfExDdqCJ2u64Gd5XlnrFOku5U9jLOKk1y70c+Twt04/RLqruv1fGP8
# LmYmtHvrB4TcBsADXSmcFjh0VgQkX4zXFwqnIG8rgY+zDqJYQNZP8O1Yo4kSckHT
# 43XC0oM40ye2+9l/rTYiDFM3nlZe2jhtOkGCO6GqiTp50xI9ITpJXi0vEek8AejT
# 4PKMEO2bPxU63p63uZbjdN5L+lgIcCNMCNI0SIopS4gaVR4Sy/IoDv1vDWpe+I28
# /Ky8jWTeed0O3HxPJMZqX4QB3I6DnwZrHiKn6oE38tgBTCCAKvEoYOTg7r2lF0Iu
# bt/3+VPvKtTCUbZPFOG8jZt9q6AFodlvQntiolYIYtqSrLyXAQIlXGhZ4gNcv4dv
# 1YAilnbWA9CsnYh+OKEFr/4w4M69lI+yaoZ3L/t/UfXpT/+yc7hS/FolcmrGFJTB
# YlS4nE1cuKblwZ/UOG26SLhDONWXGZDKMJKN53oOLSSk4ldR0HlsbT4heLlWlOEl
# JQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFO1MWqKFwrCbtrw9P8A63bAVSJzLMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQAYGZa3aCDudbk9EVdkP8xcQGZuIAIPRx9K
# 1CA7uRzBt80fC0aWkuYYhQMvHHJRHUobSM4Uw3zN7fHEN8hhaBDb9NRaGnFWdtHx
# mJ9eMz6Jpn6KiIyi9U5Og7QCTZMl17n2w4eddq5vtk4rRWOVvpiDBGJARKiXWB9u
# 2ix0WH2EMFGHqjIhjWUXhPgR4C6NKFNXHvWvXecJ2WXrJnvvQGXAfNJGETJZGpR4
# 1nUN3ijfiCSjFDxamGPsy5iYu904Hv9uuSXYd5m0Jxf2WNJSXkPGlNhrO27pPxgT
# 111myAR61S3S2hc572zN9yoJEObE98Vy5KEM3ZX53cLefN81F1C9p/cAKkE6u9V6
# ryyl/qSgxu1UqeOZCtG/iaHSKMoxM7Mq4SMFsPT/8ieOdwClYpcw0CjZe5KBx2xL
# a4B1neFib8J8/gSosjMdF3nHiyHx1YedZDtxSSgegeJsi0fbUgdzsVMJYvqVw52W
# qQNu0GRC79ZuVreUVKdCJmUMBHBpTp6VFopL0Jf4Srgg+zRD9iwbc9uZrn+89odp
# InbznYrnPKHiO26qe1ekNwl/d7ro2ItP/lghz0DoD7kEGeikKJWHdto7eVJoJhkr
# UcanTuUH08g+NYwG6S+PjBSB/NyNF6bHa/xR+ceAYhcjx0iBiv90Mn0JiGfnA2/h
# Lj5evhTcAjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
# hvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25Phdg
# M/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPF
# dvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6
# GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBp
# Dco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50Zu
# yjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3E
# XzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0
# lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1q
# GFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ
# +QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PA
# PBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkw
# EgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxG
# NSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARV
# MFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAK
# BggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0x
# M7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmC
# VgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449
# xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wM
# nosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDS
# PeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2d
# Y3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxn
# GSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+Crvs
# QWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokL
# jzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL
# 6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNQ
# MIICOAIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEn
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjk2MDAtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBL
# cI81gxbea1Ex2mFbXx7ck+0g/6CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA6yg4CDAiGA8yMDI1MDEwNzIzMzIy
# NFoYDzIwMjUwMTA4MjMzMjI0WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDrKDgI
# AgEAMAoCAQACAizNAgH/MAcCAQACAhLfMAoCBQDrKYmIAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBAFD0pcJfd0RLDnSY/bagRrVt4UAowMxnX632toa5D/WN
# U+vQRZBJnHXDB6y9Jt5DtV0N1BfIiEyMOSa4kKCF1A2/CEGIWUweVCInc46A/Ly7
# /XehbukwpuFFo6lL7mS6VqKMIo+41rWdhGcg/q+wQ4UC74EpP/1ByyfXHUlzhWoi
# gy6OXEEpQdYqgpK9OfmzIcZF22h53jWdhejpcYP91MbcuG2Iza2l74vJ8C5Qul0A
# sh9SSWgHtDArq0fHLi9GBcXEQZbkg1yYXYVV2VZRvqNs8NlXx6GZ/MdGv1hhIohh
# 6mDy8GLtpBYibWc0awo1s5O/uIvEDmMWJO7QiXrQpwIxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAe+JP1ahWMyo2gABAAAB
# 7zANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCCnRGTsMV3ba+g6N8TkHU/pQ3fWqwdxZCIqjHg3Pkv5
# JTCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIPBhKEW4Fo3wUz09NQx2a0Db
# cdsX8jovM5LizHmnyX+jMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAHviT9WoVjMqNoAAQAAAe8wIgQgfDuyhpRughjpMmO3qzDIkCnm
# DK5C5mkrF7GKjkUr4gQwDQYJKoZIhvcNAQELBQAEggIAkJWtFUAao2iHBvcov+4Y
# aZerNUk0bmVCW+ljz22ZD635mbNi10tPAws09pISzxcKt6ZJN3/Wchg6iielDWUg
# LQ6nT2cC4QxnsUMmcF64OrTNlSxsrnDcW021DpQNgwa95DyLDjr8exidAOsnkENt
# tcM/nepBa20f1GHbnlZLDntQkrho1UxYmHjaULkE704s4cozgegsWu4K2JYe6fCl
# WblBpB6swX9SDcDzGkQUHKRVwwe24azUuZPUHtqqicc4eAGuULozqAhRH9nKRsk6
# 2fIu8hRuz0/ZMZjSz4tf3jkOhLBZcx+riHUj4+Gh8ASxY2aX92Lj/Re6GYwqmjO7
# aVVWUTBsSWBmKi8auGQltiOTtCCGdnRkp4Ls8IG6ty8lq2XpYslsLaaRRi4mOPou
# RDjDBmVI98xHTDT1aXcsK/QX9wORF6tc1es3AyfwRriNd233y9V1TlNoqtAtle+g
# ZlLSvtwhmtZJOpN2FuilgX1dsNY0OWGpUYiC7vnKmV/ipmRWaqPEbHcoF9CHctAh
# yFamXatHrDXc6kRYyDdJo0ylJAsR3o2jKzX9bmuQtQjm570aNTV/VwHHLWOfiY8u
# 34f9hQY7+TVqFFCjLj70Ztvff1Jcv/LmAZq+2ynJtd6t9LlwynK8vEFaPXnJAbfI
# l7/OmanMUaFgPa/I0cZz4XE=
# SIG # End signature block
