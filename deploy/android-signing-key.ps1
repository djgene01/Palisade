<#
.SYNOPSIS
    Creates the key that signs the Palisade Android app, and can hand it to GitHub for the release workflow.

.DESCRIPTION
    Android only installs an update when it is signed with the same key as the app already on the phone.
    So this key is made once, kept safe for as long as the app exists, and used for every release.
    Lose it and everyone has to uninstall the app before they can install a newer one.

    Run it yourself, once:   pwsh ./deploy/android-signing-key.ps1
    It never prints the password or puts it on a command line.
#>
#Requires -Version 7
# PowerShell 7: Windows PowerShell 5.1 would pass the password to gh in a legacy code page, mangling any non-ASCII character.
param(
    # Where to keep the key. Somewhere that is backed up, and not inside this repository.
    [string]$Path = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'palisade-android.keystore')
)
$ErrorActionPreference = 'Stop'

if (Test-Path $Path) { throw "A key already exists at $Path. Use that one: a new key cannot update apps signed with the old one." }
if ((Resolve-Path (Split-Path $Path -Parent)).Path.StartsWith((Resolve-Path "$PSScriptRoot/..").Path)) {
    throw 'Keep the key outside the repository, so it can never be committed.'
}

# keytool comes with any Java: the one in Android Studio, the Android SDK's, or one on the PATH.
$keytool = @(
    if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin/keytool.exe' }
    "$env:ProgramFiles\Android\Android Studio\jbr\bin\keytool.exe"
    Get-ChildItem "${env:ProgramFiles(x86)}\Android\openjdk\*\bin\keytool.exe" -ErrorAction SilentlyContinue | ForEach-Object FullName
    (Get-Command keytool -ErrorAction SilentlyContinue).Source
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $keytool) { throw 'keytool was not found. Install Android Studio or a Java JDK, then run this again.' }

function Read-Password([string]$prompt) {
    $secure = Read-Host $prompt -AsSecureString
    [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
$password = Read-Password 'Password for the key (at least 12 characters; store it in your password manager)'
if ($password.Length -lt 12) { throw 'Use at least 12 characters.' }
if ($password -ne (Read-Password 'Type it again')) { throw 'The two passwords differ. Nothing was created.' }

# keytool reads the password from an environment variable, so it never appears in a process list.
$env:PALISADE_KEY_PASSWORD = $password
try {
    & $keytool -genkeypair -keystore $Path -storetype PKCS12 -alias palisade -keyalg RSA -keysize 4096 -validity 10000 `
        -dname 'CN=Palisade' -storepass:env PALISADE_KEY_PASSWORD -keypass:env PALISADE_KEY_PASSWORD
    if ($LASTEXITCODE -ne 0) { throw 'keytool could not create the key.' }
}
finally { Remove-Item Env:PALISADE_KEY_PASSWORD -ErrorAction SilentlyContinue }

Write-Host ''
Write-Host "Created $Path" -ForegroundColor Green
Write-Host 'Back up this file and its password now. Without both, the app can never be updated again.' -ForegroundColor Yellow

# Optionally hand it to GitHub, where the release workflow signs each new version with it.
if (Get-Command gh -ErrorAction SilentlyContinue) {
    $repo = (gh repo view --json nameWithOwner --jq .nameWithOwner 2>$null)
    if ($repo -and (Read-Host "Store the key as secrets of $repo for the release workflow? (y/N)") -match '^[yY]') {
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path)) | gh secret set ANDROID_KEYSTORE_BASE64 --repo $repo
        $password | gh secret set ANDROID_KEYSTORE_PASSWORD --repo $repo
        Write-Host "Stored. The next release of $repo will include the signed Android app." -ForegroundColor Green
    }
}
$password = $null
