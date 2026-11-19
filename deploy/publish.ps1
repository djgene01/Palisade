# Builds a self-contained release for Debian (x64) into ./release/palisade.
# Copy that folder to the firewall machine and run: sh install.sh
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$out = Join-Path $root 'release\palisade'

if (Test-Path $out) { Remove-Item $out -Recurse -Force }

dotnet publish (Join-Path $root 'src\Palisade.Agent') -c Release -r linux-x64 --self-contained -o (Join-Path $out 'agent') --nologo -v q
if ($LASTEXITCODE -ne 0) { throw 'Publishing the agent failed.' }
dotnet publish (Join-Path $root 'src\Palisade.Web') -c Release -r linux-x64 --self-contained -o (Join-Path $out 'web') --nologo -v q
if ($LASTEXITCODE -ne 0) { throw 'Publishing the web interface failed.' }

# Shell scripts and unit files must keep Unix line endings or Debian refuses to run them.
foreach ($name in 'install.sh', 'palisade-agent.service', 'palisade-web.service', 'palisade-dns@.service', 'palisade-capture.service', 'palisade-lease-name') {
    $text = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $name)) -replace "`r`n", "`n"
    [IO.File]::WriteAllText((Join-Path $out $name), $text, [Text.UTF8Encoding]::new($false))
}

# Marks this as a build copied on by hand. Releases built on GitHub carry their version tag here instead,
# and only those are replaced by automatic updates.
[IO.File]::WriteAllText((Join-Path $out 'VERSION'), "dev`n", [Text.UTF8Encoding]::new($false))

Write-Host "Release is ready in $out"
Write-Host 'Copy it over, for example:  scp -r release/palisade root@<firewall-address>:/root/'
Write-Host 'Then on the firewall:        sh /root/palisade/install.sh'
