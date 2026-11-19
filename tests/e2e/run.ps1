# Runs one end-to-end test against the release package in ./release/palisade (build it with deploy/publish.ps1),
# inside a privileged Debian container that boots systemd. Example:  pwsh tests/e2e/run.ps1 names
param([Parameter(Mandatory)][ValidateSet('zero-trust', 'fixed-address', 'system', 'names', 'upgrade-names')][string]$Test)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$release = Join-Path (Split-Path (Split-Path $here)) 'release\palisade'
if (-not (Test-Path $release)) { throw "No release package at $release. Run deploy/publish.ps1 first." }
docker build -q -t palisade-e2e $here | Out-Null
$name = "palisade-e2e-$Test"
docker rm -f $name 2>$null | Out-Null
# The names test runs on a machine called "palisade", to prove that name still means the firewall's home address.
docker run -d --name $name --hostname palisade --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw `
    -v "${release}:/root/palisade:ro" -v "${here}:/e2e:ro" palisade-e2e | Out-Null
try {
    Start-Sleep 5
    docker exec $name bash -c "apt-get update -qq >/dev/null 2>&1; bash /e2e/$Test.sh"
}
finally { docker rm -f $name | Out-Null }
