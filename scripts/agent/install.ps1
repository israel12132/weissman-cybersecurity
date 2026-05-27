# Weissman Endpoint Agent — single-command installer for Windows.
# Run from an elevated PowerShell. The dashboard generates the full command for you.
#
# Example:
#   iwr https://<server>/install/agent.ps1 | iex; Install-WeissmanAgent -Token "..." -Server "https://<server>"

function Install-WeissmanAgent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$Server,
        [string]$InstallDir = "$env:ProgramFiles\Weissman\Agent"
    )

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        throw "Install-WeissmanAgent must run from an elevated (Administrator) PowerShell."
    }

    $arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "i686" }
    $platform = "windows-${arch}-msvc"
    $base = ($Server.TrimEnd('/')) + "/install/binaries/${platform}"

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $binary = Join-Path $InstallDir "weissman-agent.exe"
    Write-Host "[weissman-agent] downloading $base/weissman-agent.exe"
    Invoke-WebRequest -Uri "$base/weissman-agent.exe" -OutFile "$binary.tmp" -UseBasicParsing
    $expected = (Invoke-WebRequest -Uri "$base/weissman-agent.exe.sha256" -UseBasicParsing).Content.Split(' ')[0]
    $actual = (Get-FileHash -Algorithm SHA256 "$binary.tmp").Hash
    if ($expected.ToLower() -ne $actual.ToLower()) {
        Remove-Item -Force "$binary.tmp"
        throw "SHA-256 mismatch (expected $expected, got $actual)"
    }
    Move-Item -Force "$binary.tmp" $binary

    # Enroll first to verify token works.
    $env:WEISSMAN_SERVER_URL = $Server
    $env:WEISSMAN_ENROLLMENT_TOKEN = $Token
    $proc = Start-Process -FilePath $binary -ArgumentList "--enroll-only" -NoNewWindow -PassThru -Wait
    if ($proc.ExitCode -ne 0) {
        throw "Enrollment failed; verify token and server URL."
    }

    # Register as Windows Service.
    $svcName = "WeissmanAgent"
    $existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($existing) {
        sc.exe delete $svcName | Out-Null
        Start-Sleep -Seconds 2
    }
    sc.exe create $svcName binPath= "`"$binary`"" start= auto DisplayName= "Weissman Endpoint Agent" | Out-Null
    # Inject env vars via service config (HKLM\SYSTEM\CurrentControlSet\Services\<name>\Environment).
    $regBase = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
    if (-not (Test-Path $regBase)) {
        throw "Service registration failed."
    }
    $envEntries = @(
        "WEISSMAN_SERVER_URL=$Server",
        "WEISSMAN_ENROLLMENT_TOKEN=$Token",
        "RUST_LOG=info"
    )
    New-ItemProperty -Path $regBase -Name "Environment" -PropertyType MultiString -Value $envEntries -Force | Out-Null
    Start-Service $svcName
    Write-Host "[weissman-agent] installed and started."
    Write-Host "[weissman-agent] verify in dashboard → Agents."
}
