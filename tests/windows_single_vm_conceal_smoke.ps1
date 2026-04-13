<#
Single-VM Windows conceal smoke harness.

What it validates:
- two local Windows peers can start and handshake with UDP or TCP outer transport
- configured conceal markers appear in outer capture
- UAPI reports the requested network mode and non-zero handshake/traffic counters

What it does not validate:
- multi-host routing, NAT, roaming, or full netns-style isolation semantics
#>
[CmdletBinding()]
param(
    [ValidateSet("udp", "tcp", "both")]
    [string]$Mode = "both",
    [string]$ProgramPath = ".\amneziawg-go.exe",
    [string]$GoCommand = "go",
    [string]$OutDir = ".\_artifacts\windows-single-vm-conceal-smoke",
    [int]$HandshakeTimeoutSec = 25
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$KeygenPath = ".\tests\cmd\awg-keygen"

if ([System.IO.Path]::IsPathRooted($ProgramPath)) {
    $ProgramPath = [System.IO.Path]::GetFullPath($ProgramPath)
}
else {
    $ProgramPath = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $ProgramPath))
}

if ([System.IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = [System.IO.Path]::GetFullPath($OutDir)
}
else {
    $OutDir = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $OutDir))
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run from an elevated PowerShell session."
    }
}

function New-Directory([string]$Path) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Invoke-JsonCommand([string]$FilePath, [string[]]$Arguments) {
    Push-Location $RepoRoot
    try {
        $output = & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed: $FilePath $($Arguments -join ' ')"
        }
        return $output | ConvertFrom-Json
    }
    finally {
        Pop-Location
    }
}

function New-Keypair {
    return Invoke-JsonCommand $GoCommand @("run", $KeygenPath, "-mode", "keypair")
}

function New-Psk {
    return Invoke-JsonCommand $GoCommand @("run", $KeygenPath, "-mode", "psk")
}

function Open-UapiPipe([string]$InterfaceName, [int]$TimeoutMs) {
    $pipeName = "ProtectedPrefix\Administrators\AmneziaWG\$InterfaceName"
    $client = New-Object System.IO.Pipes.NamedPipeClientStream(
        ".",
        $pipeName,
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None,
        [System.Security.Principal.TokenImpersonationLevel]::Impersonation
    )
    $client.Connect($TimeoutMs)
    return $client
}

function Read-UapiResponse([System.IO.StreamReader]$Reader) {
    $lines = New-Object System.Collections.Generic.List[string]
    $sawErrno = $false

    while ($true) {
        $line = $Reader.ReadLine()
        if ($null -eq $line) {
            break
        }

        $lines.Add($line)
        if ($line -match '^errno=') {
            $sawErrno = $true
            continue
        }
        if ($sawErrno -and $line -eq "") {
            break
        }
    }

    if (-not $sawErrno) {
        throw "Incomplete UAPI response: missing errno line."
    }

    return $lines
}

function Invoke-UapiOperation([string]$InterfaceName, [string]$Operation, [string]$Body) {
    $pipe = Open-UapiPipe -InterfaceName $InterfaceName -TimeoutMs 5000
    try {
        $writer = New-Object System.IO.StreamWriter($pipe, [System.Text.Encoding]::ASCII, 1024, $true)
        $writer.NewLine = "`n"
        $writer.AutoFlush = $true
        $reader = New-Object System.IO.StreamReader($pipe, [System.Text.Encoding]::ASCII, $false, 1024, $true)

        switch ($Operation) {
            "set" {
                if (-not $Body.EndsWith("`n")) {
                    $Body += "`n"
                }
                $writer.Write("set=1`n")
                $writer.Write($Body)
                $writer.Write("`n")
            }
            "get" {
                $writer.Write("get=1`n`n")
            }
            default {
                throw "Unsupported UAPI operation '$Operation'."
            }
        }

        $lines = Read-UapiResponse -Reader $reader
        $errnoLine = $lines | Where-Object { $_ -match '^errno=' } | Select-Object -Last 1
        $errno = [int]($errnoLine -replace '^errno=', '')
        if ($errno -ne 0) {
            throw "UAPI $Operation failed for $InterfaceName with errno=$errno"
        }

        return (($lines | Where-Object { $_ -notmatch '^errno=' -and $_ -ne "" }) -join "`n")
    }
    finally {
        $pipe.Dispose()
    }
}

function Wait-UapiReady([string]$InterfaceName, [int]$TimeoutSec) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $pipe = Open-UapiPipe -InterfaceName $InterfaceName -TimeoutMs 500
            $pipe.Dispose()
            return
        }
        catch {
            Start-Sleep -Milliseconds 200
        }
    }
    throw "Timed out waiting for UAPI pipe for $InterfaceName"
}

function Convert-LinesToMap([string]$Text) {
    $map = @{}
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -notmatch '^(?<k>[^=]+)=(?<v>.*)$') {
            continue
        }
        $key = $matches.k
        $value = $matches.v
        if ($map.ContainsKey($key)) {
            if ($map[$key] -is [System.Collections.IList]) {
                $map[$key].Add($value) | Out-Null
            }
            else {
                $list = New-Object System.Collections.ArrayList
                $list.Add($map[$key]) | Out-Null
                $list.Add($value) | Out-Null
                $map[$key] = $list
            }
        }
        else {
            $map[$key] = $value
        }
    }
    return $map
}

function Wait-Handshake([string]$InterfaceName, [int]$TimeoutSec) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $state = Convert-LinesToMap (Invoke-UapiOperation -InterfaceName $InterfaceName -Operation "get" -Body "")
        $hs = 0
        $tx = 0
        $rx = 0
        if ($state.ContainsKey("last_handshake_time_sec")) {
            $hs = [int64]$state["last_handshake_time_sec"]
        }
        if ($state.ContainsKey("tx_bytes")) {
            $tx = [int64]$state["tx_bytes"]
        }
        if ($state.ContainsKey("rx_bytes")) {
            $rx = [int64]$state["rx_bytes"]
        }

        if ($hs -gt 0 -and $tx -gt 0 -and $rx -gt 0) {
            return $state
        }

        Start-Sleep -Milliseconds 500
    }
    throw "Timed out waiting for handshake on $InterfaceName"
}

function Get-LittleEndianUint32Bytes([uint32]$Value) {
    return [System.BitConverter]::GetBytes($Value)
}

function Convert-HexToBytes([string]$Hex) {
    $clean = $Hex.ToLowerInvariant()
    if ($clean.StartsWith("0x")) {
        $clean = $clean.Substring(2)
    }
    if (($clean.Length % 2) -ne 0) {
        throw "Hex string must have even length: $Hex"
    }

    $bytes = New-Object byte[] ($clean.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
    }
    return $bytes
}

function Test-ByteSequenceInArray([byte[]]$Haystack, [byte[]]$Needle) {
    if ($Needle.Length -eq 0 -or $Haystack.Length -lt $Needle.Length) {
        return $false
    }

    for ($i = 0; $i -le ($Haystack.Length - $Needle.Length); $i++) {
        $matched = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Haystack[$i + $j] -ne $Needle[$j]) {
                $matched = $false
                break
            }
        }
        if ($matched) {
            return $true
        }
    }

    return $false
}

function Assert-CaptureContains([byte[]]$CaptureBytes, [string]$Label, [byte[]]$Needle) {
    if (-not (Test-ByteSequenceInArray -Haystack $CaptureBytes -Needle $Needle)) {
        $hex = ([System.BitConverter]::ToString($Needle)).Replace("-", "").ToLowerInvariant()
        throw "Capture does not contain expected $Label marker: $hex"
    }
}

function Invoke-Pktmon([string[]]$Arguments) {
    & pktmon.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "pktmon failed: pktmon.exe $($Arguments -join ' ')"
    }
}

function Start-Capture([string]$EtlPath, [int]$PortA, [int]$PortB, [string]$TransportProtocol) {
    try { & pktmon.exe stop | Out-Null } catch {}
    try { & pktmon.exe filter remove | Out-Null } catch {}

    Invoke-Pktmon @("filter", "add", "conceal-smoke", "-t", $TransportProtocol.ToUpperInvariant(), "-p", "$PortA", "$PortB")
    Invoke-Pktmon @("start", "--capture", "--pkt-size", "256", "--comp", "all", "--file-name", $EtlPath)
}

function Stop-Capture([string]$EtlPath, [string]$PcapPath) {
    try {
        Invoke-Pktmon @("stop")
    }
    finally {
        try { & pktmon.exe filter remove | Out-Null } catch {}
    }
    Invoke-Pktmon @("etl2pcap", $EtlPath, "--out", $PcapPath)
}

function Start-AwgProcess([string]$InterfaceName, [string]$ModeOutDir) {
    $stdout = Join-Path $ModeOutDir "$InterfaceName.stdout.log"
    $stderr = Join-Path $ModeOutDir "$InterfaceName.stderr.log"
    return Start-Process -FilePath $ProgramPath -ArgumentList @($InterfaceName) -WorkingDirectory $RepoRoot -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
}

function Stop-AwgProcess([System.Diagnostics.Process]$Process) {
    if ($null -eq $Process) {
        return
    }
    try {
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force
        }
    }
    catch {}
}

function New-ModeProfile([string]$SelectedMode) {
    if ($SelectedMode -eq "udp") {
        return @{
            Mode = "udp"
            PortA = 31000
            PortB = 32000
            FormatHex = "feedfacedeadbeef"
            I1Hex = "aabbccddeeff0011"
            I2Hex = "2233445566778899"
            H1 = [uint32]305419896
            H2 = [uint32]2596069104
            H4 = [uint32]267242409
            DeviceArgs = @(
                "network", "udp",
                "header_compat", "true",
                "format_in", "<b 0xfeedfacedeadbeef><dz be 2><d>",
                "format_out", "<b 0xfeedfacedeadbeef><dz be 2><d>",
                "i1", "<b 0xaabbccddeeff0011>",
                "i2", "<b 0x2233445566778899>",
                "jc", "1",
                "jmin", "8",
                "jmax", "8",
                "s1", "15",
                "s2", "18",
                "s4", "25",
                "h1", "305419896",
                "h2", "2596069104",
                "h4", "267242409"
            )
        }
    }

    return @{
        Mode = "tcp"
        PortA = 41000
        PortB = 42000
        FormatHex = "beefcafebad0f00d"
        I1Hex = "1122334455667788"
        I2Hex = "99aabbccddeeff00"
        H1 = [uint32]286331153
        H2 = [uint32]572662306
        H4 = [uint32]1145324612
        DeviceArgs = @(
            "network", "tcp",
            "header_compat", "true",
            "format_in", "<b 0xbeefcafebad0f00d><dz be 2><d>",
            "format_out", "<b 0xbeefcafebad0f00d><dz be 2><d>",
            "i1", "<b 0x1122334455667788>",
            "i2", "<b 0x99aabbccddeeff00>",
            "s1", "15",
            "s2", "18",
            "s4", "25",
            "h1", "286331153",
            "h2", "572662306",
            "h4", "1145324612"
        )
    }
}

function New-UapiConfig([string[]]$Pairs) {
    if (($Pairs.Length % 2) -ne 0) {
        throw "Expected an even number of key/value entries."
    }

    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Pairs.Length; $i += 2) {
        [void]$builder.Append($Pairs[$i]).Append('=').Append($Pairs[$i + 1]).Append("`n")
    }
    return $builder.ToString()
}

function Invoke-ConcealSmoke([string]$SelectedMode) {
    $profile = New-ModeProfile -SelectedMode $SelectedMode
    $modeOutDir = Join-Path $OutDir $SelectedMode
    New-Directory $modeOutDir

    $ifaceA = "awg-smoke-$SelectedMode-a"
    $ifaceB = "awg-smoke-$SelectedMode-b"
    $captureEtl = Join-Path $modeOutDir "$SelectedMode.etl"
    $capturePcap = Join-Path $modeOutDir "$SelectedMode.pcapng"

    $procA = $null
    $procB = $null

    try {
        $keyA = New-Keypair
        $keyB = New-Keypair
        $psk = New-Psk

        $procA = Start-AwgProcess -InterfaceName $ifaceA -ModeOutDir $modeOutDir
        $procB = Start-AwgProcess -InterfaceName $ifaceB -ModeOutDir $modeOutDir

        Wait-UapiReady -InterfaceName $ifaceA -TimeoutSec 20
        Wait-UapiReady -InterfaceName $ifaceB -TimeoutSec 20

        $configA = @(
            "private_key", $keyA.private,
            "listen_port", "$($profile.PortA)",
            "replace_peers", "true",
            "public_key", $keyB.public,
            "preshared_key", $psk.psk,
            "protocol_version", "1",
            "replace_allowed_ips", "true",
            "allowed_ip", "10.99.0.2/32",
            "endpoint", "127.0.0.1:$($profile.PortB)"
        ) + $profile.DeviceArgs

        $configB = @(
            "private_key", $keyB.private,
            "listen_port", "$($profile.PortB)",
            "replace_peers", "true",
            "public_key", $keyA.public,
            "preshared_key", $psk.psk,
            "protocol_version", "1",
            "replace_allowed_ips", "true",
            "allowed_ip", "10.99.0.1/32",
            "endpoint", "127.0.0.1:$($profile.PortA)"
        ) + $profile.DeviceArgs

        Invoke-UapiOperation -InterfaceName $ifaceA -Operation "set" -Body (New-UapiConfig -Pairs $configA) | Out-Null
        Invoke-UapiOperation -InterfaceName $ifaceB -Operation "set" -Body (New-UapiConfig -Pairs $configB) | Out-Null

        Start-Capture -EtlPath $captureEtl -PortA $profile.PortA -PortB $profile.PortB -TransportProtocol $SelectedMode
        try {
            $kickA = New-UapiConfig -Pairs @("public_key", $keyB.public, "persistent_keepalive_interval", "1")
            $kickB = New-UapiConfig -Pairs @("public_key", $keyA.public, "persistent_keepalive_interval", "1")
            Invoke-UapiOperation -InterfaceName $ifaceA -Operation "set" -Body $kickA | Out-Null
            Invoke-UapiOperation -InterfaceName $ifaceB -Operation "set" -Body $kickB | Out-Null

            $stateA = Wait-Handshake -InterfaceName $ifaceA -TimeoutSec $HandshakeTimeoutSec
            $stateB = Wait-Handshake -InterfaceName $ifaceB -TimeoutSec $HandshakeTimeoutSec

            Start-Sleep -Seconds 2

            if ($stateA["network"] -ne $SelectedMode) {
                throw "UAPI state for $ifaceA reports network=$($stateA["network"]), expected $SelectedMode"
            }
            if ($stateB["network"] -ne $SelectedMode) {
                throw "UAPI state for $ifaceB reports network=$($stateB["network"]), expected $SelectedMode"
            }
        }
        finally {
            Stop-Capture -EtlPath $captureEtl -PcapPath $capturePcap
        }

        $captureBytes = [System.IO.File]::ReadAllBytes($capturePcap)
        Assert-CaptureContains -CaptureBytes $captureBytes -Label "$SelectedMode format" -Needle (Convert-HexToBytes $profile.FormatHex)
        Assert-CaptureContains -CaptureBytes $captureBytes -Label "$SelectedMode I1 decoy" -Needle (Convert-HexToBytes $profile.I1Hex)
        Assert-CaptureContains -CaptureBytes $captureBytes -Label "$SelectedMode I2 decoy" -Needle (Convert-HexToBytes $profile.I2Hex)
        Assert-CaptureContains -CaptureBytes $captureBytes -Label "$SelectedMode H1 header" -Needle (Get-LittleEndianUint32Bytes $profile.H1)
        Assert-CaptureContains -CaptureBytes $captureBytes -Label "$SelectedMode H2 header" -Needle (Get-LittleEndianUint32Bytes $profile.H2)
        Assert-CaptureContains -CaptureBytes $captureBytes -Label "$SelectedMode H4 header" -Needle (Get-LittleEndianUint32Bytes $profile.H4)

        [PSCustomObject]@{
            mode = $SelectedMode
            interface_a = $ifaceA
            interface_b = $ifaceB
            pcapng = $capturePcap
            logs = $modeOutDir
        }
    }
    finally {
        Stop-AwgProcess -Process $procA
        Stop-AwgProcess -Process $procB
    }
}

Assert-Administrator
New-Directory $OutDir

if (-not (Test-Path $ProgramPath)) {
    throw "Program path does not exist: $ProgramPath"
}

$modes = if ($Mode -eq "both") { @("udp", "tcp") } else { @($Mode) }
$results = @()

foreach ($selectedMode in $modes) {
    $results += Invoke-ConcealSmoke -SelectedMode $selectedMode
}

$summaryPath = Join-Path $OutDir "summary.json"
$results | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 $summaryPath
$results | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "Summary written to $summaryPath"
