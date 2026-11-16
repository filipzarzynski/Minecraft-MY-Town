param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Command,
  [string]$HostAddress = '127.0.0.1',
  [int]$Port = 25575,
  [string]$SecretFile = (Join-Path (Split-Path -Parent $PSScriptRoot) 'admin\rcon-secret.txt'),
  [int]$TimeoutMs = 5000
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $SecretFile)) {
  throw "RCON secret file not found: $SecretFile"
}
$password = (Get-Content -Path $SecretFile -Raw).Trim()
$maxResponseBytes = 65536
$deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)

function Get-RemainingTimeoutMs {
  $rem = [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
  if ($rem -le 0) { throw "RCON operation exceeded total timeout (${TimeoutMs}ms)." }
  return $rem
}

function Write-RconPacket([System.IO.Stream]$Stream, [int]$RequestId, [int]$Type, [string]$Payload) {
  $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($Payload)
  $packetLen = 4 + 4 + $payloadBytes.Length + 2
  $buf = New-Object byte[] (4 + $packetLen)
  [BitConverter]::GetBytes([int]$packetLen).CopyTo($buf, 0)
  [BitConverter]::GetBytes([int]$RequestId).CopyTo($buf, 4)
  [BitConverter]::GetBytes([int]$Type).CopyTo($buf, 8)
  if ($payloadBytes.Length -gt 0) {
    [Array]::Copy($payloadBytes, 0, $buf, 12, $payloadBytes.Length)
  }
  $Stream.Write($buf, 0, $buf.Length)
  $Stream.Flush()
}

function Read-ExactBytes([System.Net.Sockets.TcpClient]$Client, [System.IO.Stream]$Stream, [int]$Count) {
  $buf = New-Object byte[] $Count
  $offset = 0
  while ($offset -lt $Count) {
    $Client.ReceiveTimeout = Get-RemainingTimeoutMs
    $read = $Stream.Read($buf, $offset, $Count - $offset)
    if ($read -le 0) { throw "RCON connection closed unexpectedly." }
    $offset += $read
  }
  return $buf
}

function Read-RconPacket([System.Net.Sockets.TcpClient]$Client, [System.IO.Stream]$Stream) {
  $lenBytes = Read-ExactBytes $Client $Stream 4
  $len = [BitConverter]::ToInt32($lenBytes, 0)
  if ($len -lt 10 -or $len -gt $maxResponseBytes) {
    throw "Invalid or oversized RCON packet length: $len"
  }
  $body = Read-ExactBytes $Client $Stream $len
  $reqId = [BitConverter]::ToInt32($body, 0)
  $type = [BitConverter]::ToInt32($body, 4)
  $payloadLen = [Math]::Max(0, $len - 10)
  $payload = if ($payloadLen -gt 0) { [System.Text.Encoding]::UTF8.GetString($body, 8, $payloadLen) } else { '' }
  return [PSCustomObject]@{ Id = $reqId; Type = $type; Payload = $payload }
}

$client = New-Object System.Net.Sockets.TcpClient
$client.SendTimeout = $TimeoutMs
try {
  $iar = $client.BeginConnect($HostAddress, $Port, $null, $null)
  if (-not $iar.AsyncWaitHandle.WaitOne((Get-RemainingTimeoutMs), $false)) {
    throw "Timed out connecting to RCON at ${HostAddress}:${Port}"
  }
  $client.EndConnect($iar)
  $stream = $client.GetStream()

  Write-RconPacket $stream 1 3 $password
  $authResp = $null
  while ($true) {
    $null = Get-RemainingTimeoutMs
    $pkt = Read-RconPacket $client $stream
    if ($pkt.Type -eq 2) {
      $authResp = $pkt
      break
    }
  }
  if ($authResp.Id -eq -1) {
    throw "RCON authentication failed."
  }

  Write-RconPacket $stream 10 2 $Command
  Write-RconPacket $stream 11 0 ''

  $sb = New-Object System.Text.StringBuilder
  $totalBytes = 0
  while ($true) {
    $null = Get-RemainingTimeoutMs
    $pkt = Read-RconPacket $client $stream
    if ($pkt.Id -eq 11) {
      break
    }
    if ($pkt.Id -eq 10 -and $pkt.Payload) {
      $totalBytes += $pkt.Payload.Length
      if ($totalBytes -gt $maxResponseBytes) {
        throw "RCON response exceeded ${maxResponseBytes} byte limit."
      }
      [void]$sb.Append($pkt.Payload)
    }
  }
  $out = $sb.ToString().TrimEnd("`r", "`n")
  if ($out) { Write-Output $out }
} finally {
  $client.Dispose()
}
