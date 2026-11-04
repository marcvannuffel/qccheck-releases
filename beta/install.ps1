# QCCheck – Windows-Installer (App + Kommandozeile), nach dem Muster von PodcastMagic 360.
# Zeile für Kunden (von der Installationsseite, GitHub Pages von qccheck-releases):
#   irm https://marcvannuffel.github.io/qccheck-releases/install.ps1 | iex
# Die Pakete kommen öffentlich aus den GitHub-Releases von marcvannuffel/qccheck-releases (ohne Anmeldung); sicher
# macht es die Ed25519-Signatur unten, nicht der Ort.
# Installiert nach %LOCALAPPDATA%\QCCheck (aktualisiert sich von dort):
#   - die App: Electron 36.9.5 von electron/electron (SHA-256 unten geprüft), umbenannt in QCCheck.exe, der Starter
#     als resources\app, Verknüpfung auf dem Desktop und im Startmenü – ohne Administratorrechte;
#   - die Kommandozeile: %LOCALAPPDATA%\QCCheck\bin\qccheck.cmd (Electron als Node), Ordner in den Benutzer-PATH.
# Entpackt wird nur, wenn die Ed25519-Signatur (.sig) zum Schlüssel unten passt; behalten nur, wenn VERSION stimmt und
# jede Datei zu FILES.sha256 passt (dann Marker .qc-verified für den Starter).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Repo = 'marcvannuffel/qccheck-releases'
# beta: tools/installer/make-beta ersetzt nur diese Zeile (neueste Vorabversion statt releases/latest)
$Channel = 'beta'
# Öffentliche Hälfte des Release-Schlüssels (SPKI, base64) – dieselbe wie in src/release-key.js; tools/release-key setzt sie
$releaseKey = 'MCowBQYDK2VwAyEAnqPSW7XL2BSTimnHn7YHM7XCi/ZntpIfb/BOnNZH8i0='
$electronVersion = '36.9.5'
$electronSha256 = 'fb8b47aff266bb2483aabf1c6442d519e27c68b4bf432b8e84fd6823e2515e3c'
# --- ed25519 begin ---
# Ed25519 signature check (RFC 8032, cofactorless like OpenSSL and Node) in
# plain PowerShell: Windows PowerShell 5.1 / .NET Framework has no Ed25519, and
# nothing is downloaded or compiled for it. Slow BigInteger arithmetic, but it
# runs once (a second or two). True only for a valid signature of the file.
# Names are case-insensitive and scopes dynamic in PowerShell: the prime is $fp,
# points are $U/$V, so no helper sees a caller's variable of the same name.
function Test-Ed25519Signature([string]$File, [string]$SigBase64, [string]$SpkiBase64) {
  Add-Type -AssemblyName System.Numerics
  $BI = [System.Numerics.BigInteger]
  $fp = $BI::Subtract($BI::Pow(2, 255), 19)
  $ord = $BI::Add($BI::Pow(2, 252), $BI::Parse('27742317777372353535851937790883648493'))
  function ModP($w) { $m = $BI::Remainder($w, $fp); if ($m.Sign -lt 0) { $m = $BI::Add($m, $fp) }; $m }
  function Inv($w) { $BI::ModPow((ModP $w), $BI::Subtract($fp, 2), $fp) }
  function FromLE([byte[]]$le) { $BI::new([byte[]]($le + [byte]0)) }
  $dc = ModP ($BI::Multiply(-121665, (Inv 121666)))
  $dc2 = ModP ($BI::Multiply($dc, 2))
  $sqrtM1 = $BI::ModPow(2, $BI::Divide($BI::Subtract($fp, 1), 4), $fp)
  # a point in extended coordinates X, Y, Z, T (x = X/Z, y = Y/Z, x*y = T/Z)
  function Add-Point($U, $V) {
    $ea = ModP ($BI::Multiply($BI::Subtract($U[1], $U[0]), $BI::Subtract($V[1], $V[0])))
    $eb = ModP ($BI::Multiply($BI::Add($U[1], $U[0]), $BI::Add($V[1], $V[0])))
    $ec = ModP ($BI::Multiply($BI::Multiply($U[3], $dc2), $V[3]))
    $ed = ModP ($BI::Multiply($BI::Multiply($U[2], 2), $V[2]))
    $ee = $BI::Subtract($eb, $ea); $ef = $BI::Subtract($ed, $ec); $eg = $BI::Add($ed, $ec); $eh = $BI::Add($eb, $ea)
    return , @((ModP ($BI::Multiply($ee, $ef))), (ModP ($BI::Multiply($eg, $eh))), (ModP ($BI::Multiply($ef, $eg))), (ModP ($BI::Multiply($ee, $eh))))
  }
  function Mul-Point($U, $scalar) {
    $acc = @($BI::Zero, $BI::One, $BI::One, $BI::Zero)
    $bits = $scalar.ToByteArray()
    for ($i = 255; $i -ge 0; $i--) {
      $acc = Add-Point $acc $acc
      $at = $i -shr 3
      if ($at -lt $bits.Length -and (($bits[$at] -shr ($i -band 7)) -band 1)) { $acc = Add-Point $acc $U }
    }
    return , $acc
  }
  # a 32-byte encoding as a point, or $null when it is none
  function Decode-Point([byte[]]$enc) {
    $raw = [byte[]]$enc.Clone(); $sign = $raw[31] -shr 7; $raw[31] = $raw[31] -band 0x7f
    $py = FromLE $raw
    if ($py.CompareTo($fp) -ge 0) { return $null }
    $py2 = ModP ($BI::Multiply($py, $py))
    $px2 = ModP ($BI::Multiply($BI::Subtract($py2, 1), (Inv ($BI::Add($BI::Multiply($dc, $py2), 1)))))
    $px = $BI::ModPow($px2, $BI::Divide($BI::Add($fp, 3), 8), $fp)
    if (-not (ModP ($BI::Subtract($BI::Multiply($px, $px), $px2))).IsZero) { $px = ModP ($BI::Multiply($px, $sqrtM1)) }
    if (-not (ModP ($BI::Subtract($BI::Multiply($px, $px), $px2))).IsZero) { return $null }
    if ($px.IsZero -and $sign -eq 1) { return $null }
    if ([int](-not $px.IsEven) -ne $sign) { $px = $BI::Subtract($fp, $px) }
    return , @($px, $py, $BI::One, (ModP ($BI::Multiply($px, $py))))
  }
  function To32($n) { $out = New-Object byte[] 32; $le = $n.ToByteArray(); [Array]::Copy($le, $out, [Math]::Min($le.Length, 32)); return , $out }
  function Encode-Point($U) {
    $zi = Inv $U[2]; $px = ModP ($BI::Multiply($U[0], $zi)); $py = ModP ($BI::Multiply($U[1], $zi))
    $out = To32 $py
    if (-not $px.IsEven) { $out[31] = $out[31] -bor 0x80 }
    return , $out
  }
  try {
    $spki = [Convert]::FromBase64String($SpkiBase64)
    $sig = [Convert]::FromBase64String($SigBase64.Trim())
  } catch { return $false }
  # SPKI of an Ed25519 key: 12 fixed bytes, then the 32-byte key
  if ($spki.Length -ne 44 -or [BitConverter]::ToString($spki, 0, 12) -ne '30-2A-30-05-06-03-2B-65-70-03-21-00' -or $sig.Length -ne 64) { return $false }
  $pub = [byte[]]$spki[12..43]
  $pointA = Decode-Point $pub
  if ($null -eq $pointA) { return $false }
  $sS = FromLE ([byte[]]$sig[32..63])
  if ($sS.CompareTo($ord) -ge 0) { return $false }
  $sha = New-Object System.Security.Cryptography.SHA512CryptoServiceProvider
  [void]$sha.TransformBlock($sig, 0, 32, $null, 0)
  [void]$sha.TransformBlock($pub, 0, 32, $null, 0)
  $fs = [IO.File]::OpenRead($File)
  try {
    $buf = New-Object byte[] 1048576
    while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { [void]$sha.TransformBlock($buf, 0, $n, $null, 0) }
  } finally { $fs.Close() }
  [void]$sha.TransformFinalBlock($buf, 0, 0)
  $kh = $BI::Remainder((FromLE $sha.Hash), $ord)
  $base = Decode-Point (To32 (ModP ($BI::Multiply(4, (Inv 5)))))
  # [S]B - [k]A must give R, the first half of the signature
  $negA = @($BI::Subtract($fp, $pointA[0]), $pointA[1], $pointA[2], $BI::Subtract($fp, $pointA[3]))
  $enc = Encode-Point (Add-Point (Mul-Point $base $sS) (Mul-Point $negA $kh))
  return [BitConverter]::ToString($enc) -eq [BitConverter]::ToString($sig, 0, 32)
}
# --- ed25519 end ---
# --- package check begin ---
function Confirm-Package([string]$Dir, [string]$Version) {
  $vf = Join-Path $Dir 'VERSION'
  $inside = if (Test-Path -LiteralPath $vf -PathType Leaf) { ([IO.File]::ReadAllText($vf)).Trim() } else { '' }
  if ($inside -cne $Version) { throw "Paket ist Version '$inside', nicht $Version - nichts installiert." }
  $list = Join-Path $Dir 'FILES.sha256'
  if (-not (Test-Path -LiteralPath $list -PathType Leaf)) { throw 'Paket ohne Dateiliste (FILES.sha256) - nichts installiert.' }
  $n = 0
  $lines = @([IO.File]::ReadAllLines($list) | Where-Object { $_.Trim() })
  foreach ($line in $lines) {
    if ($line -cnotmatch '^([0-9a-f]{64}) [ *](.+)$') { throw 'Dateiliste unlesbar - nichts installiert.' }
    $want = $Matches[1]
    $rel = $Matches[2] -replace '^\./', ''
    if ($rel -match '(^|[\\/])\.\.([\\/]|$)' -or $rel -match '^([a-zA-Z]:|[\\/])') { throw "Dateiliste: unerwarteter Pfad $rel - nichts installiert." }
    $f = Join-Path $Dir $rel
    if (-not (Test-Path -LiteralPath $f -PathType Leaf) -or (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant() -ne $want) {
      throw "$rel passt nicht zur Dateiliste - nichts installiert."
    }
    $n++
  }
  if ($n -eq 0) { throw 'Dateiliste leer - nichts installiert.' }
  # wie app/update.mjs und starter/verify.cjs: SHA-256 der Zeilen, mit \n verbunden
  $sha = [Security.Cryptography.SHA256]::Create()
  $listHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($lines -join "`n")))) -replace '-', '').ToLowerInvariant()
  [IO.File]::WriteAllText((Join-Path $Dir '.qc-verified'), "{`"version`":`"$Version`",`"list`":`"$listHash`"}")
}
# --- package check end ---

# --- nur zum Testen (tools/installer/test-install.ps1): andere Quelle, Wegwerf-Schlüssel, anderer Zielordner, ohne
# Verknüpfungen/PATH. Drei Variablen, die niemand zufällig setzt; sie melden sich laut.
$Base = $null
if ($env:QC_INSTALL_TEST_BASE) {
  $Base = $env:QC_INSTALL_TEST_BASE
  if ($env:QC_INSTALL_TEST_KEY) { $releaseKey = $env:QC_INSTALL_TEST_KEY }
  Write-Warning "TESTMODUS: Quelle $Base$(if ($env:QC_INSTALL_TEST_KEY) { ', Test-Schluessel' }). Nicht fuer Tester."
}
if ($releaseKey -like '__*') { throw 'Dieser Installer hat noch keinen Release-Schluessel (tools/release-key) - nichts installiert.' }
$H = @{ 'User-Agent' = 'qccheck-install' }
# latest.json liegt als Asset in jedem Release: stabil über releases/latest (nie eine Vorabversion), Beta über die
# neueste Vorabversion der Release-Liste; im Testmodus <Quelle>/latest.json und <Quelle>/download/<datei>
if ($env:QC_INSTALL_TEST_BASE) { $feedUrl = "$Base/latest.json" }
elseif ($Channel -eq 'beta') {
  $tag = $null
  foreach ($r in (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases?per_page=50" -Headers $H)) {
    if (-not $r.prerelease -or $r.draft -or $r.tag_name -notmatch '^v\d+\.\d+\.\d+$') { continue }
    if (-not $tag -or [version]$r.tag_name.TrimStart('v') -gt [version]$tag.TrimStart('v')) { $tag = $r.tag_name }
  }
  if (-not $tag) { throw 'Keine Beta-Version gefunden. / No beta release found.' }
  Write-Warning "BETA: $tag ist eine Vorabversion. / $tag is a pre-release."
  $feedUrl = "https://github.com/$Repo/releases/download/$tag/latest.json"
} else { $feedUrl = "https://github.com/$Repo/releases/latest/download/latest.json" }
# als Datei laden: GitHub liefert Assets als application/octet-stream (PowerShell 5.1 gäbe sonst Bytes zurück)
$feedFile = [IO.Path]::GetTempFileName()
Invoke-WebRequest $feedUrl -Headers $H -OutFile $feedFile -UseBasicParsing
$latest = Get-Content -LiteralPath $feedFile -Raw | ConvertFrom-Json
Remove-Item -Force $feedFile
$version = "$($latest.version)"
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw "Unerwartete Version '$version'." }
$name = "$($latest.packages.win64)"
if ($name -ne "qccheck-$version-win64.tar.gz") { throw "Unerwarteter Paketname '$name'." }

$testRoot = $env:QC_INSTALL_TEST_BASE -and $env:QC_INSTALL_TEST_ROOT
$app = if ($testRoot) { $env:QC_INSTALL_TEST_ROOT } else { Join-Path $env:LOCALAPPDATA 'QCCheck' }
New-Item -ItemType Directory -Force $app | Out-Null
[IO.File]::WriteAllText((Join-Path $app 'channel.json'), "{`"channel`":`"$Channel`"}")
$installed = $null
try { $installed = (Get-Content -LiteralPath (Join-Path $app 'current.json') -Raw | ConvertFrom-Json).version } catch { }
if ("$installed" -match '^\d+\.\d+\.\d+$' -and ([version]"$installed" -gt [version]$version) -and $env:QC_INSTALL_DOWNGRADE -ne '1') {
  throw "Installiert ist $installed, neuer als $version - Version bleibt. Aeltere nur mit `$env:QC_INSTALL_DOWNGRADE='1'."
}
Write-Host "QCCheck $version wird installiert ..."
$tmp = Join-Path ([IO.Path]::GetTempPath()) "qccheck-$version"
New-Item -ItemType Directory -Force $tmp | Out-Null
$pkg = Join-Path $tmp $name
$dl = if ($Base) { "$Base/download" } else { "https://github.com/$Repo/releases/download/v$version" }
Invoke-WebRequest "$dl/$name" -Headers $H -OutFile $pkg -UseBasicParsing
$sigFile = Join-Path $tmp "$name.sig"
Invoke-WebRequest "$dl/$name.sig" -Headers $H -OutFile $sigFile -UseBasicParsing
Write-Host 'Signatur wird geprueft ...'
if (-not (Test-Ed25519Signature $pkg (Get-Content $sigFile -Raw) $releaseKey)) {
  Remove-Item -Recurse -Force $tmp
  throw 'Signatur ungueltig - Paket nicht von QCCheck signiert oder beschaedigt. Nichts installiert.'
}
$dir = Join-Path $app "versions\$version"
if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
New-Item -ItemType Directory -Force $dir | Out-Null
$tarExe = Join-Path $env:SystemRoot 'System32\tar.exe'
& $tarExe -xzf $pkg -C $dir
if ($LASTEXITCODE -ne 0) { throw "Entpacken fehlgeschlagen (tar Code $LASTEXITCODE)." }
try { Confirm-Package $dir $version } catch { Remove-Item -Recurse -Force $dir; Remove-Item -Recurse -Force $tmp; throw }
Set-Content -Path (Join-Path $app 'current.json') -Value "{`"version`":`"$version`"}" -Encoding ascii
# Für die Update-Prüfung der App: woher (GitHub-Repo; im Testmodus die Testquelle)
$src = if ($Base) { @{ base = $Base } } else { @{ repo = $Repo } }
[IO.File]::WriteAllText((Join-Path $app 'install.json'), ($src | ConvertTo-Json -Compress))

# --- die App: eigenes Electron, darin der Starter
$electronDir = Join-Path $app 'electron'
$exe = Join-Path $electronDir 'QCCheck.exe'
if (-not ((Test-Path (Join-Path $electronDir ".ok-$electronVersion")) -and (Test-Path $exe))) {
  Write-Host "Laufzeit der App wird geladen (Electron $electronVersion, ca. 110 MB) ..."
  $zip = Join-Path $tmp 'electron.zip'
  Invoke-WebRequest "https://github.com/electron/electron/releases/download/v$electronVersion/electron-v$electronVersion-win32-x64.zip" -OutFile $zip -UseBasicParsing
  $got = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($got -ne $electronSha256) { Remove-Item -Recurse -Force $tmp; throw "Electron: falsche Pruefsumme ($got) - App nicht installiert." }
  if (Test-Path $electronDir) {
    try { Remove-Item -Recurse -Force $electronDir } catch { throw 'QCCheck laeuft noch - bitte schliessen und die Zeile noch einmal ausfuehren.' }
  }
  New-Item -ItemType Directory -Force $electronDir | Out-Null
  & $tarExe -xf $zip -C $electronDir
  if ($LASTEXITCODE -ne 0) { throw "Electron entpacken fehlgeschlagen (tar Code $LASTEXITCODE)." }
  Rename-Item (Join-Path $electronDir 'electron.exe') 'QCCheck.exe'
  Set-Content -Path (Join-Path $electronDir ".ok-$electronVersion") -Value $electronVersion -Encoding ascii
}
$starter = Join-Path $electronDir 'resources\app'
New-Item -ItemType Directory -Force $starter | Out-Null
Copy-Item (Join-Path $dir 'starter\*') $starter -Force
$shell = New-Object -ComObject WScript.Shell
foreach ($l in $(if ($testRoot) { @() } else { @((Join-Path ([Environment]::GetFolderPath('Desktop')) 'QCCheck.lnk'), (Join-Path ([Environment]::GetFolderPath('Programs')) 'QCCheck.lnk')) })) {
  $s = $shell.CreateShortcut($l)
  $s.TargetPath = $exe
  $s.WorkingDirectory = $electronDir
  $s.Description = 'QCCheck - Pruefung vor der Abgabe an den Sender'
  $s.Save()
}
# --- die Kommandozeile: qccheck.cmd ruft das Electron als Node mit dem CLI-Starter auf
$bin = Join-Path $app 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null
$cmd = "@echo off`r`nsetlocal`r`nset ELECTRON_RUN_AS_NODE=1`r`n`"%~dp0..\electron\QCCheck.exe`" `"%~dp0..\electron\resources\app\cli.cjs`" %*`r`n"
[IO.File]::WriteAllText((Join-Path $bin 'qccheck.cmd'), $cmd)
$pathNote = ''
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $testRoot -and -not ("$userPath" -split ';' | Where-Object { $_ -eq $bin })) {
  [Environment]::SetEnvironmentVariable('Path', ("$userPath;$bin").TrimStart(';'), 'User')
  $pathNote = '(neues Terminal oeffnen, damit qccheck gefunden wird)'
}
Remove-Item -Recurse -Force $tmp
Write-Host ''
Write-Host "Fertig: QCCheck $version."
Write-Host '  App: Desktop und Startmenue > QCCheck. Dateien oder Ordner ins Fenster ziehen.'
Write-Host "  Kommandozeile: qccheck film.mxf --profile zdf $pathNote"
Write-Host '  Updates: die App meldet sie oben rechts.'
Write-Host ''
Write-Host 'Entfernen: Verknuepfungen QCCheck loeschen, dazu die Ordner'
Write-Host "  $app"
Write-Host "  $(Join-Path $env:APPDATA 'QCCheck')"
