$ErrorActionPreference='Stop'
$sourcePath=Join-Path $PSScriptRoot '../AttackMap.NativeSpike/NativeAccessibility.cs'
$source=Get-Content -LiteralPath $sourcePath -Raw
$expected=@('open_report','choose_repository','scan','cancel','export','settings','history')
foreach($key in $expected){if($source -notmatch ('\["'+$key+'"\]=')){throw "Missing public shortcut declaration $key"}}
if($source -notmatch 'element.Visibility!=Visibility.Visible'){throw 'Collapsed tree exclusion missing'}
if($source -notmatch 'enabled && !focusable'){throw 'Disabled focusability guard missing'}
if($source -notmatch 'primary==null \|\| !primary.IsEnabled'){throw 'Disabled primary accelerator guard missing'}
if($source -notmatch 'accelerator.Invoked-=handler;root.KeyboardAccelerators.Remove'){throw 'Owned accelerator cleanup missing'}
if($source -match 'SetForegroundWindow|SendInput|UIAutomationClient|SetValue\(.+Foreground|Task.Delay|Thread.Sleep'){throw 'Unexpected external automation, styling or fixed wait'}
[ordered]@{sourceChecksPassed=12;scope='Source guard checks only; not compilation, runtime UI automation, keyboard task or Narrator proof';sourceSha256=(Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash;manualAcceptance='unmeasured'} | ConvertTo-Json
