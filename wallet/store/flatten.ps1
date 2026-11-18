# Copyright (c) Privasys. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only
#
# App Store Connect refuses screenshots with an alpha channel, and browsers
# write PNGs with one. This redraws every PNG in a folder as 24-bit RGB, in
# place, and checks its size. Windows PowerShell 5.1 (System.Drawing).
#
#   powershell -File store/flatten.ps1 -Dir <folder> [-Width 1320 -Height 2868]

param([Parameter(Mandatory = $true)][string]$Dir, [int]$Width = 0, [int]$Height = 0)
Add-Type -AssemblyName System.Drawing
Get-ChildItem -Path $Dir -Filter *.png | ForEach-Object {
    $src = [System.Drawing.Image]::FromFile($_.FullName)
    $w = $src.Width; $h = $src.Height
    $bmp = New-Object System.Drawing.Bitmap($w, $h, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.Clear([System.Drawing.Color]::White)
    $g.DrawImage($src, 0, 0, $w, $h)
    $g.Dispose(); $src.Dispose()
    $tmp = "$($_.FullName).tmp"
    $bmp.Save($tmp, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
    Move-Item -Force $tmp $_.FullName
    $ok = ($Width -eq 0) -or ($w -eq $Width -and $h -eq $Height)
    Write-Output ("{0}  {1}x{2}  {3}" -f $_.Name, $w, $h, $(if ($ok) { 'ok' } else { 'WRONG SIZE' }))
}
