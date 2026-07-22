<#
    File: Select-MBItem.ps1
    Author: 0x0ff537 - Claude Code
    Description: Cross-platform interactive selection helper used as a drop-in
                 replacement for "Out-GridView -PassThru".

                 Out-GridView relies on a Windows-only GUI assembly and is not
                 available on PowerShell Core running on Linux/macOS (e.g. Kali).
                 This helper presents a numbered console menu instead, returning
                 the selected object(s) just like Out-GridView -PassThru did.

                 On Windows (where Out-GridView exists) it transparently falls
                 back to the native Out-GridView so the original GUI experience
                 is preserved.
#>

Function Select-MBItem
{
<#
    .SYNOPSIS
        Interactive, cross-platform item picker. Drop-in replacement for
        "Out-GridView -PassThru".
    .DESCRIPTION
        Accepts objects from the pipeline, displays them in a numbered table,
        and returns the object(s) the user selects. Supports selecting multiple
        items (comma/space separated), all items ('a'), or cancelling (empty
        input). On Windows, defers to the native Out-GridView when present.
    .PARAMETER InputObject
        The objects to choose from (accepted from the pipeline).
    .PARAMETER Title
        Heading shown above the list. Matches Out-GridView's -Title.
    .PARAMETER PassThru
        Accepted for compatibility with Out-GridView call sites. Selected
        objects are always returned, so this switch is effectively a no-op.
    .PARAMETER Single
        Restrict the selection to a single item.
    .PARAMETER MaxColumns
        Maximum number of object properties to show as columns in the menu
        (default 8) to keep the table from wrapping. Display only; the full
        original objects are still returned.
    .EXAMPLE
        $subChoice = $Subscriptions | Select-MBItem -Title "Select One or More Subscriptions"
#>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true)]
        [object[]]$InputObject,

        [string]$Title = "Select item(s)",

        [switch]$PassThru,

        [switch]$Single,

        [int]$MaxColumns = 8
    )

    Begin
    {
        $items = New-Object System.Collections.Generic.List[object]
    }

    Process
    {
        if ($null -ne $InputObject)
        {
            foreach ($obj in $InputObject) { $items.Add($obj) }
        }
    }

    End
    {
        if ($items.Count -eq 0) { return }

        # On Windows (or Windows PowerShell Desktop), use the native GUI grid if available.
        $onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($IsWindows -eq $true)
        if ($onWindows -and (Get-Command Out-GridView -ErrorAction SilentlyContinue))
        {
            if ($Single)
            {
                return ($items | Out-GridView -Title $Title -OutputMode Single)
            }
            else
            {
                return ($items | Out-GridView -Title $Title -PassThru)
            }
        }

        # ---- Console fallback (Linux/macOS or no Out-GridView) ----
        Write-Host ""
        Write-Host $Title -ForegroundColor Cyan

        # Build a numbered display table without mutating the original objects.
        $display = for ($i = 0; $i -lt $items.Count; $i++)
        {
            $current = $items[$i]
            $row = [ordered]@{ '#' = $i + 1 }

            # Scalars (strings, value types) have no meaningful properties to
            # list as columns, so show the value itself instead.
            if (($current -is [string]) -or ($current -is [System.ValueType]) -or ($null -eq $current))
            {
                $row['Value'] = $current
            }
            else
            {
                $props = @($current.PSObject.Properties | Select-Object -First $MaxColumns)
                foreach ($p in $props) { $row[$p.Name] = $p.Value }
            }
            [pscustomobject]$row
        }
        $display | Format-Table -AutoSize | Out-Host

        if ($Single)
        {
            $prompt = "Enter the number of your selection (or press Enter to cancel)"
        }
        else
        {
            $prompt = "Enter number(s), comma-separated, 'a' for all (or press Enter to cancel)"
        }

        while ($true)
        {
            $answer = Read-Host $prompt

            # Empty input cancels, mirroring closing the Out-GridView window.
            if ([string]::IsNullOrWhiteSpace($answer)) { return }

            $answer = $answer.Trim()

            if ((-not $Single) -and ($answer.ToLower() -eq 'a'))
            {
                return $items.ToArray()
            }

            $picked = New-Object System.Collections.Generic.List[object]
            $valid = $true
            foreach ($token in ($answer -split '[,\s]+' | Where-Object { $_ -ne '' }))
            {
                if ($token -match '^\d+$')
                {
                    $n = [int]$token
                    if (($n -ge 1) -and ($n -le $items.Count))
                    {
                        $picked.Add($items[$n - 1])
                    }
                    else { $valid = $false; break }
                }
                else { $valid = $false; break }
            }

            if ((-not $valid) -or ($picked.Count -eq 0))
            {
                Write-Host "Invalid selection. Enter a number between 1 and $($items.Count)." -ForegroundColor Yellow
                continue
            }

            if ($Single) { return $picked[0] }
            return $picked.ToArray()
        }
    }
}
