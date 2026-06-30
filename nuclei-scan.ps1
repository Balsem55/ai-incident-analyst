param(
    [string]$target,
    [string]$severity = "medium,high,critical"
)

$outputFile = "C:\Tools\nuclei\scan-result.json"

# Lance le scan Nuclei
& "C:\Tools\nuclei\nuclei.exe" -u $target -severity $severity -j -o $outputFile -silent | Out-Null

# Lit les résultats
if (Test-Path $outputFile) {
    $lines = Get-Content $outputFile
    $results = @()
    
    foreach ($line in $lines) {
        try {
            $results += $line | ConvertFrom-Json
        } catch {}
    }
    
    $vulns = @()
    foreach ($r in $results) {
        $vulns += @{
            name = $r.info.name
            severity = $r.info.severity
            url = $r.'matched-at'
            template = $r.'template-id'
        }
    }
    
    $summary = @{
        target = $target
        total = $results.Count
        critical = ($results | Where-Object { $_.info.severity -eq "critical" }).Count
        high = ($results | Where-Object { $_.info.severity -eq "high" }).Count
        medium = ($results | Where-Object { $_.info.severity -eq "medium" }).Count
        vulnerabilities = $vulns | Select-Object -First 10
    }
    
    $summary | ConvertTo-Json -Depth 5
    
    Remove-Item $outputFile -Force
} else {
    @{ target = $target; total = 0; message = "No vulnerabilities found" } | ConvertTo-Json
}