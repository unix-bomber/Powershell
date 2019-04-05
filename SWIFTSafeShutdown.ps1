$activityflagpath1 = "C:\whatever.txt"
$activityflagpath2 = "C:\whatever.txt"
$activityflagpath3 = "C:\whatever.txt"
$activityflagpath4 = "C:\whatever.txt"
$flags = $activityflagpath1, $activityflagpath2, $activityflagpath3, $activityflagpath4

$task1 = "My Task"
$task2 = "My Task"
$task3 = "My Task"
$task4 = "My Task"
$task5 = "My Task"
$task6 = "My Task"
$tasks = $task1, $task2, $task3, $task4, $task5, $task6

if (([System.Diagnostics.EventLog]::SourceExists("SWIFTSafeShutdown") -ne "True"))
    {
    New-EventLog -Source "SWIFTSafeShutdown" -LogName "Application"
    }

if (([System.Diagnostics.EventLog]::SourceExists("SWIFTSafeShutdown") -ne "True"))
    {
    New-EventLog -Source "SWIFTSafeStartup" -LogName "Application"
    }

try {

foreach ($task in $tasks) {
schtasks.exe /CHANGE /TN "$task" /DISABLE
}

foreach ($flag in $flags){
    While ((Get-Content $flag) -eq "Active"){
    start-sleep -seconds 5
    }
}
Write-EventLog -LogName "Application" -source "SwiftSafeShutdown" -EventId 1001 -EntryType Information -Message "Info: Thanks for using the safe shutdown, errors to follow" -Category 1 -RawData 10,20
}

Catch {
Write-EventLog -LogName "Application" -source "SwiftSafeShutdown" -EventId 1000 -EntryType Information -Message "Error: $($_.Exception.Message)" -Category 1 -RawData 10,20
}

Restart-Computer -Wait 1 -Force
