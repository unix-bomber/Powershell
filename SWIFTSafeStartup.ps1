$activityflagpath1 = "C:\users\kactw\desktop\test.txt"
$activityflagpath2 = "C:\users\kactw\desktop\test1.txt"
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

try{
foreach ($flag in $flags){
    Set-Content -Path $flag -Value "Inactive"
}

foreach ($task in $tasks) {
schtasks.exe /CHANGE /TN "$task" /ENABLE
}

Write-EventLog -LogName "Application" -source "SwiftSafeStartup" -EventId 1000 -EntryType Information -Message "Info: Computer rebooted, check additional logs for errors" -Category 1 -RawData 10,20
}

Catch {
Write-EventLog -LogName "Application" -source "SwiftSafeStartup" -EventId 1001 -EntryType Information -Message "Error: $($_.Exception.Message)" -Category 1 -RawData 10,20
}