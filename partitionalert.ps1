$parts = Get-WmiObject Win32_Volume -Filter "DriveType='3'" | ForEach {
                $Name = $_.Name
                $Label = $_.Label
                $FreeSpace_GB = ([Math]::Round($_.FreeSpace /1GB,2))
                $TotalSize_GB = ([Math]::Round($_.Capacity /1GB,2))
                $UsedSpace_GB = ([Math]::Round($_.Capacity /1GB,2)) - ([Math]::Round($_.FreeSpace /1GB,2))
            if ([Math]::($FreeSpace_GB / $TotalSize_GB) * 100 -lt 70) 
            {
            if (([System.Diagnostics.EventLog]::SourceExists("partitionmonitor") -ne "True"))
                {
                New-EventLog -Source "partitionmonitor" -LogName "Application"
                }

            $lastlog = Get-EventLog -LogName "Application" -InstanceId "8888" -Source "partitionmonitor" -Newest 1 -Message "*$basename*"
            if ($lastlog -lt $(Get-Date).AddMinutes(-60))
                {
                Write-EventLog -LogName "Application" -Source "partitionmonitor" -EventID 8888 -EntryType Information -Message "Alert: $($MyInvocation.MyCommand.name) has detected a partition at 70% capacity on $env:computername" -Category 1 -RawData 10,20
                }
            }
            }