##################
##SMTP settings ##
##################
$SMTPAlert = $True #turns the alert on or off
$SMTPAlertTime = "60" #if data hasn't been transfered in 'x' minutes, send an email 
$SMTPServer = "192.168.0.3"#IP address or hostname of mail server
$SMTPPort = "25"#port to connect with
$SMTPFrom = "pfts@gmail.com" #use the format x@domain
$SMTPTo = "pfts@gmail.com" #use the format x@domain
$SMTPSubject = "Critical Error"# this will automatically provide the name of the datafeed at the end
$SMTPPriority = "High" #use "High" "Medium" or "Low"

$Partmon = Get-EventLog -LogName Application -InstanceId "8888" -Newest 1 -Message ""
$MQmon = Get-EventLog -LogName Application -Newest 1 -Message ""

$Parent = $partmon, $MQmon

foreach ($Child in $Parent) 
    {
    if ($Child.TimeGenerated -lt $(Get-Date).AddMinutes(-$SMTPAlertTime))
        {
        Send-MailMessage -Port $SMTPPort -From $SMTPFrom -subject ("$SMTPSubject" + $Child.source + "error") -To $SMTPTo -Priority $SMTPPriority -SmtpServer $SMTPServer -Body $Child.message
        }
    }