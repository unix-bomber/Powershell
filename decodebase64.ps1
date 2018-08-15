$file = "pathtofile"
#change delimiter based on requirements
$data = Get-Content $file -Delimiter '|'
#remove delimiter
$data = $data.replace("|","")
foreach ($d in $data){
  [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("$d")) | Out-File -Encoding "ASCII" "pathtodestinationfile" -append
  }
