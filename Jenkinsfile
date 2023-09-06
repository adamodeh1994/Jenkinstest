pipeline {
    agent any

    stages {
        stage('Check Password Change') {
            steps {
                script {
                    // Define your logic here to check if an account's password has changed after 7 days
                    // You can use PowerShell to perform this task
                    powershell(script: '''
                      # Set the time interval in minutes to check for password changes
											$minutesToCheck = 2
											
											# Calculate the time threshold
											$thresholdTime = (Get-Date).AddMinutes(-$minutesToCheck)
											
											# Get the Security event log entries for password changes
											$events = Get-WinEvent -LogName Security | Where-Object {
											    $_.Id -eq 4723 -or $_.Id -eq 4724 -or $_.Id -eq 4725
											}
											
											# Iterate through the events and check the timestamp
											foreach ($event in $events) {
											    if ($event.TimeCreated -ge $thresholdTime) {
											        Write-Host "User $($event.Properties[0].Value) changed their password within the last $minutesToCheck minutes."
											        # You can add additional actions here if needed
											    }
											}
										''')
                }
            }
        }
    }
}
