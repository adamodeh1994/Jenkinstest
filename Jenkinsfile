pipeline {
    agent any

    stages {
        stage('Check Password Change') {
            steps {
                script {
                    // Define your logic here to check if an account's password has changed after 7 days
                    // You can use PowerShell to perform this task
                    powershell(script: '''
                        # PowerShell script to check password change
                        $accountName = "YourAccountNameHere"
                        $lastPasswordChange = (Get-ADUser $accountName -Properties "PasswordLastSet").PasswordLastSet
                        $currentDate = Get-Date
                        $passwordAge = $currentDate - $lastPasswordChange
                        $passwordAgeDays = [math]::Round($passwordAge.TotalDays)

                        if ($passwordAgeDays -gt 7) {
                            Write-Host "Password for $accountName changed more than 7 days ago."
                            // You can add additional steps here, like sending notifications or taking actions
                        } else {
                            Write-Host "Password for $accountName changed within the last 7 days."
                        }
                    ''')
                }
            }
        }
    }
}
