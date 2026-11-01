
import java.util.*;
import java.time.LocalDateTime;
import java.time.Duration;
import java.io.FileWriter;
import java.io.IOException;

public class Main {

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);
        int num = 0;

        // Sample login records
        String[] loginAttempts = {
            "SUCCESS", "FAILED", "FAILED", "SUCCESS",
            "FAILED", "FAILED", "FAILED", "SUCCESS"
        };

        // Sample failed login IP addresses
        String[] failedIPs = {
            "192.168.1.10",
            "192.168.1.20",
            "192.168.1.10",
            "192.168.1.30",
            "192.168.1.10",
            "192.168.1.20",
            "192.168.1.10"
        };

        // Sample timestamps
        LocalDateTime[] attemptTimes = {
            LocalDateTime.of(2026, 11, 1, 14, 30),
            LocalDateTime.of(2026, 11, 1, 14, 31),
            LocalDateTime.of(2026, 11, 1, 14, 32),
            LocalDateTime.of(2026, 11, 1, 14, 33),
            LocalDateTime.of(2026, 11, 1, 14, 34),
            LocalDateTime.of(2026, 11, 1, 14, 35),
            LocalDateTime.of(2026, 11, 1, 14, 40)
        };

        do {

            System.out.println("\nLOGGUARD");
            System.out.println("SECURITY LOG ANALYZER\n");

            System.out.println("1. Load Log");
            System.out.println("2. Analyze Login Attempts");
            System.out.println("3. Detect Suspicious Activity");
            System.out.println("4. Generate Report");
            System.out.println("5. Exit\n");

            System.out.println("Please enter a number:");

            try {

                num = sc.nextInt();

                switch (num) {

                    case 1:
                        System.out.println("Loading log...");
                        System.out.println("Feature coming soon!");
                        break;

                    case 2:
                        System.out.println("Analyzing login attempts...");

                        int failedCount = countFailedLogins(loginAttempts);
                        int successCount = loginAttempts.length - failedCount;

                        System.out.println("\n===== LOGIN ANALYSIS REPORT =====");

                        System.out.println(
                            "Total Login Attempts: " + loginAttempts.length
                        );

                        System.out.println(
                            "Successful Logins: " + successCount
                        );

                        System.out.println(
                            "Failed Logins: " + failedCount
                        );

                        if (failedCount >= 3) {
                            System.out.println(
                                "\nSECURITY NOTICE: High number of failed logins!"
                            );
                        } else {
                            System.out.println(
                                "\nFailed login count is below the alert threshold."
                            );
                        }

                        break;

                    case 3:
                        System.out.println("Detecting suspicious activity...");

                        HashMap<String, Integer> ipCounts = new HashMap<>();

                        for (int i = 0; i < failedIPs.length; i++) {

                            String ip = failedIPs[i];

                            ipCounts.put(
                                ip,
                                ipCounts.getOrDefault(ip, 0) + 1
                            );
                        }

                        System.out.println(
                            "\n===== SUSPICIOUS ACTIVITY REPORT ====="
                        );

                        for (Map.Entry<String, Integer> entry : ipCounts.entrySet()) {

                            System.out.println(
                                entry.getKey() +
                                " | Total failed attempts: " +
                                entry.getValue()
                            );
                        }

                        HashSet<String> suspiciousIPs =
                            detectSuspiciousIPs(failedIPs, attemptTimes);

                        if (suspiciousIPs.isEmpty()) {

                            System.out.println(
                                "\nNo suspicious activity detected."
                            );

                        } else {

                            for (String ip : suspiciousIPs) {

                                System.out.println(
                                    "\nSECURITY ALERT: " + ip +
                                    " - Possible brute-force attack within 5 minutes!"
                                );
                            }
                        }

                        break;

                    case 4:
                        System.out.println("Generating security report...");

                        String report = generateReport(
                            loginAttempts,
                            failedIPs,
                            attemptTimes
                        );

                        // Display the complete report in the console
                        System.out.println("\n" + report);

                        // Try to save the same report as a TXT file
                        try {

                            saveReport(report);

                            System.out.println(
                                "Report saved successfully: security-report.txt"
                            );

                        } catch (IOException e) {

                            System.out.println(
                                "Could not save the TXT file."
                            );

                            System.out.println(e.getMessage());

                            System.out.println(
                                "You can copy the report above into a TXT file."
                            );
                        }

                        break;

                    case 5:
                        System.out.println(
                            "Exiting LOGGUARD... You exited!"
                        );
                        break;

                    default:
                        System.out.println(
                            "Invalid choice! Please select a number between 1 and 5."
                        );
                }

            } catch (InputMismatchException e) {

                System.out.println(
                    "Invalid input! Please enter a whole number between 1 and 5."
                );

                sc.nextLine();
            }

        } while (num != 5);

        sc.close();
    }


    // METHOD 1: Count failed logins

    public static int countFailedLogins(String[] attempts) {

        int failedCount = 0;

        for (int i = 0; i < attempts.length; i++) {

            if (attempts[i].equals("FAILED")) {
                failedCount++;
            }
        }

        return failedCount;
    }


    // METHOD 2: Detect suspicious IPs

    public static HashSet<String> detectSuspiciousIPs(
            String[] failedIPs,
            LocalDateTime[] attemptTimes) {

        HashSet<String> suspiciousIPs = new HashSet<>();

        for (int i = 0; i < failedIPs.length; i++) {

            String currentIP = failedIPs[i];
            int attemptsInWindow = 0;

            for (int j = 0; j < failedIPs.length; j++) {

                if (currentIP.equals(failedIPs[j])) {

                    Duration difference =
                        Duration.between(
                            attemptTimes[i],
                            attemptTimes[j]
                        );

                    if (!difference.isNegative() &&
                        difference.compareTo(Duration.ofMinutes(5)) <= 0) {

                        attemptsInWindow++;
                    }
                }
            }

            if (attemptsInWindow >= 3) {
                suspiciousIPs.add(currentIP);
            }
        }

        return suspiciousIPs;
    }


    // METHOD 3: Generate security report text

    public static String generateReport(
            String[] loginAttempts,
            String[] failedIPs,
            LocalDateTime[] attemptTimes) {

        int failedCount = countFailedLogins(loginAttempts);

        int successCount = loginAttempts.length - failedCount;

        HashSet<String> suspiciousIPs =
            detectSuspiciousIPs(failedIPs, attemptTimes);

        StringBuilder report = new StringBuilder();

        report.append("===== LOGGUARD SECURITY REPORT =====\n\n");

        report.append(
            "Total Login Attempts: " + loginAttempts.length + "\n"
        );

        report.append(
            "Successful Logins: " + successCount + "\n"
        );

        report.append(
            "Failed Logins: " + failedCount + "\n\n"
        );

        report.append("===== SECURITY ANALYSIS =====\n");

        report.append(
            "Total Failed IP Records: " + failedIPs.length + "\n"
        );

        report.append(
            "Suspicious IPs Detected: " + suspiciousIPs.size() + "\n"
        );

        if (suspiciousIPs.isEmpty()) {

            report.append("\nNo suspicious activity detected.\n");

        } else {

            for (String ip : suspiciousIPs) {

                report.append(
                    "Suspicious IP: " + ip + "\n"
                );
            }

            report.append(
                "\nThreat Type: Possible Brute-Force Attack\n"
            );

            report.append(
                "Detection Window: 5 minutes\n"
            );
        }

        report.append("\n===== END OF REPORT =====\n");

        return report.toString();
    }


    // METHOD 4: Save report to TXT file

    public static void saveReport(String report) throws IOException {

        try (FileWriter writer = new FileWriter("security-report.txt")) {

            writer.write(report);
        }
    }
}
