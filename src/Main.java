
import java.util.*;
import java.time.LocalDateTime;
import java.io.FileWriter;
import java.io.IOException;

public class Main {

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);
        int num = 0;

        // Create login attempt objects
        List<LoginAttempt> attempts = new ArrayList<>();

        attempts.add(new LoginAttempt(
            "192.0.2.10", "FAILED",
            LocalDateTime.of(2026, 11, 1, 14, 30)
        ));

        attempts.add(new LoginAttempt(
            "192.0.2.20", "SUCCESS",
            LocalDateTime.of(2026, 11, 1, 14, 31)
        ));

        attempts.add(new LoginAttempt(
            "192.0.2.10", "FAILED",
            LocalDateTime.of(2026, 11, 1, 14, 32)
        ));

        attempts.add(new LoginAttempt(
            "192.0.2.30", "SUCCESS",
            LocalDateTime.of(2026, 11, 1, 14, 33)
        ));

        attempts.add(new LoginAttempt(
            "192.0.2.10", "FAILED",
            LocalDateTime.of(2026, 11, 1, 14, 34)
        ));

        attempts.add(new LoginAttempt(
            "192.0.2.20", "FAILED",
            LocalDateTime.of(2026, 11, 1, 14, 35)
        ));

        attempts.add(new LoginAttempt(
            "192.0.2.40", "SUCCESS",
            LocalDateTime.of(2026, 11, 1, 14, 36)
        ));

        attempts.add(new LoginAttempt(
            "192.0.2.10", "FAILED",
            LocalDateTime.of(2026, 11, 1, 14, 40)
        ));

        // Create analyzer object
        LogAnalyzer analyzer = new LogAnalyzer();

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

                        int failedCount =
                            analyzer.countFailedLogins(attempts);

                        int successCount =
                            attempts.size() - failedCount;

                        System.out.println(
                            "\n===== LOGIN ANALYSIS REPORT ====="
                        );

                        System.out.println(
                            "Total Login Attempts: " + attempts.size()
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

                        Map<String, Integer> ipCounts = new HashMap<>();

                        // Count failed attempts per IP
                        for (LoginAttempt attempt : attempts) {

                            if (attempt.getStatus().equals("FAILED")) {

                                String ip = attempt.getIpAddress();

                                ipCounts.put(
                                    ip,
                                    ipCounts.getOrDefault(ip, 0) + 1
                                );
                            }
                        }

                        System.out.println(
                            "\n===== SUSPICIOUS ACTIVITY REPORT ====="
                        );

                        for (Map.Entry<String, Integer> entry :
                                ipCounts.entrySet()) {

                            System.out.println(
                                entry.getKey() +
                                " | Total failed attempts: " +
                                entry.getValue()
                            );
                        }

                        // Detect suspicious IPs using LogAnalyzer
                        Set<String> suspiciousIPs =
                            analyzer.detectSuspiciousIPs(attempts);

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
                            attempts,
                            analyzer
                        );

                        // Display report in console
                        System.out.println("\n" + report);

                        // Save report to TXT file
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

    // METHOD 1: Generate security report

    public static String generateReport(
            List<LoginAttempt> attempts,
            LogAnalyzer analyzer) {

        int failedCount =
            analyzer.countFailedLogins(attempts);

        int successCount =
            attempts.size() - failedCount;

        Set<String> suspiciousIPs =
            analyzer.detectSuspiciousIPs(attempts);

        StringBuilder report = new StringBuilder();

        report.append(
            "===== LOGGUARD SECURITY REPORT =====\n\n"
        );

        report.append(
            "Total Login Attempts: " + attempts.size() + "\n"
        );

        report.append(
            "Successful Logins: " + successCount + "\n"
        );

        report.append(
            "Failed Logins: " + failedCount + "\n\n"
        );

        report.append("===== SECURITY ANALYSIS =====\n");

        report.append(
            "Total Failed IP Records: " + failedCount + "\n"
        );

        report.append(
            "Suspicious IPs Detected: " + suspiciousIPs.size() + "\n"
        );

        if (suspiciousIPs.isEmpty()) {

            report.append(
                "\nNo suspicious activity detected.\n"
            );

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

        report.append(
            "\n===== END OF REPORT =====\n"
        );

        return report.toString();
    }

    // METHOD 2: Save report to TXT file

    public static void saveReport(String report)
            throws IOException {

        try (FileWriter writer =
                new FileWriter("security-report.txt")) {

            writer.write(report);
        }
    }
}
