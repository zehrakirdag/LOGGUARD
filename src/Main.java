import java.util.*;
import java.time.LocalDateTime;
import java.time.Duration;



public class Main {
    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);
        int num = 0;

        do {
            System.out.println("\nLOGGUARD\nSECURITY LOG ANALYZER\n");

            System.out.println("1. Load Log\n" +
                               "2. Analyze Login Attempts\n" +
                               "3. Detect Suspicious Activity\n" +
                               "4. Generate Report\n" +
                               "5. Exit\n");

            System.out.println("Please enter a number:");

            try {
                num = sc.nextInt();

                switch (num) {
                    case 1:
                        System.out.println("Loading log...");
                        break;

                    case 2:
                        System.out.println("Analyzing login attempts...");
                        String[] LoginAttempts = { "SUCCESS", "FAILED", "FAILED", "SUCCESS", "FAILED", "FAILED", "FAILED", "SUCCESS" };
                        int successCount = 0 ;
                        int failedCount = 0;

                        for(int i=0; i< LoginAttempts.length ; i++){
                          if (LoginAttempts[i].equals("SUCCESS")){
                            successCount ++;
                          }
                          if (LoginAttempts[i].equals("FAILED")){
                            failedCount++;
                          }
                        }
                        if (failedCount >= 3) {
                              System.out.println("SECURITY ALERT: Too many failed login attempts!");
                          } else {
                              System.out.println("No suspicious activity detected.");
                          }

                        System.out.println("\n===== LOGIN ANALYSIS REPORT =====");
                        System.out.println("Total Login Attempts: " + LoginAttempts.length);
                        System.out.println("Successful Logins: " + successCount);
                        System.out.println("Failed Logins: " + failedCount);

                        
                        break;

                                  
                case 3:
                    System.out.println("Detecting suspicious activity...");

                    String[] failedIPs = {
                        "192.168.1.10",
                        "192.168.1.20",
                        "192.168.1.10",
                        "192.168.1.30",
                        "192.168.1.10",
                        "192.168.1.20",
                        "192.168.1.10"
                    };

                    LocalDateTime[] attemptTimes = {
                        LocalDateTime.of(2026, 11, 1, 14, 30),
                        LocalDateTime.of(2026, 11, 1, 14, 31),
                        LocalDateTime.of(2026, 11, 1, 14, 32),
                        LocalDateTime.of(2026, 11, 1, 14, 33),
                        LocalDateTime.of(2026, 11, 1, 14, 34),
                        LocalDateTime.of(2026, 11, 1, 14, 35),
                        LocalDateTime.of(2026, 11, 1, 14, 40)
                    };

                    HashMap<String, Integer> ipCounts = new HashMap<>();

                    // Count total failed attempts for each IP
                    for (int i = 0; i < failedIPs.length; i++) {
                        String ip = failedIPs[i];
                        ipCounts.put(ip, ipCounts.getOrDefault(ip, 0) + 1);
                    }

                    System.out.println("\n===== SUSPICIOUS ACTIVITY REPORT =====");

                    // Display total failed attempts
                    for (Map.Entry<String, Integer> entry : ipCounts.entrySet()) {
                        System.out.println(
                            entry.getKey() + " | Total failed attempts: " + entry.getValue()
                        );
                    }

                    // Track IP addresses that have already triggered an alert
                    HashSet<String> alertedIPs = new HashSet<>();

                    // Check every possible starting point
                    for (int i = 0; i < failedIPs.length; i++) {

                        String currentIP = failedIPs[i];
                        int attemptsInWindow = 0;

                        // Compare with other login attempts
                        for (int j = 0; j < failedIPs.length; j++) {

                            if (currentIP.equals(failedIPs[j])) {

                                Duration difference =
                                    Duration.between(attemptTimes[i], attemptTimes[j]);

                                // Only count attempts within the next 5 minutes
                                if (!difference.isNegative() &&
                                    difference.compareTo(Duration.ofMinutes(5)) <= 0) {

                                    attemptsInWindow++;
                                }
                            }
                        }

                        // Generate only one alert per IP
                        if (attemptsInWindow >= 3 && !alertedIPs.contains(currentIP)) {

                            System.out.println(
                                "\nSECURITY ALERT: " + currentIP +
                                " - Possible brute-force attack within 5 minutes!"
                            );

                            System.out.println(
                                "Failed attempts in time window: " + attemptsInWindow
                            );

                            alertedIPs.add(currentIP);
                        }
                    }

                    if (alertedIPs.isEmpty()) {
                        System.out.println("\nNo suspicious activity detected.");
                    }

                    break;

                                        
                                        

                    case 4:
                        System.out.println("Generating report...");
                        break;

                    case 5:
                        System.out.println("Exiting LOGGUARD... You exited!");
                        break;

                    default:
                        System.out.println("Invalid choice! Please select a number between 1 and 5.");
                }

            } catch (InputMismatchException e) {
                System.out.println("Invalid input! Please enter a whole number between 1 and 5.");
                sc.nextLine();
            }

        } while (num != 5);

        sc.close();
    }
}
