
import java.util.*;

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
                        String[] FailedIPs = { 
                        "192.168.1.10",
                        "192.168.1.20",
                        "192.168.1.10",
                        "192.168.1.30",
                        "192.168.1.10",
                        "192.168.1.20",
                        "192.168.1.10"
                       };

                        int attemptCount = 0;

                        for(int i=0 ; i< FailedIPs.length ; i++){
                          if (FailedIPs[i].equals("192.168.1.10")){
                            attemptCount ++;
                          }
                        }

                        if (attemptCount >= 3) {
                          System.out.println("===== SUSPICIOUS ACTIVITY REPORT =====\n" +
                          "\n" +
                          "IP Address: 192.168.1.10\n"+

                          "SECURITY ALERT: Possible brute-force attack!");
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

