
import java.util.*;
import java.time.Duration;

public class LogAnalyzer {

    // METHOD 1: Count failed login attempts
    public int countFailedLogins(List<LoginAttempt> attempts) {

        int failedCount = 0;

        for (LoginAttempt attempt : attempts) {

            if (attempt.getStatus().equals("FAILED")) {
                failedCount++;
            }
        }

        return failedCount;
    }

    // METHOD 2: Detect suspicious IP addresses
    public Set<String> detectSuspiciousIPs(List<LoginAttempt> attempts) {

        Set<String> suspiciousIPs = new HashSet<>();

        for (int i = 0; i < attempts.size(); i++) {

            LoginAttempt current = attempts.get(i);

            if (!current.getStatus().equals("FAILED")) {
                continue;
            }

            int attemptsInWindow = 0;

            for (int j = 0; j < attempts.size(); j++) {

                LoginAttempt other = attempts.get(j);

                if (other.getStatus().equals("FAILED") &&
                    current.getIpAddress().equals(other.getIpAddress())) {

                    Duration difference = Duration.between(
                        current.getAttemptTime(),
                        other.getAttemptTime()
                    );

                    if (!difference.isNegative() &&
                        difference.compareTo(Duration.ofMinutes(5)) <= 0) {

                        attemptsInWindow++;
                    }
                }
            }

            if (attemptsInWindow >= 3) {
                suspiciousIPs.add(current.getIpAddress());
            }
        }

        return suspiciousIPs;
    }
}
