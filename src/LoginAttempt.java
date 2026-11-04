import java.time.LocalDateTime;

public class LoginAttempt {

    private final String ipAddress;
    private final String status;
    private final LocalDateTime attemptTime;

    // Constructor
    public LoginAttempt(
            String ipAddress,
            String status,
            LocalDateTime attemptTime) {

        if (ipAddress == null || ipAddress.isBlank()) {
            throw new IllegalArgumentException("IP address cannot be empty!");
        }

        if (!"SUCCESS".equals(status) && !"FAILED".equals(status)) {
            throw new IllegalArgumentException("Invalid login status!");
        }

        if (attemptTime == null) {
            throw new IllegalArgumentException("Attempt time cannot be null!");
        }

        this.ipAddress = ipAddress;
        this.status = status;
        this.attemptTime = attemptTime;
    }

    // Getter methods
    public String getIpAddress() {
        return ipAddress;
    }

    public String getStatus() {
        return status;
    }

    public LocalDateTime getAttemptTime() {
        return attemptTime;
    }
}