package entities;

public class AuthDetails {
    private String username;
    private String token;
    private Long expiration;

    public AuthDetails(String username, String token, Long expiration) {
        this.username = username;
        this.token = token;
        this.expiration = expiration;
    }

    public String getToken() {
        return this.token;
    }

    public Long getTokenExpiration() {
        return this.expiration;
    }

    public String getUsername() {
        return this.username;
    }
}
