package com.eddy.authserver.dto.auth;

import java.sql.Date;
import java.util.Objects;

public class VerificationToken {

    private String token;
    private Date expiryDate;
    private String userId;

    private VerificationToken() {
    }

    public VerificationToken(String token, Date expiryDate, String userId) {
        this.token = token;
        this.expiryDate = expiryDate;
        this.userId = userId;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Date expiryDate) {
        this.expiryDate = expiryDate;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerificationToken that = (VerificationToken) o;
        return Objects.equals(token, that.token) && Objects.equals(expiryDate, that.expiryDate) && Objects.equals(userId, that.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(token, expiryDate, userId);
    }

    @Override
    public String toString() {
        return "{" +
                "token='" + token + '\'' +
                ", expiryDate=" + expiryDate +
                ", userId='" + userId + '\'' +
                '}';
    }
}
