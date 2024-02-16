package com.eddy.authserver.dto.auth;

import java.sql.Date;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.UUID;

public class TokenGenerator {

    private static final int EXPIRATION = 60 * 24;

    private TokenGenerator() {
    }

    public static VerificationToken generate(String userId) {
        String token = UUID.randomUUID().toString();
        Date expiryDate = calculateExpiryDate();
        return new VerificationToken(token, expiryDate, userId);
    }

    private static Date calculateExpiryDate() {
        Calendar cal = Calendar.getInstance();
        cal.setTime(new Timestamp(cal.getTime().getTime()));
        cal.add(Calendar.MINUTE, TokenGenerator.EXPIRATION);
        return new Date(cal.getTime().getTime());
    }

}
