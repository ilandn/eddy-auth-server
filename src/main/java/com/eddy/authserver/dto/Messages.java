package com.eddy.authserver.dto;

public class Messages {

    public static final String CONFIRMATION_MAIL_SUBJECT = "Confirm Your Account Registration";

    public static final String CONFIRMATION_MAIL_MESSAGE = """
            <p>Dear %s,</p>

            <p>Thank you for registering with Eddy. We're excited to have you as a member of our community.</p>

            <p>To activate your account and start using our services, please confirm your email address by clicking the below:</p>

            <p><a href="%s">Confirm here</a></p>

            <p>Please note that the activation link will expire in 24 hours. If you miss the deadline, please register again to receive a new activation link.</p>

            <p>If you did not create an account with us, please disregard this email.</p>

            <p>Thank you for choosing Eddy. Let's play!</p>

            <p>Best regards,</p>            
            </p>Eddy</p>""";

}
