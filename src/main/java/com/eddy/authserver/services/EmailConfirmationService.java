package com.eddy.authserver.services;

import com.eddy.authserver.db.DBUtil;
import com.eddy.authserver.db.PGPooledClient;
import com.eddy.authserver.dto.Messages;
import com.eddy.authserver.dto.auth.UserRequest;
import com.eddy.authserver.dto.auth.VerificationToken;
import com.eddy.data.exception.DBClientException;
import com.eddy.data.exception.EddyException;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.googleapis.json.GoogleJsonError;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;
import jakarta.annotation.Resource;
import jakarta.mail.Session;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;

import static com.eddy.authserver.dto.Constants.AUTH_SERVER;
import static com.google.api.services.gmail.GmailScopes.GMAIL_SEND;
import static jakarta.mail.Message.RecipientType.TO;


@Service(value = "emailConfirmationService")
@PropertySource("classpath:email.properties")
public class EmailConfirmationService {

    private static final Logger log = LoggerFactory.getLogger(EmailConfirmationService.class);

    private static final String APP_NAME = "Eddy";
    private static final GsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();

    @Resource(name = "pgPooledClient")
    private PGPooledClient pgPooledClient;

    @Value("${from.email}")
    private String FROM_EMAIL;

    private final Gmail service;

    public EmailConfirmationService() throws Exception {
        NetHttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        service = new Gmail.Builder(httpTransport, JSON_FACTORY, getCredentials(httpTransport, JSON_FACTORY))
                .setApplicationName(APP_NAME)
                .build();
    }

    public void activate(String token) throws DBClientException {
        PreparedStatement stmt = null;
        Connection conn = null;

        String userId = getUserIdByToken(token);

        try {
            conn = pgPooledClient.getConnection();
            stmt = conn.prepareStatement("UPDATE public.users SET active = true WHERE id = '" + userId + "'");
            stmt.executeUpdate();
        } catch (Exception e) {
            throw new DBClientException("Fail activate user", e);
        } finally {
            DBUtil.close(conn, null, stmt);
        }
    }

    public void deleteToken(String token) throws DBClientException {
        PreparedStatement stmt = null;
        Connection conn = null;

        try {
            conn = pgPooledClient.getConnection();
            stmt = conn.prepareStatement("DELETE FROM public.verification_token WHERE token=?");
            stmt.setString(1, token);
            stmt.executeUpdate();
        } catch (Exception e) {
            throw new DBClientException("Fail delete token", e);
        } finally {
            DBUtil.close(conn, null, stmt);
        }
    }

    public String getUserIdByToken(String token) throws DBClientException {
        ResultSet rs = null;
        PreparedStatement stmt = null;
        Connection conn = null;

        try {
            conn = pgPooledClient.getConnection();
            stmt = conn.prepareStatement("SELECT user_id FROM public.verification_token WHERE token = '" + token + "'");
            rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("user_id");
            }
            log.error("Fail find token: " + token);
            return null;
        } catch (Exception e) {
            throw new DBClientException("Fail get userId from verification token", e);
        } finally {
            DBUtil.close(conn, rs, stmt);
        }
    }

    public String isTokenExpired(String token) throws DBClientException {
        ResultSet rs = null;
        PreparedStatement stmt = null;
        Connection conn = null;

        try {
            conn = pgPooledClient.getConnection();
            stmt = conn.prepareStatement("SELECT expiry_date,user_id FROM public.verification_token WHERE token = '" + token + "'");
            rs = stmt.executeQuery();
            if (rs.next()) {
                java.util.Date expiryDate = new java.util.Date(rs.getDate("expiry_date").getTime());
                if (!(new java.util.Date().getTime() > expiryDate.getTime())) {
                    return rs.getString("user_id");
                }
            }
            log.error("Fail find token: " + token);
            return null;
        } catch (Exception e) {
            throw new DBClientException("Fail to check if token expired", e);
        } finally {
            DBUtil.close(conn, rs, stmt);
            pgPooledClient.disconnect(conn);
        }
    }

    public void sendConfirmationMail(VerificationToken token, UserRequest userRequest) throws EddyException, DBClientException, AddressException {
        if (token == null) {
            throw new EddyException("Fail to generate token", Response.Status.INTERNAL_SERVER_ERROR);
        }
        PreparedStatement stmt = null;
        Connection conn = null;

        try {
            conn = pgPooledClient.getConnection();
            stmt = conn.prepareStatement("INSERT INTO public.verification_token " +
                    "(token,expiry_date,user_id) VALUES (?,?,?)");
            stmt.setString(1, token.getToken());
            stmt.setDate(2, new Date(token.getExpiryDate().getTime()));
            stmt.setString(3, token.getUserId());
            stmt.executeUpdate();
        } catch (Exception e) {
            throw new DBClientException("Fail to persist verification token", e);
        } finally {
            DBUtil.close(conn, null, stmt);
        }

        String activateUri = AUTH_SERVER + "/activate/" + token.getToken();
        String msg = String.format(Messages.CONFIRMATION_MAIL_MESSAGE, userRequest.getUsername(), activateUri);
        sendMail(Messages.CONFIRMATION_MAIL_SUBJECT, msg, new InternetAddress(userRequest.getEmail()));
    }

    private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT, GsonFactory jsonFactory) throws IOException {
        // Load client secrets
        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(jsonFactory,
                new InputStreamReader(Objects.requireNonNull(EmailConfirmationService.class.getResourceAsStream("/google/client_secret.json"))));

        // Build flow and trigger user authorization request
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT, jsonFactory, clientSecrets, Set.of(GMAIL_SEND))
                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File("tokens")))
                .setAccessType("offline")
                .build();

        LocalServerReceiver receiver = new LocalServerReceiver.Builder().setHost("iam.eddygames.net").setPort(8888).build();
        return new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");
    }

    private void sendMail(String subject, String message, InternetAddress recipient) throws EddyException {
        try {
            Properties props = new Properties();
            Session session = Session.getDefaultInstance(props, null);
            MimeMessage email = new MimeMessage(session);
            email.setFrom(new InternetAddress(FROM_EMAIL));
            email.addRecipient(TO, recipient);
            email.setSubject(subject);
            email.setContent(message, "text/html");

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            email.writeTo(buffer);
            byte[] rawMessageBytes = buffer.toByteArray();
            String encodedEmail = Base64.encodeBase64URLSafeString(rawMessageBytes);
            Message msg = new Message();
            msg.setRaw(encodedEmail);

            try {
                service.users().messages().send("me", msg).execute();
            } catch (GoogleJsonResponseException e) {
                GoogleJsonError error = e.getDetails();
                if (error.getCode() == 403) {
                    log.error("Unable to send message: " + e.getDetails(), e);
                } else {
                    throw e;
                }
            }
        } catch (Exception e) {
            log.error("Fail to send email", e);
            throw new EddyException(e.getMessage(), Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

}
