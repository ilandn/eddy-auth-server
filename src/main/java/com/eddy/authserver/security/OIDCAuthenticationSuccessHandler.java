package com.eddy.authserver.security;

import com.eddy.authserver.services.UserService;
import com.eddy.data.exception.DBClientException;
import com.eddy.data.exception.EddyException;
import com.eddy.data.user.Role;
import com.eddy.data.user.User;
import jakarta.annotation.Resource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Date;
import java.util.function.Consumer;

@Component(value = "oidcAuthSuccessHandler")
public class OIDCAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OIDCAuthenticationSuccessHandler.class);

    private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();

    private Consumer<OAuth2User> oauth2UserHandler = (user) -> {
    };

    private Consumer<OidcUser> oidcUserHandler = (user) -> this.oauth2UserHandler.accept(user);

    @Resource(name = "userService")
    private UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        AuthenticationSuccessHandler.super.onAuthenticationSuccess(request, response, chain, authentication);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof OAuth2AuthenticationToken) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof OidcUser) {
                String email = ((OidcUser) principal).getAttributes().get("email").toString();
                createUserIfNonExist(email);
                this.oidcUserHandler.accept((OidcUser) authentication.getPrincipal());
            } else if (principal instanceof OAuth2User) {
                String email = ((OAuth2User) principal).getAttributes().get("email").toString();
                createUserIfNonExist(email);
                this.oauth2UserHandler.accept((OAuth2User) authentication.getPrincipal());
            }
        }

        this.delegate.onAuthenticationSuccess(request, response, authentication);
    }

    private void createUserIfNonExist(String email) {
        try {
            if (!userService.isUserExistByEmail(email)) {
                userService.createUser(buildNewUser(email, email));
            } else {
                log.debug("User with email already exist: " + email);
            }
        } catch (DBClientException | EddyException e) {
            throw new RuntimeException(e);
        }
    }

    private static User buildNewUser(String username, String email) {
        // Default role is parent in this scenario because advertisers should register as Eddy users only.
        User user = new User(username, email, null, null, null, "", Role.ROLE_PARENT);
        user.setActive(false);
        user.setCreatedOn(new Date());
        user.setOidcUser(true);
        return user;
    }

    public void setOAuth2UserHandler(Consumer<OAuth2User> oauth2UserHandler) {
        this.oauth2UserHandler = oauth2UserHandler;
    }

    public void setOidcUserHandler(Consumer<OidcUser> oidcUserHandler) {
        this.oidcUserHandler = oidcUserHandler;
    }

}
