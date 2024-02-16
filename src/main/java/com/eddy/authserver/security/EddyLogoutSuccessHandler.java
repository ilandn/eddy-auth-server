package com.eddy.authserver.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import java.io.IOException;

public class EddyLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    public EddyLogoutSuccessHandler() {
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {
        String refererUrl = request.getHeader("Referer");
        if (refererUrl != null) {
            super.setDefaultTargetUrl(refererUrl);
        }
        super.onLogoutSuccess(request, response, authentication);
    }

}
