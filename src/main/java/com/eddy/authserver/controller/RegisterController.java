package com.eddy.authserver.controller;

import com.eddy.authserver.dto.Constants;
import com.eddy.authserver.dto.auth.TokenGenerator;
import com.eddy.authserver.dto.auth.UserRequest;
import com.eddy.authserver.dto.auth.VerificationToken;
import com.eddy.authserver.services.EmailConfirmationService;
import com.eddy.authserver.services.UserService;
import com.eddy.data.exception.DBClientException;
import com.eddy.data.exception.EddyException;
import jakarta.annotation.Resource;
import jakarta.ws.rs.core.MediaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;

@RestController
public class RegisterController {

    private static final Logger log = LoggerFactory.getLogger(RegisterController.class);
    @Resource(name = "emailConfirmationService")
    private EmailConfirmationService emailConfirmationService;

    @Resource(name = "userService")
    private UserService userService;

    @RequestMapping(value = "/register", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON)
    public ResponseEntity<Object> register(@RequestBody UserRequest userRequest) throws Exception {
        try {
            String uid = userService.createUser(userRequest.buildNewUser());
            log.debug("Successfully created user, user id: " + uid);
            VerificationToken token = TokenGenerator.generate(uid);
            emailConfirmationService.sendConfirmationMail(token, userRequest);
            return ResponseEntity
                    .created(ServletUriComponentsBuilder.fromCurrentRequest().path("/users/{id}").buildAndExpand(uid).toUri())
                    .body("PodAddy user created");
        } catch (EddyException e) {
            log.error("Fail to register user", e);
            return ResponseEntity.badRequest().body("Fail to register user, message: " + e.getMessage());
        }
    }

    @RequestMapping(value = "/activate/{token}", method = RequestMethod.GET)
    public ResponseEntity<Object> activate(@PathVariable("token") String token) throws Exception {
        try {
            String uid = emailConfirmationService.isTokenExpired(token);
            if (uid == null) {
                return ResponseEntity.badRequest().body("Token expired, please register again");
            }
            emailConfirmationService.activate(token);
            emailConfirmationService.deleteToken(token);

            URI location = URI.create(Constants.EDDY_SITE);
            return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
        } catch (DBClientException e) {
            log.error("Fail to register user", e);
            return ResponseEntity.badRequest().body("Fail to activate user, message: " + e.getMessage());
        }
    }

}
