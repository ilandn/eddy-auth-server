package com.eddy.authserver.dto.auth;

import com.eddy.data.Grade;
import com.eddy.data.user.Gender;
import com.eddy.data.user.Role;
import com.eddy.data.user.User;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;

public class UserRequest {

    @JsonProperty("userName")
    protected String username;

    @JsonProperty("email")
    protected String email;

    @JsonProperty("dateOfBirth")
    protected Date dob;

    @JsonProperty("grade")
    protected Grade grade;

    @JsonProperty("gender")
    protected Gender gender;

    @JsonProperty("password")
    protected String password;

    @JsonProperty("isParent")
    protected boolean isParent;

    public UserRequest() {
    }

    public UserRequest(String username, String email, Date dob, Grade grade, Gender gender, String password,
                       boolean isParent) {
        this.username = username;
        this.email = email;
        this.dob = dob;
        this.grade = grade;
        this.gender = gender;
        this.password = password;
        this.isParent = isParent;
    }

    public User buildNewUser() {
        Role role = isParent ? Role.ROLE_PARENT : Role.ROLE_CHILD;
        User user = new User(username, email, dob, grade, gender, password, role);
        user.setActive(false);
        user.setCreatedOn(new Date());
        user.setOidcUser(false);
        user.setRole(role);
        return user;
    }

    public User build() {
        Role role = isAdvertiser ? Role.ADVERTISER : Role.PODCASTER;
        return new User(username, email, password, role);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}
