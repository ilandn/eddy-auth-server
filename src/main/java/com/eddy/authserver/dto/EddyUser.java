package com.eddy.authserver.dto;

import com.eddy.data.Grade;
import com.eddy.data.user.*;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

@JsonPropertyOrder({"id", "username", "email"})
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class EddyUser extends User implements UserDetails {

    public EddyUser(String id, String username, String email, Map<String, Role> groupRoles, Date dob, Grade grade,
                    EddyScore eddyScore, Language language, Country country, Gender gender, String password,
                    Role role, boolean active, Date createdOn, boolean isOidcUser) {
        super(id, username, email, groupRoles, dob, grade, eddyScore, language, country, gender, password, role, active,
                createdOn, isOidcUser);
    }

    @Override
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        ArrayList<GrantedAuthority> grantAuth = new ArrayList<GrantedAuthority>();
        grantAuth.add(new SimpleGrantedAuthority(role.name()));
        return grantAuth;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return isActive();
    }

}
