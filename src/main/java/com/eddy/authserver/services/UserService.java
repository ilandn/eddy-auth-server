package com.eddy.authserver.services;

import com.eddy.authserver.db.DBUtil;
import com.eddy.authserver.db.PGPooledClient;
import com.eddy.authserver.dto.EddyUser;
import com.eddy.data.exception.DBClientException;
import com.eddy.data.exception.EddyException;
import com.eddy.data.user.Country;
import com.eddy.data.user.Role;
import com.eddy.data.user.User;
import jakarta.annotation.Resource;
import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service(value = "userService")
public class UserService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    @Resource(name = "pgPooledClient")
    private PGPooledClient pgPooledClient;

    @Resource(name = "encoder")
    private BCryptPasswordEncoder encoder;

    public boolean isUserExistByUsername(String username) throws DBClientException {
        ResultSet rs = null;
        PreparedStatement stmt = null;
        Connection conn = null;

        try {
            conn = pgPooledClient.getConnection();
            stmt = conn.prepareStatement("SELECT COUNT(*) FROM public.users WHERE LOWER(user_name)=LOWER(?)");
            stmt.setString(1, username);
            rs = stmt.executeQuery();
            if (rs.next()) {
                int count = rs.getInt("count");
                return count > 0;
            }
        } catch (Exception e) {
            throw new DBClientException("Fail to run 'isUserExistByUsername'", e);
        } finally {
            DBUtil.close(conn, rs, stmt);
        }

        return false;
    }

    public boolean isUserExistByEmail(String email) throws DBClientException {
        ResultSet rs = null;
        PreparedStatement stmt = null;
        Connection conn = null;

        try {
            conn = pgPooledClient.getConnection();
            stmt = conn.prepareStatement("SELECT COUNT(*) FROM public.users WHERE LOWER(email)=LOWER(?)");
            stmt.setString(1, email);
            rs = stmt.executeQuery();
            if (rs.next()) {
                int count = rs.getInt("count");
                return count > 0;
            }
        } catch (Exception e) {
            throw new DBClientException("Fail to run 'isUserExistByEmail'", e);
        } finally {
            DBUtil.close(conn, rs, stmt);
        }

        return false;
    }

    public String createUser(User user) throws EddyException, DBClientException {
        if (user.isOidcUser() && (isUserExistByEmail(user.getEmail()) || StringUtils.isEmpty(user.getUsername()))) {
            throw new EddyException("User with email [" + user.getEmail() + "] already exists or missing info",
                    Response.Status.CONFLICT);
        } else if (!user.isOidcUser() && (isUserExistByUsername(user.getUsername()) || StringUtils.isEmpty(user.getUsername()) ||
                StringUtils.isEmpty(user.getEmail()) || StringUtils.isEmpty(user.getPassword()))) {
            throw new EddyException("User with username [" + user.getUsername() + "] already exists or missing info",
                    Response.Status.CONFLICT);
        }
        ResultSet rs = null;
        PreparedStatement stmt = null;
        Connection conn = null;
        String id = null;

        try {
            conn = pgPooledClient.getConnection();
            stmt = conn.prepareStatement("INSERT INTO public.users " +
                    "(user_name,first_name,last_name,email,birthday,language,country,gender,password,role,active,created_on,is_oidc_user) " +
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id");
            stmt.setString(1, user.getUsername());
            stmt.setString(2, user.getFirstName());
            if (user.getFirstName() != null) {
                stmt.setString(2, user.getFirstName());
            } else {
                stmt.setNull(2, Types.OTHER);
            }
            if (user.getLastName() != null) {
                stmt.setString(3, user.getLastName());
            } else {
                stmt.setNull(3, Types.OTHER);
            }
            stmt.setString(4, user.getEmail());
            if (user.getBirthday() != null) {
                stmt.setDate(5, new Date(user.getBirthday().getTime()));
            } else {
                stmt.setNull(5, Types.OTHER);
            }
            if (user.getLanguage() != null) {
                stmt.setInt(6, user.getLanguage().getCode());
            } else {
                stmt.setNull(6, Types.OTHER);
            }
            if (user.getCountry() != null) {
                stmt.setString(7, user.getCountry().getName());
            } else {
                stmt.setNull(7, Types.OTHER);
            }
            if (user.getGender() != null) {
                stmt.setInt(8, user.getGender().getCode());
            } else {
                stmt.setNull(8, Types.OTHER);
            }
            stmt.setString(9, encoder.encode(user.getPassword()));
            if (user.getRole() != null) {
                stmt.setInt(10, user.getRole().getCode());
            } else {
                stmt.setNull(10, Types.OTHER);
            }
            stmt.setBoolean(11, user.isActive());
            stmt.setDate(12, new Date(user.getCreatedOn().getTime()));
            stmt.setBoolean(13, user.isOidcUser());
            rs = stmt.executeQuery();
            if (rs.next()) {
                id = rs.getString("id");
            }
        } catch (Exception e) {
            throw new DBClientException("Fail to create user", e);
        } finally {
            DBUtil.close(conn, rs, stmt);
        }
        return id;
    }

    public EddyUser getUserByEmail(String email) throws DBClientException {
        EddyUser user = null;
        ResultSet rs = null;
        PreparedStatement stmt = null;
        Connection conn = null;

        try {
            conn = pgPooledClient.getConnection();
            stmt = conn.prepareStatement("SELECT * FROM public.users WHERE email=?");
            stmt.setString(1, email);
            rs = stmt.executeQuery();
            if (rs.next()) {
                user = getUserFromDbResult(rs);
            }
        } catch (Exception e) {
            throw new DBClientException("Fail to get user by email", e);
        } finally {
            DBUtil.close(conn, rs, stmt);
        }
        return user;
    }

    public EddyUser getUserByUsername(String username) throws DBClientException {
        EddyUser user = null;
        ResultSet rs = null;
        PreparedStatement stmt = null;
        Connection conn = null;

        try {
            conn = pgPooledClient.getConnection();
            stmt = conn.prepareStatement("SELECT * FROM public.users WHERE user_name=?");
            stmt.setString(1, username);
            rs = stmt.executeQuery();
            if (rs.next()) {
                user = getUserFromDbResult(rs);
            }
        } catch (Exception e) {
            throw new DBClientException("Fail to get user by username", e);
        } finally {
            DBUtil.close(conn, rs, stmt);
        }
        return user;
    }

    public List<User> getAllUsers() throws DBClientException {
        List<User> users = new ArrayList<>();
        ResultSet rs = null;
        PreparedStatement stmt = null;
        Connection conn = null;

        try {
            conn = pgPooledClient.getConnection();
            stmt = conn.prepareStatement("SELECT * FROM public.users");
            rs = stmt.executeQuery();
            while (rs.next()) {
                User user = getUserFromDbResult(rs);
                users.add(user);
            }
        } catch (Exception e) {
            throw new DBClientException("Fail to get all users", e);
        } finally {
            DBUtil.close(conn, rs, stmt);
        }

        return users;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            return getUserByUsername(username);
        } catch (Exception e) {
            log.error("Fail to get user: " + username, e);
            return null;
        }
    }

    private EddyUser getUserFromDbResult(ResultSet rs) throws SQLException {
        String id = rs.getString("id");
        String userName = rs.getString("name");
        int age = rs.getInt("age");
        int grade = rs.getInt("grade");
        int eddyScore = rs.getInt("eddy_score");
        int language = rs.getInt("language");
        int country = rs.getInt("country");
        int gender = rs.getInt("gender");
        String password = rs.getString("password");
        String role = rs.getString("role");
        Array groupRolesArr = rs.getArray("group_roles");
        List<String> groupRoles = groupRolesArr != null ? Arrays.asList((String[]) groupRolesArr.getArray())
                : new ArrayList<>();
        String email = rs.getString("email");


        java.util.Date birthday = rs.getDate("birthday");
        int language = rs.getInt("language");
        String country = rs.getString("country");
        int gender = rs.getInt("gender");
        String password = rs.getString("password");
        Role role = Role.fromCode(rs.getInt("role"));
        boolean active = rs.getBoolean("active");
        java.util.Date createdOn = rs.getDate("created_on");
        boolean isOidcUser = rs.getBoolean("is_oidc_user");
        return new EddyUser(id, userName, firstName, lastName, email, birthday, Language.fromCode(language),
                Country.fromName(country), Gender.fromCode(gender), password, role, active, createdOn, isOidcUser);
    }

}
