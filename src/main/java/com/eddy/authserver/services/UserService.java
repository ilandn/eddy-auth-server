package com.eddy.authserver.services;

import com.eddy.authserver.db.DBUtil;
import com.eddy.authserver.db.PGPooledClient;
import com.eddy.authserver.dto.EddyUser;
import com.eddy.data.Grade;
import com.eddy.data.exception.DBClientException;
import com.eddy.data.exception.EddyException;
import com.eddy.data.user.*;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
                    "(name,email,dob,grade,language,country,gender,password,role,group_roles,active,created_on,is_oidc_user) " +
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id");
            stmt.setString(1, user.getUsername());
            stmt.setString(2, user.getEmail());
            if (user.getDOB() != null) {
                stmt.setDate(3, new java.sql.Date(user.getDOB().getTime()));
            } else {
                stmt.setNull(3, Types.OTHER);
            }
            if (user.getRole().equals(Role.ROLE_PARENT) || user.getRole().equals(Role.ROLE_ADMIN)) {
                stmt.setNull(4, java.sql.Types.INTEGER);
            } else {
                stmt.setInt(4, user.getGrade().getId());
            }
            stmt.setInt(5, user.getLanguage().getId());
            stmt.setInt(6, user.getCountry().getId());
            stmt.setInt(7, user.getGender().getId());
            stmt.setString(8, encoder.encode(user.getPassword()));
            stmt.setString(9, user.getRole().name());
            if (user.getGroupsWithRoles() != null && !user.getGroupsWithRoles().isEmpty()) {
                try {
                    Array groupRolesArray = conn.createArrayOf("VARCHAR",
                            groupRolesArr(user.getGroupsWithRoles()));
                    stmt.setArray(10, groupRolesArray);
                } catch (Exception e) {
                    log.error("fail to add group roles");
                    stmt.setNull(10, Types.OTHER);
                }
            }
            stmt.setBoolean(11, user.isActive());
            stmt.setDate(12, new java.sql.Date(new java.util.Date().getTime()));
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
        String email = rs.getString("email");
        String name = rs.getString("name");
        java.util.Date dob = null;
        java.sql.Date dobDate = rs.getDate("dob");
        if (dobDate != null) {
            dob = new java.util.Date(dobDate.getTime());
        }
        int grade = rs.getInt("grade");
        int eddy_score = rs.getInt("eddy_score");
        int language = rs.getInt("language");
        int country = rs.getInt("country");
        int gender = rs.getInt("gender");
        String password = rs.getString("password");
        Role role = Role.valueOf(rs.getString("role"));

        Map<String, Role> groupRoles = new HashMap<>();
        String[][] groupRolesArr = (String[][]) rs.getArray("group_roles").getArray();
        for (String[] gr : groupRolesArr) {
            String groupId = gr[0];
            Role grole = Role.valueOf(gr[1]);
            groupRoles.put(groupId, grole);
        }
        boolean active = rs.getBoolean("active");
        java.util.Date createdOn = null;
        java.sql.Date createdOnDate = rs.getDate("created_on");
        if (createdOnDate != null) {
            createdOn = new java.util.Date(createdOnDate.getTime());
        }
        boolean isOidcUser = rs.getBoolean("is_oidc_user");

        return new EddyUser(id, name, email, groupRoles, dob, Grade.fromId(grade), new EddyScore(eddy_score),
                Language.fromId(language), Country.fromId(country), Gender.fromId(gender), password, role,
                active, createdOn, isOidcUser);
    }

    private String[][] groupRolesArr(Map<String, Role> grMap) {
        if (grMap == null || grMap.isEmpty()) {
            return null;
        }
        String[][] podArr = new String[grMap.size()][];

        int num = 0;
        for (Map.Entry<String, Role> grEntry : grMap.entrySet()) {
            String grId = grEntry.getKey();
            Role role = grEntry.getValue();
            podArr[num] = new String[]{grId, role.name()};
            num++;
        }

        return podArr;
    }

}
