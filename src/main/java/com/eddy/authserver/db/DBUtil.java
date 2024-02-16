package com.eddy.authserver.db;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class DBUtil {

    private static final Logger log = LoggerFactory.getLogger(DBUtil.class);

    public static void close(Connection conn, ResultSet resultSet, PreparedStatement statement) {
        try {
            if (conn != null && !conn.isClosed()) {
                conn.setAutoCommit(true);
                conn.close();
            }
            if (resultSet != null) {
                resultSet.close();
            }
            if (statement != null) {
                statement.close();
            }
        } catch (SQLException e) {
            log.error("Error closing result set or statement" + e.getMessage());
        }
    }

    public static void executeTransaction(Connection conn, String... sql) throws SQLException {
        try {
            conn.setAutoCommit(false);

            for (String s : sql) {
                PreparedStatement preparedStatement = conn.prepareStatement(s);
                preparedStatement.execute();
            }

            conn.commit();
        } catch (SQLException e) {
            log.error("Fail to execute transaction.", e);
            conn.rollback();
        } finally {
            try {
                conn.setAutoCommit(true);
            } catch (SQLException e) {
                log.error("Fail to set auto commit to true.", e);
            }
        }
    }

}
