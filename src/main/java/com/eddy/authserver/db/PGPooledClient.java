package com.eddy.authserver.db;

import com.google.common.base.Strings;
import com.mchange.v2.c3p0.ComboPooledDataSource;
import com.mchange.v2.c3p0.DataSources;
import com.podaddy.authserver.dto.Constants;
import com.podaddy.data.common.exception.DBClientException;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.annotation.Resource;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.beans.PropertyVetoException;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * Created by iland.
 */
@Component(value = "pgPooledClient")
public class PGPooledClient {

    private static final Logger log = LoggerFactory.getLogger(PGPooledClient.class);

    private static final int DEFAULT_PORT = 5432;

    private String dbName = Constants.DB_NAME;
    private String dbHost = Constants.DEFAULT_DB_HOST;
    private String dbUser = Constants.DB_LOCAL_USER;
    private String dbPassword = Constants.DB_LOCAL_PASSWORD;
    private int dbPort = Constants.DB_PORT;

    @Resource
    private ApplicationContext applicationContext;
    private ComboPooledDataSource comboPooledDataSource;

    public void disconnect(Connection connection) {
        try {
            if (connection != null && !connection.isClosed()) {
                //restore to default
                connection.setAutoCommit(true);
                connection.close();
                log.debug("Disconnected from podaddy database");
            }
        } catch (SQLException e) {
            log.error("Fail to disconnect from database: ", e);
        }
    }

    @PostConstruct
    public void init() throws PropertyVetoException, SQLException {
        dbHost = StringUtils.isEmpty(getProperty(Constants.DB_HOST_VAR)) ? dbHost : getProperty(Constants.DB_HOST_VAR);
        dbUser = StringUtils.isEmpty(getProperty(Constants.DB_USER_VAR)) ? dbUser : getProperty(Constants.DB_USER_VAR);
        dbPassword = StringUtils.isEmpty(getProperty(Constants.DB_PASS_VAR)) ? dbPassword : getProperty(Constants.DB_PASS_VAR);
        comboPooledDataSource = initPooledDataSource(dbHost, dbUser, dbPassword);
    }

    private String getProperty(String key) {
        return StringUtils.isNotEmpty(System.getenv(key)) ? System.getenv(key) : System.getProperty(key);
    }

    private ComboPooledDataSource initPooledDataSource(String host, String user, String password) throws PropertyVetoException {
        ComboPooledDataSource comboPooledDataSource = applicationContext.getBean(ComboPooledDataSource.class);
        comboPooledDataSource.setDriverClass(Constants.JDBC_DRIVER_CLASS);
        comboPooledDataSource.setJdbcUrl("jdbc:postgresql://" + host + ":" + dbPort + "/" + dbName);
        if (!Strings.isNullOrEmpty(user) && !Strings.isNullOrEmpty(password)) {
            comboPooledDataSource.setPassword(password);
            comboPooledDataSource.setUser(user);
        }
        return comboPooledDataSource;
    }

    public Connection getConnection() throws DBClientException {
        try {
            if (comboPooledDataSource == null) {
                log.error("Database not found in pooled connections");
                throw new DBClientException("Database not found in pooled connections");
            } else {
                return comboPooledDataSource.getConnection();
            }
        } catch (SQLException e) {
            log.error("Can't connect to pooled database connection: " + e.getMessage(), e);
            throw new DBClientException(e);
        }
    }

    @PreDestroy
    public void killConnectionPools() {
        log.info("Killing SQL connection pools");
        try {
            DataSources.destroy(comboPooledDataSource);
        } catch (SQLException e) {
            log.error("Fail while closing DB connections", e);
        }
        log.info("SQL connection pools destroyed");
    }

}