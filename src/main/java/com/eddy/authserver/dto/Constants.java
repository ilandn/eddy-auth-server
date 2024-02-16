package com.eddy.authserver.dto;

public class Constants {

    public static final String LOGIN_PATH = "/login";
    public static final String LOGOUT_PATH = "/logout";
    public static final String AUTHORITIES_CLAIM = "authorities";

    /* URIs */
    public static final String EDDY_SITE = "https://eddy.io/";
    public static final String AUTH_SERVER = "https://iam.eddy.io:9000";
    public static final String API_SERVER = "https://api.eddy.io";
    public static final String DEFAULT_DB_HOST = "podaddy-db.cvhp8o5wnnq4.us-east-1.rds.amazonaws.com";
//    public static final String DEFAULT_DB_HOST = "localhost";

    /* PoDaddy DB */
    public static final String DB_NAME = "eddy";
    public static final String DB_HOST_VAR = "PDD_DB_HOST";
    public static final String DB_USER_VAR = "PDD_DB_USER";
    public static final String DB_PASS_VAR = "PDD_DB_PASS";
    public static final String DB_LOCAL_USER = "postgres";
    public static final String DB_LOCAL_PASSWORD = "pdd123456";
    public static final int DB_PORT = 5432;
    public static final String JDBC_DRIVER_CLASS = "org.postgresql.Driver";

}
