package com.eddy.authserver.config;

import com.mchange.v2.c3p0.ComboPooledDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.multipart.MultipartResolver;
import org.springframework.web.multipart.support.StandardServletMultipartResolver;

import java.util.Arrays;

@Configuration
@ComponentScan(basePackages = {"com.eddy.authserver"})
public class ApplicationConfig {

    @Bean(name = "comboPooledDataSource", destroyMethod = "close")
    @Scope("prototype")
    public ComboPooledDataSource comboPooledDataSource() {
        ComboPooledDataSource comboPooledDataSource = new ComboPooledDataSource();
        comboPooledDataSource.setInitialPoolSize(2);
        comboPooledDataSource.setMinPoolSize(2);
        comboPooledDataSource.setMaxPoolSize(25);
        comboPooledDataSource.setAcquireIncrement(2);
        comboPooledDataSource.setCheckoutTimeout(30000);
        comboPooledDataSource.setStatementCacheNumDeferredCloseThreads(1);
        /*comboPooledDataSource.setTestConnectionOnCheckin(true);
        comboPooledDataSource.setTestConnectionOnCheckout(true);
        comboPooledDataSource.setIdleConnectionTestPeriod(30);
        comboPooledDataSource.setPreferredTestQuery("SELECT 1");*/

        return comboPooledDataSource;
    }

    @Bean(name = "encoder")
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder(11);
    }

    @Bean(name = "multipartResolver")
    public MultipartResolver multipartResolver() {
        return new StandardServletMultipartResolver();
    }

    public static CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
