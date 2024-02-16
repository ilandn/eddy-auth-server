package com.eddy.authserver.config;

import com.eddy.authserver.security.EddyLogoutSuccessHandler;
import com.eddy.authserver.security.OIDCAuthenticationSuccessHandler;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static com.eddy.authserver.dto.Constants.LOGIN_PATH;
import static com.eddy.authserver.dto.Constants.LOGOUT_PATH;

@Configuration
@EnableWebMvc
@EnableWebSecurity
@PropertySource("classpath:application.properties")
@ComponentScan(basePackages = {"com.eddy.authserver"})
public class SecurityConfig implements WebMvcConfigurer {

    private static final String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.";
    private static final List<String> clients = Arrays.asList("google", "facebook");

    @Autowired
    private Environment env;

    @Resource(name = "oidcAuthSuccessHandler")
    private OIDCAuthenticationSuccessHandler oidcAuthSuccessHandler;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(ApplicationConfig.corsConfigurationSource()))
                .headers((headers) -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .authorizeHttpRequests(authorizeRequests -> {
                    authorizeRequests.requestMatchers(AntPathRequestMatcher.antMatcher(LOGIN_PATH)).permitAll();
                    authorizeRequests.requestMatchers(AntPathRequestMatcher.antMatcher(LOGOUT_PATH)).permitAll();
                    authorizeRequests.requestMatchers(AntPathRequestMatcher.antMatcher("/register")).permitAll();
                    authorizeRequests.requestMatchers(AntPathRequestMatcher.antMatcher("/activate/*")).permitAll();
                    authorizeRequests.anyRequest().authenticated();
                })
                .formLogin(formLogin -> formLogin
                        .loginPage(LOGIN_PATH)
                        .permitAll())
                .logout((logout) -> logout
                        .logoutUrl(LOGOUT_PATH)
                        .logoutSuccessHandler(new EddyLogoutSuccessHandler())
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll())
                .oauth2Login(oauth2Login -> oauth2Login
                        .loginPage(LOGIN_PATH)
                        .successHandler(oidcAuthSuccessHandler));
        return http.build();
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/favicon.ico")
                .addResourceLocations("classpath:/static/");
    }

    @Override
    public void configureDefaultServletHandling(DefaultServletHandlerConfigurer servletConfig) {
        servletConfig.enable();
    }

    @Bean
    public ViewResolver viewResolver() {
        InternalResourceViewResolver bean = new InternalResourceViewResolver();
        bean.setPrefix("/WEB-INF/views/");
        bean.setSuffix(".html");

        return bean;
    }

    ///// Oauth2 authentication setting /////

    @Bean(name = "clientRegistrationRepository")
    public ClientRegistrationRepository clientRegistrationRepository() {
        List<ClientRegistration> registrations = clients.stream()
                .map(c -> getRegistration(c))
                .filter(registration -> registration != null)
                .collect(Collectors.toList());

        return new InMemoryClientRegistrationRepository(registrations);
    }

    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }

    @Bean(name = "authorizedClientService")
    @DependsOn("clientRegistrationRepository")
    public OAuth2AuthorizedClientService authorizedClientService(
            @Qualifier("clientRegistrationRepository") ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }

    private ClientRegistration getRegistration(String client) {
        String clientId = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-id");

        if (clientId == null) {
            return null;
        }

        String clientSecret = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-secret");

        if (client.equals("google")) {
            return CommonOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .build();
        }
        if (client.equals("facebook")) {
            return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .build();
        }
        return null;
    }

}
