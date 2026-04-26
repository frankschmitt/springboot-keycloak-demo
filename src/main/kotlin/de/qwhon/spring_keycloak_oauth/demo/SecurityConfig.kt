package de.qwhon.spring_keycloak_oauth.demo

import org.springframework.beans.factory.config.BeanFactoryPostProcessor
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer
import org.springframework.security.web.SecurityFilterChain

/**
 * SecurityConfig class configures security settings for the application,
 * enabling security filters and setting up OAuth2 login and logout behavior.
 */
@Configuration
@EnableWebSecurity
class SecurityConfig {
    /**
     * Configures the security filter chain for handling HTTP requests, OAuth2 login, and logout.
     *
     * @param http HttpSecurity object to define web-based security at the HTTP level
     * @return SecurityFilterChain for filtering and securing HTTP requests
     * @throws Exception in case of an error during configuration
     */
    @Bean
    @Throws(Exception::class)
    fun filterChain(http: HttpSecurity, forceAutoProxyCreatorToUseClassProxying: BeanFactoryPostProcessor): SecurityFilterChain? {
        http // Configures authorization rules for different endpoints
        http

            .authorizeHttpRequests {
                it.requestMatchers("/").permitAll() // Allows public access to the root URL
                it.requestMatchers("/menu").authenticated() // Requires authentication to access "/menu"
                it.anyRequest().authenticated()
            }
            .oauth2Login(Customizer { oauth2: OAuth2LoginConfigurer<HttpSecurity?>? ->
                oauth2!!
                    .loginPage("/oauth2/authorization/keycloak") // Sets custom login page for OAuth2 with Keycloak
                    .defaultSuccessUrl("/menu", true)
            } // Redirects to "/menu" after successful login
            ) // Configures logout settings
            .logout(Customizer { logout: LogoutConfigurer<HttpSecurity?>? ->
                logout!!
                    .logoutSuccessUrl("/") // Redirects to the root URL on successful logout
                    .invalidateHttpSession(true) // Invalidates session to clear session data
                    .clearAuthentication(true) // Clears authentication details
                    .deleteCookies("JSESSIONID")
            } // Deletes the session cookie
            )

        return http.build()
    }
}
