package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    public static BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http.authorizeRequests()
                .antMatchers("/")
                .access("hasAnyAuthority('USER','ADMIN')")
                .antMatchers("/teacher")
                .access("hasAuthority('ADMIN')")
                .anyRequest().authenticated()
                .antMatchers("/student")
                .access("hasAuthority('USER')")
                .anyRequest().authenticated()

                .antMatchers("/both")
                .access("hasAnyAuthority('USER','ADMIN')")
                .anyRequest().authenticated()

                .and()
                .formLogin().loginPage("/login").permitAll()
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login").permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.inMemoryAuthentication().
                 withUser("teacher").password(passwordEncoder().encode("teacher123")).authorities("ADMIN")
                .and()
                .withUser("student").password(passwordEncoder().encode("student123")).authorities("USER")
                .and()
                .withUser("adminStaff").password(passwordEncoder().encode("password")).authorities("USER", "ADMIN");
    }
}