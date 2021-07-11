package io.staticvoid.springsecurityjdbc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // this automagically configures Spring Security to point towards the embedded h2 database
        // withDefaultSchema - gives us out of the box users and authorities tables

        // on startup the h2 database is populated with stuff below:
        // at runtime this datasource is used to verify user information

//        auth.jdbcAuthentication()
//                .dataSource(dataSource)
//                .withDefaultSchema()
//                .withUser(
//                        User.withUsername("user")
//                        .password("pass")
//                        .roles("USER")
//                )
//                .withUser(
//                        User.withUsername("admin")
//                        .password("pass")
//                        .roles("ADMIN")
//                );

        // database and schema and users populated should all be present
        // and here just point to the dataSource to connect to for authentication
//        auth.jdbcAuthentication()
//                .dataSource(dataSource);

        // you can tell spring security if you have a different schema so that Spring Security knows
        // what tables to query and how to query:

        // these two methods allow you to pass queries

        // just point spring secuity to the datasource and tell it what queries to run
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .usersByUsernameQuery("select username, password, enabled "
                + "from users "
                        + "where username = ?")
                .authoritiesByUsernameQuery("select username, authority "
                    + "from authorities "
                        + "where username = ?");


    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("ADMIN", "USER")
                .antMatchers("/").permitAll()
                .and().formLogin();

    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        // NEVER in production - basically amounts to clear text password storage
        // should use hashing and password encoding - BCrypt
        return NoOpPasswordEncoder.getInstance();
    }
}
