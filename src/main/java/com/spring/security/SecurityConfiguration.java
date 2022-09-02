package com.spring.security;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private DataSource dataSource; 
	// we can use any external database, e.g, mysql. For that we need 
	// to configure in application.properies file
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		jdbcAuthenticationWithCustomUserTable(auth);
	}
	
	private void jdbcAuthenticationWithCustomUserTable(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication()
		.dataSource(dataSource)
		// here we are using default tables only, but we can use any other table
		.usersByUsernameQuery("select username, password, enabled from users where username = ?")
		.authoritiesByUsernameQuery("select username, authority from authorities  where username = ?");
	}
	
	// this is going to use schema.sql and data.sql in resource folder
	private void jdbcAuthenticationWithUsingDataFile(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication()
		.dataSource(dataSource);
	}
	
	private void jdbcAuthentication(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication()
		.dataSource(dataSource)
		.withDefaultSchema()
		.withUser(
				User.withUsername("user")
				.password("pass")
				.roles("USER")
		)
		.withUser(
				User.withUsername("admin")
				.password("root")
				.roles("ADMIN")
		);
	}
	
	private void inMemoryAuthentication(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
		.withUser("admin")
		.password("admin")
		.roles("ADMIN")
		.and()
		.withUser("foo")
		.password("foo")
		.roles("USER");
	}
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/admin").hasRole("ADMIN")
		.antMatchers("/user").hasAnyRole("USER", "ADMIN")
		.antMatchers("/").permitAll()
		.and().formLogin();
	}

}
