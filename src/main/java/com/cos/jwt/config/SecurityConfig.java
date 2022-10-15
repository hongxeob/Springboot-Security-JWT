package com.cos.jwt.config;

import org.aspectj.weaver.ast.And;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration // @Configuration은 설정파일을 만들기 위한 / Bean을 등록하기 위한 Annotation
@EnableWebSecurity // 활성화 , 스프링 시큐리티 필터가 스프링 필터 체인에 등록
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final CorsFilter corsFilter;
	
	//jwt의 기본적인 세팅 
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable(); // 비활성화
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않음.
		.and()
		.addFilter(corsFilter) //@CrossOrigin(인증x), 시큐리티 필터에 등록을 해야 인증있을때 사용
		.formLogin().disable() // formLogin 사용 X
////////////////위 까지가 jwt의  세팅시 기본적으로 들어가야 하는 세팅/////////////////
		.httpBasic().disable() // 기존의 Http 로그인 방식 사용 X
		.addFilter(new JwtAuthenticationFilter(authenticationManager())) // 파라미터 AuthenticationManager를 던져 줘야함. 
		.authorizeRequests() // 권한에 따른 홈페이지 접속 허용(추가기능) 
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**")
		.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**")
		.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll();
		
	}
}
