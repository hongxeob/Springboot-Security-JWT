package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import org.springframework.web.filter.CorsFilter;

@Configuration // @Configuration은 설정파일을 만들기 위한 / Bean을 등록하기 위한 Annotation
public class CorsConfig {
	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true); // 내 서버가 응답을 할 때 json을 자바스크립트에서 처리할수 있게 할지를 설정하는 것.
		config.addAllowedOrigin("*");  // 모든 ip에 응답 허용.
		config.addAllowedHeader("*"); // 모든 header에 응답 허용.
		config.addAllowedMethod("*"); // 모든 get,post,put,delete,patch 요청 허용.
		source.registerCorsConfiguration("/api/**", config);
		return new CorsFilter(source);
	}
}
