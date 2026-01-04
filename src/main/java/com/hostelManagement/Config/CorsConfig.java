package com.hostelManagement.Config;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfig {
	@Bean
	CorsConfigurationSource corsConfigurationSource(@Value("${app.cors.front-end-urls}") String corsUrls) {
		
		String[] urls = corsUrls.trim().split(",");
		
//		Arrays.stream(urls).forEach(System.out::print);
		
		var config = new CorsConfiguration();
		config.setAllowedOrigins(List.of(urls));
		config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		config.setAllowedHeaders(List.of("*"));
		config.setAllowCredentials(true);
		
		var source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		
		return source;
	}
}
