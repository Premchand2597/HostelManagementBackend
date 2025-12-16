package com.hostelManagement.Config;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class CookieService {

	private String refreshTokenCookieName;
	private boolean cookieHttpOnly;
	private boolean cookieSecure;
	private String cookieDomain;
	private String cookieSameSite;
	
	private Logger logger = LoggerFactory.getLogger(CookieService.class);
	
	public CookieService(
			@Value("${security.jwt.refresh-token-cookie-name}") String refreshTokenCookieName, 
			@Value("${security.jwt.cookie-http-only}") boolean cookieHttpOnly, 
			@Value("${security.jwt.cookie-secure}") boolean cookieSecure,
			@Value("${security.jwt.cookie-domain}") String cookieDomain, 
			@Value("${security.jwt.cookie-same-site}") String cookieSameSite
			) {
		super();
		this.refreshTokenCookieName = refreshTokenCookieName;
		this.cookieHttpOnly = cookieHttpOnly;
		this.cookieSecure = cookieSecure;
		this.cookieDomain = cookieDomain;
		this.cookieSameSite = cookieSameSite;
	}

	public String getRefreshTokenCookieName() {
		return refreshTokenCookieName;
	}

	public void setRefreshTokenCookieName(String refreshTokenCookieName) {
		this.refreshTokenCookieName = refreshTokenCookieName;
	}

	public boolean isCookieHttpOnly() {
		return cookieHttpOnly;
	}

	public void setCookieHttpOnly(boolean cookieHttpOnly) {
		this.cookieHttpOnly = cookieHttpOnly;
	}

	public boolean isCookieSecure() {
		return cookieSecure;
	}

	public void setCookieSecure(boolean cookieSecure) {
		this.cookieSecure = cookieSecure;
	}

	public String getCookieDomain() {
		return cookieDomain;
	}

	public void setCookieDomain(String cookieDomain) {
		this.cookieDomain = cookieDomain;
	}

	public String getCookieSameSite() {
		return cookieSameSite;
	}

	public void setCookieSameSite(String cookieSameSite) {
		this.cookieSameSite = cookieSameSite;
	}
	
	// Create method to attach cookie to response
	public void attachRefreshCookie(HttpServletResponse response, String value, int maxAge) {
		
		logger.info("Attaching cookie with name: {} and value {}", refreshTokenCookieName, value);
		
		var responseCookieBuilder = ResponseCookie.from(refreshTokenCookieName, value)
			.httpOnly(cookieHttpOnly)
			.secure(cookieSecure)
			.path("/")
			.maxAge(maxAge)
			.sameSite(cookieSameSite);
		
		if(cookieDomain!=null && !cookieDomain.isBlank()) {
			responseCookieBuilder.domain(cookieDomain);
		}
		
		ResponseCookie responseCookie = responseCookieBuilder.build();
		response.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
	}
	
	// Clear refresh cookie
	public void clearRefreshCookie(HttpServletResponse res) {
		var builder = ResponseCookie.from(refreshTokenCookieName, "")
					.maxAge(0)
					.httpOnly(cookieHttpOnly)
					.path("/")
					.sameSite(cookieSameSite)
					.secure(cookieSecure);
		
		if(cookieDomain!=null && !cookieDomain.isBlank()) {
			builder.domain(cookieDomain);
		}
		
		ResponseCookie responseCookie = builder.build();
		res.addHeader(HttpHeaders.SET_COOKIE, responseCookie.toString());
	}
	
	public void addNoStoreHeader(HttpServletResponse res) {
		res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
		res.setHeader("Pragma", "no-cache");
	}
	
    // ⭐ NEW METHOD — Extract refresh token from cookie
    public String getRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;

        for (Cookie cookie : request.getCookies()) {
            if (cookie.getName().equals(refreshTokenCookieName)) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
