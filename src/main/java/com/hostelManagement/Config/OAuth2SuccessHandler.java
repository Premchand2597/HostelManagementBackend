package com.hostelManagement.Config;

import java.io.IOException;
import java.time.LocalDateTime;

import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.hostelManagement.DTO.RefreshTokenDto;
import com.hostelManagement.Entity.LoginEntity;
import com.hostelManagement.Entity.RefreshTokenEntity;
import com.hostelManagement.Repo.LoginRepo;
import com.hostelManagement.Repo.RefreshTokenRepo;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(OAuth2SuccessHandler.class);

    @Autowired
    private LoginRepo repo;

    @Autowired
    private RefreshTokenRepo refreshToken_Repo;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CookieService cookieService;
    
    @Value("${app.auth.frontend.success-redirect}")
    private String frontEndSuccessUrl;
    
    @Autowired
    private ModelMapper mapper;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

        String provider = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();

        LoginEntity user = null;

        switch (provider) {
            case "google":
				user = extractGoogleUser(oauth2User);
                break;

            case "github":
				user = extractGithubUser(oauth2User);
                break;

            default:
                throw new IllegalStateException("Unknown provider: " + provider);
        }
        
        System.out.println("user == "+user);

        // Create refresh token
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());
        
        System.out.println("refreshToken == "+refreshToken);

        RefreshTokenDto savedRefreshTokenDto = new RefreshTokenDto(
        		refreshToken,
                LocalDateTime.now(),
                LocalDateTime.now().plusSeconds(86400),
                user.getEmail(),
                false,
                null
        );
        RefreshTokenEntity dtoToEntity = mapper.map(savedRefreshTokenDto, RefreshTokenEntity.class);
        refreshToken_Repo.save(dtoToEntity);
        
        System.out.println("dtoToEntity == "+dtoToEntity);

        // Attach refresh token in cookie
        cookieService.attachRefreshCookie(response, refreshToken, 86400);

        // return success and redirect to success page
        response.sendRedirect(frontEndSuccessUrl);
    }


    // ---------------- GOOGLE ---------------- 
    private LoginEntity extractGoogleUser(OAuth2User oauth2User) {

        String email = oauth2User.getAttribute("email");

        return repo.findByEmail(email)
            .map(existingUser -> {
                logger.info("Google user exists, logging in");
                return existingUser;
            })
            .orElseGet(() -> {
                logger.info("Creating new Google user");

                LoginEntity user = new LoginEntity();
                user.setEmail(email);
                user.setName(oauth2User.getAttribute("name"));
                user.setProvider("GOOGLE");
                user.setRole("ROLE_User");

                return repo.save(user);
            });
    }

    // ---------------- GITHUB ----------------
    private LoginEntity extractGithubUser(OAuth2User oauth2User) {

        String email = oauth2User.getAttribute("email");
        if (email == null) {
            email = oauth2User.getAttribute("login") + "@github.com";
        }

        final String finalEmail = email;

        return repo.findByEmail(finalEmail)
            .map(existingUser -> {
                logger.info("GitHub user exists, logging in");
                return existingUser;
            })
            .orElseGet(() -> {
                logger.info("Creating new GitHub user");

                LoginEntity user = new LoginEntity();
                user.setEmail(finalEmail);
                user.setName(
                    oauth2User.getAttribute("name") != null
                        ? oauth2User.getAttribute("name")
                        : oauth2User.getAttribute("login")
                );
                user.setProvider("GITHUB");
                user.setRole("ROLE_User");

                return repo.save(user);
            });
    }
} 