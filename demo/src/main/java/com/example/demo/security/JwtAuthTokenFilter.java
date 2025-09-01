package com.example.demo.security;

import com.example.demo.jwt.JwtUtil;
import com.example.demo.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthTokenFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsServiceImpl userDetailsService;
    private final ApplicationContext applicationContext;

    // 토큰 블랙리스트를 필터에서 직접 관리 (순환참조 해결)
    private static final Set<String> tokenBlacklist = new HashSet<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = parseJwt(request);

            if (jwt != null && jwtUtil.validateJwtToken(jwt)) {
                // 토큰이 블랙리스트에 있는지 확인
                if (tokenBlacklist.contains(jwt)) {
                    log.warn("블랙리스트에 있는 토큰으로 접근 시도");
                    response.setContentType("application/json");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"error\": \"Token has been invalidated\"}");
                    return;
                }

                String username = jwtUtil.getUsernameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            log.error("사용자 인증을 설정할 수 없습니다: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        return null;
    }

    /**
     * 토큰을 블랙리스트에 추가 (static 메소드로 외부에서 접근 가능)
     */
    public static void addToBlacklist(String token) {
        tokenBlacklist.add(token);
        log.info("토큰이 블랙리스트에 추가되었습니다");
    }

    /**
     * 토큰이 블랙리스트에 있는지 확인
     */
    public static boolean isTokenBlacklisted(String token) {
        return tokenBlacklist.contains(token);
    }

    /**
     * 만료된 토큰들을 블랙리스트에서 제거
     */
    public static void cleanupExpiredTokens(JwtUtil jwtUtil) {
        tokenBlacklist.removeIf(token -> {
            try {
                return !jwtUtil.validateJwtToken(token);
            } catch (Exception e) {
                return true; // 예외 발생 시 제거
            }
        });
        log.info("만료된 토큰 정리 완료. 현재 블랙리스트 크기: {}", tokenBlacklist.size());
    }
}