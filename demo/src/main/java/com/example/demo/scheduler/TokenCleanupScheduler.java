package com.example.demo.scheduler;

import com.example.demo.jwt.JwtUtil;
import com.example.demo.security.JwtAuthTokenFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenCleanupScheduler {

    private final JwtUtil jwtUtil;

    /**
     * 매일 새벽 2시에 만료된 토큰들을 정리
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void cleanupExpiredTokens() {
        log.info("만료된 토큰 정리 작업 시작");
        JwtAuthTokenFilter.cleanupExpiredTokens(jwtUtil);
        log.info("만료된 토큰 정리 작업 완료");
    }

    /**
     * 1시간마다 만료된 토큰들을 정리 (선택사항)
     */
    @Scheduled(fixedRate = 3600000) // 1시간 = 3600000ms
    public void cleanupExpiredTokensHourly() {
        JwtAuthTokenFilter.cleanupExpiredTokens(jwtUtil);
    }
}