package com.example.demo.service;

import com.example.demo.dto.AuthDto;
import com.example.demo.entity.User;
import com.example.demo.jwt.JwtUtil;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.JwtAuthTokenFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    public AuthDto.MessageResponse signup(AuthDto.SignupRequest signupRequest) {
        // 사용자명 중복 체크
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            throw new RuntimeException("이미 존재하는 사용자명입니다.");
        }

        // 이메일 중복 체크
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new RuntimeException("이미 존재하는 이메일입니다.");
        }

        // 닉네임 중복 체크
        if (userRepository.existsByNickname(signupRequest.getNickname())) {
            throw new RuntimeException("이미 존재하는 닉네임입니다.");
        }

        // 사용자 생성
        User user = User.builder()
                .username(signupRequest.getUsername())
                .password(passwordEncoder.encode(signupRequest.getPassword()))
                .nickname(signupRequest.getNickname())
                .email(signupRequest.getEmail())
                .build();

        userRepository.save(user);
        log.info("새로운 사용자가 등록되었습니다: {}", user.getUsername());

        return AuthDto.MessageResponse.builder()
                .message("회원가입이 성공적으로 완료되었습니다.")
                .build();
    }

    public AuthDto.JwtResponse login(AuthDto.LoginRequest loginRequest) {
        try {
            // 인증 시도
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 사용자 정보 조회
            User user = userRepository.findByUsername(loginRequest.getUsername())
                    .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

            // JWT 토큰 생성
            String jwt = jwtUtil.generateJwtToken(user.getUsername(), user.getId());

            log.info("사용자 로그인 성공: {}", user.getUsername());

            return AuthDto.JwtResponse.builder()
                    .accessToken(jwt)
                    .tokenType("Bearer")
                    .userId(user.getId())
                    .username(user.getUsername())
                    .nickname(user.getNickname())
                    .build();

        } catch (BadCredentialsException e) {
            log.warn("로그인 실패 - 잘못된 인증 정보: {}", loginRequest.getUsername());
            throw new RuntimeException("잘못된 사용자명 또는 비밀번호입니다.");
        }
    }

    public void logout(String token) {
        try {
            // 토큰 유효성 검증
            if (!jwtUtil.validateJwtToken(token)) {
                throw new RuntimeException("유효하지 않은 토큰입니다.");
            }

            String username = jwtUtil.getUsernameFromJwtToken(token);

            // 토큰을 블랙리스트에 추가 (static 메소드 사용)
            JwtAuthTokenFilter.addToBlacklist(token);

            // SecurityContext 클리어
            SecurityContextHolder.clearContext();

            log.info("사용자 로그아웃 성공: {}", username);

        } catch (Exception e) {
            log.error("로그아웃 처리 중 오류 발생: {}", e.getMessage());
            throw new RuntimeException("로그아웃 처리 중 오류가 발생했습니다.");
        }
    }

    public AuthDto.JwtResponse refreshToken(String token) {
        try {
            // 토큰 유효성 검증
            if (!jwtUtil.validateJwtToken(token)) {
                throw new RuntimeException("유효하지 않은 토큰입니다.");
            }

            // 블랙리스트에 있는 토큰인지 확인
            if (JwtAuthTokenFilter.isTokenBlacklisted(token)) {
                throw new RuntimeException("로그아웃된 토큰입니다.");
            }

            String username = jwtUtil.getUsernameFromJwtToken(token);
            Long userId = jwtUtil.getUserIdFromJwtToken(token);

            // 사용자 정보 조회
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

            // 기존 토큰을 블랙리스트에 추가
            JwtAuthTokenFilter.addToBlacklist(token);

            // 새로운 토큰 생성
            String newJwt = jwtUtil.generateJwtToken(user.getUsername(), user.getId());

            log.info("토큰 갱신 성공: {}", username);

            return AuthDto.JwtResponse.builder()
                    .accessToken(newJwt)
                    .tokenType("Bearer")
                    .userId(user.getId())
                    .username(user.getUsername())
                    .nickname(user.getNickname())
                    .build();

        } catch (Exception e) {
            log.error("토큰 갱신 중 오류 발생: {}", e.getMessage());
            throw new RuntimeException("토큰 갱신 중 오류가 발생했습니다: " + e.getMessage());
        }
    }
}