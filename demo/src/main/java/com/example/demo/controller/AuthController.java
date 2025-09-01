package com.example.demo.controller;

import com.example.demo.dto.AuthDto;
import com.example.demo.jwt.JwtUtil;
import com.example.demo.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Authentication", description = "인증 관련 API")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;

    @Operation(summary = "회원가입", description = "새로운 사용자 계정을 생성합니다.")
    @PostMapping("/signup")
    public ResponseEntity<AuthDto.MessageResponse> registerUser(@Valid @RequestBody AuthDto.SignupRequest signupRequest) {
        try {
            AuthDto.MessageResponse response = authService.signup(signupRequest);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest()
                    .body(AuthDto.MessageResponse.builder()
                            .message(e.getMessage())
                            .build());
        }
    }

    @Operation(summary = "로그인", description = "사용자 로그인을 수행하고 JWT 토큰을 반환합니다.")
    @PostMapping("/login")
    public ResponseEntity<AuthDto.JwtResponse> authenticateUser(@Valid @RequestBody AuthDto.LoginRequest loginRequest) {
        try {
            AuthDto.JwtResponse response = authService.login(loginRequest);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest()
                    .body(AuthDto.JwtResponse.builder()
                            .accessToken("")
                            .build());
        }
    }

    @Operation(summary = "로그아웃", description = "사용자 로그아웃을 수행합니다.",
            security = {@SecurityRequirement(name = "bearer-jwt")})
    @PostMapping("/logout")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<AuthDto.MessageResponse> logout(HttpServletRequest request) {
        try {
            String token = extractTokenFromRequest(request);
            // ✅ 수정된 부분: 토큰을 직접 전달
            authService.logout(token);

            return ResponseEntity.ok(
                    AuthDto.MessageResponse.builder()
                            .message("로그아웃이 성공적으로 처리되었습니다.")
                            .build()
            );
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest()
                    .body(AuthDto.MessageResponse.builder()
                            .message("로그아웃 처리 중 오류가 발생했습니다: " + e.getMessage())
                            .build());
        }
    }

    @Operation(summary = "토큰 검증", description = "JWT 토큰의 유효성을 확인합니다.",
            security = {@SecurityRequirement(name = "bearer-jwt")})
    @GetMapping("/validate")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<AuthDto.MessageResponse> validateToken() {
        return ResponseEntity.ok(
                AuthDto.MessageResponse.builder()
                        .message("토큰이 유효합니다.")
                        .build()
        );
    }

    @Operation(summary = "토큰 갱신", description = "기존 토큰을 이용하여 새로운 토큰을 발급받습니다.",
            security = {@SecurityRequirement(name = "bearer-jwt")})
    @PostMapping("/refresh")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<AuthDto.JwtResponse> refreshToken(HttpServletRequest request) {
        try {
            String token = extractTokenFromRequest(request);
            AuthDto.JwtResponse response = authService.refreshToken(token);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest()
                    .body(AuthDto.JwtResponse.builder()
                            .accessToken("")
                            .build());
        }
    }

    /**
     * Authorization 헤더에서 JWT 토큰 추출
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        throw new RuntimeException("JWT 토큰이 없습니다.");
    }
}