package com.example.demo.controller;

import com.example.demo.dto.AuthDto;
import com.example.demo.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Authentication", description = "인증 관련 API")
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private final AuthService authService;

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

    @Operation(summary = "토큰 검증", description = "JWT 토큰의 유효성을 확인합니다.")
    @GetMapping("/validate")
    public ResponseEntity<AuthDto.MessageResponse> validateToken() {
        return ResponseEntity.ok(
                AuthDto.MessageResponse.builder()
                        .message("토큰이 유효합니다.")
                        .build()
        );
    }
}