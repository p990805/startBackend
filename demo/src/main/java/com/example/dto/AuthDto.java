package com.example.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

public class AuthDto {

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @Schema(description = "회원가입 요청")
    public static class SignupRequest {

        @NotBlank(message = "사용자명은 필수입니다.")
        @Size(min = 3, max = 20, message = "사용자명은 3-20자 사이여야 합니다.")
        @Schema(description = "사용자명", example = "testuser")
        private String username;

        @NotBlank(message = "비밀번호는 필수입니다.")
        @Size(min = 6, max = 40, message = "비밀번호는 6-40자 사이여야 합니다.")
        @Schema(description = "비밀번호", example = "password123")
        private String password;

        @NotBlank(message = "닉네임은 필수입니다.")
        @Size(min = 2, max = 20, message = "닉네임은 2-20자 사이여야 합니다.")
        @Schema(description = "닉네임", example = "테스트유저")
        private String nickname;

        @NotBlank(message = "이메일은 필수입니다.")
        @Email(message = "올바른 이메일 형식이 아닙니다.")
        @Schema(description = "이메일", example = "test@example.com")
        private String email;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @Schema(description = "로그인 요청")
    public static class LoginRequest {

        @NotBlank(message = "사용자명은 필수입니다.")
        @Schema(description = "사용자명", example = "testuser")
        private String username;

        @NotBlank(message = "비밀번호는 필수입니다.")
        @Schema(description = "비밀번호", example = "password123")
        private String password;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @Schema(description = "JWT 토큰 응답")
    public static class JwtResponse {

        @Schema(description = "액세스 토큰")
        private String accessToken;

        @Schema(description = "토큰 타입", example = "Bearer")
        private String tokenType = "Bearer";

        @Schema(description = "사용자 ID")
        private Long userId;

        @Schema(description = "사용자명")
        private String username;

        @Schema(description = "닉네임")
        private String nickname;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @Schema(description = "API 응답")
    public static class MessageResponse {

        @Schema(description = "응답 메시지")
        private String message;
    }
}
