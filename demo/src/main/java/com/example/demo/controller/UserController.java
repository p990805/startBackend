package com.example.demo.controller;

import com.example.demo.entity.User;
import com.example.demo.jwt.JwtUtil;
import com.example.demo.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Tag(name = "User", description = "사용자 관련 API")
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
public class UserController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    @Operation(summary = "내 정보 조회", description = "현재 로그인한 사용자의 정보를 조회합니다.",
            security = {@SecurityRequirement(name = "bearer-jwt")})
    @GetMapping("/me")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<User> getCurrentUser(HttpServletRequest request) {
        String token = extractTokenFromRequest(request);
        String username = jwtUtil.getUsernameFromJwtToken(token);

        User user = userService.getUserByUsername(username)
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

        // 비밀번호는 응답에서 제거
        user.setPassword(null);

        return ResponseEntity.ok(user);
    }

    @Operation(summary = "사용자 정보 조회", description = "특정 사용자의 정보를 조회합니다.",
            security = {@SecurityRequirement(name = "bearer-jwt")})
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id)
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

        // 비밀번호는 응답에서 제거
        user.setPassword(null);

        return ResponseEntity.ok(user);
    }

    @Operation(summary = "모든 사용자 조회", description = "모든 사용자를 페이징하여 조회합니다.",
            security = {@SecurityRequirement(name = "bearer-jwt")})
    @GetMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Page<User>> getAllUsers(
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        Page<User> users = userService.getAllUsers(pageable);

        // 비밀번호는 응답에서 제거
        users.forEach(user -> user.setPassword(null));

        return ResponseEntity.ok(users);
    }

    @Operation(summary = "사용자 정보 수정", description = "현재 로그인한 사용자의 정보를 수정합니다.",
            security = {@SecurityRequirement(name = "bearer-jwt")})
    @PutMapping("/me")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<User> updateCurrentUser(
            HttpServletRequest request,
            @RequestParam String nickname,
            @RequestParam String email) {
        String token = extractTokenFromRequest(request);
        Long userId = jwtUtil.getUserIdFromJwtToken(token);

        User updatedUser = userService.updateUser(userId, nickname, email);
        updatedUser.setPassword(null);

        return ResponseEntity.ok(updatedUser);
    }

    @Operation(summary = "사용자 삭제", description = "현재 로그인한 사용자 계정을 삭제합니다.",
            security = {@SecurityRequirement(name = "bearer-jwt")})
    @DeleteMapping("/me")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> deleteCurrentUser(HttpServletRequest request) {
        String token = extractTokenFromRequest(request);
        Long userId = jwtUtil.getUserIdFromJwtToken(token);

        userService.deleteUser(userId);

        return ResponseEntity.ok("계정이 성공적으로 삭제되었습니다.");
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        throw new RuntimeException("JWT 토큰이 없습니다.");
    }
}