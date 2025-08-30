package com.example.demo.service;

import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;

    // 모든 사용자 조회 (페이징)
    public Page<User> getAllUsers(Pageable pageable) {
        return userRepository.findAll(pageable);
    }

    // 사용자 ID로 조회
    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }

    // 사용자명으로 조회
    public Optional<User> getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    // 이메일로 조회
    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    // 닉네임으로 검색
    public Optional<User> searchByNickname(String nickname) {
        return userRepository.findByNicknameContaining(nickname);
    }

    // 사용자 정보 업데이트
    @Transactional
    public User updateUser(Long id, String nickname, String email) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

        // 이메일 중복 체크 (자신 제외)
        if (!user.getEmail().equals(email) && userRepository.existsByEmail(email)) {
            throw new RuntimeException("이미 존재하는 이메일입니다.");
        }

        user.setNickname(nickname);
        user.setEmail(email);

        User savedUser = userRepository.save(user);
        log.info("사용자 정보가 업데이트되었습니다. ID: {}, 닉네임: {}, 이메일: {}",
                savedUser.getId(), savedUser.getNickname(), savedUser.getEmail());

        return savedUser;
    }

    // 사용자 삭제
    @Transactional
    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new RuntimeException("사용자를 찾을 수 없습니다.");
        }
        userRepository.deleteById(id);
        log.info("사용자가 삭제되었습니다. ID: {}", id);
    }

    // 사용자 존재 확인
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    // 전체 사용자 수 조회
    public long getTotalUserCount() {
        return userRepository.count();
    }

    // 특정 조건으로 사용자 검색 (복합 조건)
    public Optional<User> findByUsernameOrEmail(String usernameOrEmail) {
        return userRepository.findByUsernameOrEmail(usernameOrEmail);
    }
}
