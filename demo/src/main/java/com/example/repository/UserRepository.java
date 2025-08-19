package com.example.repository;

import com.example.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // 기본 CRUD는 JpaRepository에서 제공

    // 사용자명으로 조회
    Optional<User> findByUsername(String username);

    // 이메일로 조회
    Optional<User> findByEmail(String email);

    // 사용자명 존재 확인
    boolean existsByUsername(String username);

    // 닉제임 존재 확인
    boolean existsByNickname(String nickname);

    // 이메일 존재 확인
    boolean existsByEmail(String email);

    // 사용자명과 이메일로 조회 (복합 조건)
    Optional<User> findByUsernameAndEmail(String username, String email);

    // 닉네임으로 조회 (LIKE 검색)
    @Query("SELECT u FROM User u WHERE u.nickname LIKE %:nickname%")
    Optional<User> findByNicknameContaining(@Param("nickname") String nickname);

    // 사용자명 또는 이메일로 조회
    @Query("SELECT u FROM User u WHERE u.username = :usernameOrEmail OR u.email = :usernameOrEmail")
    Optional<User> findByUsernameOrEmail(@Param("usernameOrEmail") String usernameOrEmail);
}
