package com.chatterbox.user_service.repository;

import com.chatterbox.user_service.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByEmail(String email);
    Optional<Member> findByNickname(String nickname);
    boolean existsByEmail(String email);
    boolean existsByNickname(String nickname);

    // 활성 상태인 사용자만 조회
    Optional<Member> findByEmailAndStatus(String email, Character status);
}