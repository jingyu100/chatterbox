package com.chatterbox.user_service.repository;

import com.chatterbox.user_service.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {
}
