package com.chatterbox.user_service.repository;

import com.chatterbox.user_service.entity.Member;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class MemberRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private MemberRepository memberRepository;

    private Member testMember;

    @BeforeEach
    void setUp() {
        testMember = Member.builder()
                .email("test@example.com")
                .password("encodedPassword")
                .nickname("testuser")
                .profileImageUrl("profile.jpg")
                .status('A')
                .build();
    }

    @Test
    @DisplayName("이메일로 멤버 조회 성공 테스트")
    void findByEmailSuccess() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        Optional<Member> result = memberRepository.findByEmail("test@example.com");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo("test@example.com");
        assertThat(result.get().getNickname()).isEqualTo("testuser");
        assertThat(result.get().getStatus()).isEqualTo('A');
    }

    @Test
    @DisplayName("존재하지 않는 이메일로 멤버 조회 실패 테스트")
    void findByEmailNotFound() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        Optional<Member> result = memberRepository.findByEmail("nonexistent@example.com");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("대소문자 구분하여 이메일 조회 테스트")
    void findByEmailCaseSensitive() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        Optional<Member> result = memberRepository.findByEmail("TEST@EXAMPLE.COM");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("닉네임으로 멤버 조회 성공 테스트")
    void findByNicknamSuccess() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        Optional<Member> result = memberRepository.findByNickname("testuser");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getNickname()).isEqualTo("testuser");
        assertThat(result.get().getEmail()).isEqualTo("test@example.com");
    }

    @Test
    @DisplayName("존재하지 않는 닉네임으로 멤버 조회 실패 테스트")
    void findByNicknameNotFound() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        Optional<Member> result = memberRepository.findByNickname("nonexistent");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("이메일 존재 여부 확인 - 존재하는 경우")
    void existsByEmailExistsReturnsTrue() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        boolean exists = memberRepository.existsByEmail("test@example.com");

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    @DisplayName("이메일 존재 여부 확인 - 존재하지 않는 경우")
    void existsByEmailNotExistsReturnsFalse() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        boolean exists = memberRepository.existsByEmail("nonexistent@example.com");

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    @DisplayName("닉네임 존재 여부 확인 - 존재하는 경우")
    void existsByNicknameExistsReturnsTrue() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        boolean exists = memberRepository.existsByNickname("testuser");

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    @DisplayName("닉네임 존재 여부 확인 - 존재하지 않는 경우")
    void existsByNicknameNotExistsReturnsFalse() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        boolean exists = memberRepository.existsByNickname("nonexistent");

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    @DisplayName("이메일과 상태로 멤버 조회 성공 테스트")
    void findByEmailAndStatusSuccess() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        Optional<Member> result = memberRepository.findByEmailAndStatus("test@example.com", 'A');

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo("test@example.com");
        assertThat(result.get().getStatus()).isEqualTo('A');
    }

    @Test
    @DisplayName("이메일과 상태로 멤버 조회 실패 - 잘못된 상태")
    void findByEmailAndStatusWrongStatusNotFound() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        Optional<Member> result = memberRepository.findByEmailAndStatus("test@example.com", 'I');

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("이메일과 상태로 멤버 조회 실패 - 잘못된 이메일")
    void findByEmailAndStatusWrongEmailNotFound() {
        // Given
        entityManager.persistAndFlush(testMember);

        // When
        Optional<Member> result = memberRepository.findByEmailAndStatus("wrong@example.com", 'A');

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("멤버 저장 후 자동 생성 필드 확인")
    void saveAutoGeneratedFields() {
        // When
        Member savedMember = memberRepository.save(testMember);

        // Then
        assertThat(savedMember.getId()).isNotNull();
        assertThat(savedMember.getCreatedAt()).isNotNull();
        assertThat(savedMember.getCreatedAt()).isBeforeOrEqualTo(LocalDateTime.now());
    }

    @Test
    @DisplayName("멤버 저장 후 조회 확인")
    void saveThenFind() {
        // Given
        Member savedMember = memberRepository.save(testMember);

        // When
        Optional<Member> foundMember = memberRepository.findById(savedMember.getId());

        // Then
        assertThat(foundMember).isPresent();
        assertThat(foundMember.get().getEmail()).isEqualTo("test@example.com");
        assertThat(foundMember.get().getNickname()).isEqualTo("testuser");
        assertThat(foundMember.get().getPassword()).isEqualTo("encodedPassword");
        assertThat(foundMember.get().getProfileImageUrl()).isEqualTo("profile.jpg");
        assertThat(foundMember.get().getStatus()).isEqualTo('A');
    }

    @Test
    @DisplayName("여러 멤버 저장 후 이메일 중복 확인")
    void saveMultipleMembersCheckDuplicateEmail() {
        // Given
        Member member1 = Member.builder()
                .email("user1@example.com")
                .password("password1")
                .nickname("user1")
                .profileImageUrl("profile1.jpg")
                .status('A')
                .build();

        Member member2 = Member.builder()
                .email("user2@example.com")
                .password("password2")
                .nickname("user2")
                .profileImageUrl("profile2.jpg")
                .status('A')
                .build();

        memberRepository.save(member1);
        memberRepository.save(member2);

        // When & Then
        assertThat(memberRepository.existsByEmail("user1@example.com")).isTrue();
        assertThat(memberRepository.existsByEmail("user2@example.com")).isTrue();
        assertThat(memberRepository.existsByEmail("user3@example.com")).isFalse();
    }

    @Test
    @DisplayName("여러 멤버 저장 후 닉네임 중복 확인")
    void saveMultipleMembersCheckDuplicateNickname() {
        // Given
        Member member1 = Member.builder()
                .email("user1@example.com")
                .password("password1")
                .nickname("nickname1")
                .profileImageUrl("profile1.jpg")
                .status('A')
                .build();

        Member member2 = Member.builder()
                .email("user2@example.com")
                .password("password2")
                .nickname("nickname2")
                .profileImageUrl("profile2.jpg")
                .status('A')
                .build();

        memberRepository.save(member1);
        memberRepository.save(member2);

        // When & Then
        assertThat(memberRepository.existsByNickname("nickname1")).isTrue();
        assertThat(memberRepository.existsByNickname("nickname2")).isTrue();
        assertThat(memberRepository.existsByNickname("nickname3")).isFalse();
    }

    @Test
    @DisplayName("비활성화된 멤버 조회 테스트")
    void findInactiveMember() {
        // Given
        Member inactiveMember = Member.builder()
                .email("inactive@example.com")
                .password("password")
                .nickname("inactive")
                .profileImageUrl("profile.jpg")
                .status('I') // 비활성화
                .build();

        entityManager.persistAndFlush(inactiveMember);

        // When
        Optional<Member> activeResult = memberRepository.findByEmailAndStatus("inactive@example.com", 'A');
        Optional<Member> inactiveResult = memberRepository.findByEmailAndStatus("inactive@example.com", 'I');

        // Then
        assertThat(activeResult).isEmpty();
        assertThat(inactiveResult).isPresent();
        assertThat(inactiveResult.get().getStatus()).isEqualTo('I');
    }

    @Test
    @DisplayName("null 값 처리 테스트")
    void handleNullValues() {
        // When & Then
        assertThat(memberRepository.findByEmail(null)).isEmpty();
        assertThat(memberRepository.findByNickname(null)).isEmpty();
        assertThat(memberRepository.existsByEmail(null)).isFalse();
        assertThat(memberRepository.existsByNickname(null)).isFalse();
    }

    @Test
    @DisplayName("빈 문자열 처리 테스트")
    void handleEmptyString() {
        // When & Then
        assertThat(memberRepository.findByEmail("")).isEmpty();
        assertThat(memberRepository.findByNickname("")).isEmpty();
        assertThat(memberRepository.existsByEmail("")).isFalse();
        assertThat(memberRepository.existsByNickname("")).isFalse();
    }

    @Test
    @DisplayName("삭제된 멤버 조회 테스트")
    void findDeletedMember() {
        // Given
        Member deletedMember = Member.builder()
                .email("deleted@example.com")
                .password("password")
                .nickname("deleted")
                .profileImageUrl("profile.jpg")
                .status('A')
                .deletedAt(LocalDateTime.now())
                .build();

        entityManager.persistAndFlush(deletedMember);

        // When
        Optional<Member> result = memberRepository.findByEmail("deleted@example.com");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getDeletedAt()).isNotNull();
    }
}