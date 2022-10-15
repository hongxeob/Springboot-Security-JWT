package com.cos.jwt.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;


//Security 설정에서 loginProcessUrl("/login")으로 걸어뒀기 때문에 /login 요청이오면 자동으로 타입이 IoC 되어있는
//loadUserByUsername 함수가 수행 => "약속"
//함수 종료시 @AuthenticationPrncipal 어노테이션이 만들어진다.

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService{
	

	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User userEntity = userRepository.findByUsername(username);
		return new PrincipalDetails(userEntity);
	}

	
}
