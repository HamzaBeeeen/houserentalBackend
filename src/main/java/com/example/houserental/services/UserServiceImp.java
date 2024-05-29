package com.example.houserental.services;

import com.example.houserental.dao.entities.User;
import com.example.houserental.dao.repositories.UserRepository;
import com.example.houserental.dto.AuthenticationRequest;
import com.example.houserental.dto.AuthenticationResponse;
import com.example.houserental.dto.SignUpDTO;
import com.example.houserental.security.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserSerivceImp implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    public boolean hasUserWithEmail(String email) {
        return userRepository.findByEmail(email).isPresent();
    }

    public User createUser(SignUpDTO signUpDTO) {
        if (hasUserWithEmail(signUpDTO.getEmail())) {
            return null; // User already exists
        }
        User user = new User();
        user.setUsername(signUpDTO.getUsername());
        user.setFirstname(signUpDTO.getFirstname());
        user.setLastname(signUpDTO.getLastname());
        user.setEmail(signUpDTO.getEmail());
        user.setPassword(passwordEncoder.encode(signUpDTO.getPassword()));
        return userRepository.save(user);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var user = userRepository.findByUsername(request.getUsername()).orElseThrow(() -> new UsernameNotFoundException("User not found!!"));
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        var JwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(JwtToken)
                .build();
    }

}
