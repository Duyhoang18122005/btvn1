package com.example.demo_jwt.controllers;

import com.example.demo_jwt.TokenService;
import com.example.demo_jwt.entities.User;
import com.example.demo_jwt.payloads.ApiResponse;
import com.example.demo_jwt.payloads.TokenResponse;
import com.example.demo_jwt.payloads.UserLogin;
import com.example.demo_jwt.repositories.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthController(TokenService tokenService, 
                         AuthenticationManager authenticationManager,
                         UserRepository userRepository,
                         PasswordEncoder passwordEncoder) {
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/token")
    public ResponseEntity<ApiResponse<TokenResponse>> login(@RequestBody UserLogin userLogin) {
        try {
            // Kiểm tra user trong database
            Optional<User> userOpt = userRepository.findByUsername(userLogin.getUsername());
            if (userOpt.isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(ApiResponse.error(400, "User not found"));
            }

            // Xác thực thông tin đăng nhập
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userLogin.getUsername(), userLogin.getPassword())
            );

            // Tạo token
            String token = tokenService.generateToken(authentication);
            
            // Trả về response với format mới
            TokenResponse tokenResponse = new TokenResponse(token);
            return ResponseEntity.ok(ApiResponse.success("Login successful", tokenResponse));

        } catch (AuthenticationException e) {
            return ResponseEntity.badRequest()
                .body(ApiResponse.error(400, "Invalid username or password"));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(ApiResponse.error(500, "Internal server error"));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<User>> register(@RequestBody UserLogin userLogin) {
        try {
            // Kiểm tra username đã tồn tại chưa
            if (userRepository.findByUsername(userLogin.getUsername()).isPresent()) {
                return ResponseEntity.badRequest()
                    .body(ApiResponse.error(400, "Username already exists"));
            }

            // Tạo user mới
            User user = new User();
            user.setUsername(userLogin.getUsername());
            user.setPassword(passwordEncoder.encode(userLogin.getPassword()));
            user.setRole("USER");
            
            // Lưu vào database
            User savedUser = userRepository.save(user);
            
            return ResponseEntity.ok(ApiResponse.success("User registered successfully", savedUser));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(ApiResponse.error(500, "Internal server error"));
        }
    }
}
