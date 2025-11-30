package com.authentication.system.controller;

import com.authentication.system.dto.JwtResponse;
import com.authentication.system.dto.LoginRequest;
import com.authentication.system.dto.MessageResponse;
import com.authentication.system.dto.SignupRequest;
import com.authentication.system.security.UserPrincipal;
import com.authentication.system.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthService authService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            String jwt = authService.authenticateUser(loginRequest);
            Authentication authentication = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
            
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();        
            List<String> roles = authService.getUserRoles(authentication);

            return ResponseEntity.ok(new JwtResponse(jwt, 
                                                     userPrincipal.getId(), 
                                                     userPrincipal.getUsername(), 
                                                     userPrincipal.getEmail(), 
                                                     roles));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Authentication failed - " + e.getMessage()));
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        try {
            authService.registerUser(signUpRequest);
            return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }
}