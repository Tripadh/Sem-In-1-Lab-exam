package com.example.jwtrbac.service;

import com.example.jwtrbac.dto.request.LoginRequest;
import com.example.jwtrbac.dto.request.RegisterRequest;
import com.example.jwtrbac.dto.response.AdminDashboardResponse;
import com.example.jwtrbac.dto.response.JwtResponse;
import com.example.jwtrbac.dto.response.MessageResponse;
import com.example.jwtrbac.dto.response.UserProfileResponse;
import com.example.jwtrbac.exception.BadRequestException;
import com.example.jwtrbac.exception.ResourceConflictException;
import com.example.jwtrbac.exception.ResourceNotFoundException;
import com.example.jwtrbac.model.Role;
import com.example.jwtrbac.model.RoleType;
import com.example.jwtrbac.model.User;
import com.example.jwtrbac.repository.RoleRepository;
import com.example.jwtrbac.repository.UserRepository;
import com.example.jwtrbac.security.jwt.JwtUtils;
import com.example.jwtrbac.security.services.UserDetailsImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    public AuthService(AuthenticationManager authenticationManager,
                       UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder,
                       JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
    }

    @Transactional
    public MessageResponse registerUser(RegisterRequest registerRequest) {
        // 1. Verify username uniqueness
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new ResourceConflictException("Username '" + registerRequest.getUsername() + "' is already taken");
        }

        // 2. Verify email uniqueness
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new ResourceConflictException("Email '" + registerRequest.getEmail() + "' is already in use");
        }

        // 3. Security Boundary: Strictly prevent users from assigning themselves ROLE_ADMIN
        if (registerRequest.getRoles() != null && !registerRequest.getRoles().isEmpty()) {
            boolean attemptsAdmin = registerRequest.getRoles().stream()
                    .anyMatch(r -> r.equalsIgnoreCase("ROLE_ADMIN") || r.equalsIgnoreCase("ADMIN"));
            if (attemptsAdmin) {
                throw new BadRequestException("Self-assignment of administrative roles is strictly prohibited.");
            }
        }

        // 4. Secure password hashing with BCrypt
        User user = new User(
                registerRequest.getUsername().trim(),
                registerRequest.getEmail().trim().toLowerCase(),
                passwordEncoder.encode(registerRequest.getPassword())
        );

        // 5. Assign default ROLE_USER to all public registrations
        Role userRole = roleRepository.findByName(RoleType.ROLE_USER)
                .orElseGet(() -> roleRepository.save(new Role(RoleType.ROLE_USER)));

        Set<Role> roles = new HashSet<>();
        roles.add(userRole);
        user.setRoles(roles);

        userRepository.save(user);

        return new MessageResponse("User registered successfully");
    }

    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        // Authenticate with AuthenticationManager (handles BCrypt password verification)
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername().trim(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate JWT token
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new JwtResponse(
                jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles
        );
    }

    @Transactional(readOnly = true)
    public UserProfileResponse getCurrentUserProfile(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + username));

        List<String> roles = user.getRoles().stream()
                .map(r -> r.getName().name())
                .collect(Collectors.toList());

        return new UserProfileResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                roles,
                user.getCreatedAt()
        );
    }

    @Transactional(readOnly = true)
    public AdminDashboardResponse getAdminDashboard() {
        long userCount = userRepository.count();
        return new AdminDashboardResponse(
                "Admin dashboard access granted",
                userCount,
                LocalDateTime.now(),
                "OPERATIONAL"
        );
    }
}
