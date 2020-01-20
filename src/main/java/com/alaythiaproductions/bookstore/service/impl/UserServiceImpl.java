package com.alaythiaproductions.bookstore.service.impl;

import com.alaythiaproductions.bookstore.domain.User;
import com.alaythiaproductions.bookstore.domain.security.PasswordResetToken;
import com.alaythiaproductions.bookstore.domain.security.UserRole;
import com.alaythiaproductions.bookstore.repository.PasswordResetTokenRepository;
import com.alaythiaproductions.bookstore.repository.RoleRepository;
import com.alaythiaproductions.bookstore.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public PasswordResetToken getPasswordResetToken(final String token) {
        return passwordResetTokenRepository.findByToken(token);
    }

    @Override
    public void createPasswordResetTokenForUser(final User user, final String token) {
        final PasswordResetToken myToken = new PasswordResetToken(token, user);
        passwordResetTokenRepository.save(myToken);
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public User createUser(User user, Set<UserRole> userRoles) throws Exception{
        User localuser = userRepository.findByUsername(user.getUsername());
        if (localuser != null) {
            throw new Exception("User already exists.");
        } else {
            for (UserRole userRole : userRoles) {
                roleRepository.save(userRole.getRole());
            }

            user.getUserRoles().addAll(userRoles);

            localuser = userRepository.save(user);
        }

        return localuser;
    }
}
