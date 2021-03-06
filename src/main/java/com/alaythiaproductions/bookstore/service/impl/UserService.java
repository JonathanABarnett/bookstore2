package com.alaythiaproductions.bookstore.service.impl;

import com.alaythiaproductions.bookstore.domain.User;
import com.alaythiaproductions.bookstore.domain.security.PasswordResetToken;
import com.alaythiaproductions.bookstore.domain.security.UserRole;

import java.util.Set;

public interface UserService {

    PasswordResetToken getPasswordResetToken(final String token);

    void createPasswordResetTokenForUser(final User user, final String token);

    User findByUsername(String username);

    User findByEmail(String email);

    User createUser(User user, Set<UserRole>userRoles);
}
