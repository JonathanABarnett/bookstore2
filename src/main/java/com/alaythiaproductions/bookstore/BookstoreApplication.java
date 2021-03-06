package com.alaythiaproductions.bookstore;

import com.alaythiaproductions.bookstore.domain.User;
import com.alaythiaproductions.bookstore.domain.security.Role;
import com.alaythiaproductions.bookstore.domain.security.UserRole;
import com.alaythiaproductions.bookstore.service.impl.UserService;
import com.alaythiaproductions.bookstore.utility.SecurityUtility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
public class BookstoreApplication implements CommandLineRunner {

    @Autowired
    private UserService userService;

    public static void main(String[] args) {
        SpringApplication.run(BookstoreApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        User user1 = new User();
        user1.setFirstName("First");
        user1.setLastName("User");
        user1.setUsername("a");
        user1.setPassword(SecurityUtility.passwordEncoder().encode("1"));
        user1.setEmail("abc@gmail.com");
        Set<UserRole> userRoles = new HashSet<>();
        Role role1 = new Role();
        role1.setRoleId(1);
        role1.setName("ROLE_USER");
        userRoles.add(new UserRole(user1, role1));

        userService.createUser(user1, userRoles);
    }

}
