package com.alaythiaproductions.bookstore.repository;

import com.alaythiaproductions.bookstore.domain.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, Long> {

    User findByUsername(String username);

    User findByEmail(String email);
}
