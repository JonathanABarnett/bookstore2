package com.alaythiaproductions.bookstore.repository;

import com.alaythiaproductions.bookstore.domain.security.Role;
import org.springframework.data.repository.CrudRepository;

public interface RoleRepository extends CrudRepository<Role, Long> {

    Role findByName(String name);
}
