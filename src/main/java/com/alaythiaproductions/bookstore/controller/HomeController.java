package com.alaythiaproductions.bookstore.controller;

import com.alaythiaproductions.bookstore.domain.User;
import com.alaythiaproductions.bookstore.domain.security.PasswordResetToken;
import com.alaythiaproductions.bookstore.domain.security.Role;
import com.alaythiaproductions.bookstore.domain.security.UserRole;
import com.alaythiaproductions.bookstore.service.UserSecurityService;
import com.alaythiaproductions.bookstore.service.impl.UserService;
import com.alaythiaproductions.bookstore.utility.MailConstructor;
import com.alaythiaproductions.bookstore.utility.SecurityUtility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Controller
public class HomeController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserSecurityService userSecurityService;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private MailConstructor mailConstructor;

    @GetMapping({"/", "/index"})
    public String index() {
        return "index";
    }

    @GetMapping(value = "/myAccount")
    public String myAccount(Model model) {
        model.addAttribute("classActiveLogin", true);
        return "myAccount";
    }

    @GetMapping(value = "/login")
    public String login(Model model) {
        model.addAttribute("classActiveLogin", true);

        return "myAccount";
    }

    @GetMapping(value = "/createAccount")
    public String createAccount(Locale locale, @RequestParam("token") String token, Model model) {
        PasswordResetToken passwordResetToken  = userService.getPasswordResetToken(token);
        if (passwordResetToken == null) {
            String message = "Invalid Token";
            model.addAttribute("message", message);
            return "redirect:/badRequest";
        }

        User user = passwordResetToken.getUser();
        String username = user.getUsername();

        UserDetails userDetails = userSecurityService.loadUserByUsername(username);

        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        model.addAttribute("classActiveCreate", true);
        return "myAccount";
    }

    @PostMapping(value = "/createAccount")
    public String createAccountPost(HttpServletRequest request, @ModelAttribute("createEmail") String userEmail, @ModelAttribute("createUsername") String username, Model model) throws Exception {
        model.addAttribute("createEmail", userEmail);
        model.addAttribute("createUsername", username);

        if(userService.findByUsername(username) != null) {
            model.addAttribute("usernameExists", true);
            return "myAccount";
        }

        if(userService.findByEmail(userEmail) != null) {
            model.addAttribute("emailExists", true);
            return "myAccount";
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(userEmail);

        String password = SecurityUtility.randomPassword();

        String encryptedPassword = SecurityUtility.passwordEncoder().encode(password);
        user.setPassword(encryptedPassword);

        Role role = new Role();
        role.setRoleId(1);
        role.setName("ROLE_USER");
        Set<UserRole> userRoles = new HashSet<>();
        userRoles.add(new UserRole(user, role));
        userService.createUser(user, userRoles);

        String token = UUID.randomUUID().toString();
        userService.createPasswordResetTokenForUser(user, token);

        String appUrl = "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();

        SimpleMailMessage email = mailConstructor.constructResetTokenEmail(appUrl, request.getLocale(), token, user, password);

        mailSender.send(email);

        model.addAttribute("emailSent", true);
        model.addAttribute("classActiveCreate", true);
//        model.addAttribute("classActiveLogin", false);
//        model.addAttribute("classActiveForgot", false);

        return "myAccount";
    }

    @GetMapping(value = "/forgotPassword")
    public String forgotPassword(Model model) {
        model.addAttribute("classActiveForgot", true);

        return "myAccount";
    }
}
