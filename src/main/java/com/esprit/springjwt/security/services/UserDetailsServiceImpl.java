package com.esprit.springjwt.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.esprit.springjwt.models.User;
import com.esprit.springjwt.repository.UserRepository;

import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired
  UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsernameAndEnabled(username, true)
            .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

    return UserDetailsImpl.build(user);
  }






 /* @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

    return UserDetailsImpl.build(user);
  }*/

  public List<User> getAllUsers() {
    return userRepository.findAll();
  }
  // Inside your UserService or UserRepository
  //@Override
  public void enableUser(Long userId) {
    // Retrieve currently authenticated user
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    // Check if the authenticated user has the ROLE_ADMIN
    boolean isAdmin = authentication.getAuthorities().stream()
            .anyMatch(role -> role.getAuthority().equals("ROLE_ADMIN"));

    if (isAdmin) {
      // User has the required role, proceed with enabling the user
      User user = userRepository.findById(userId).orElse(null);
      if (user != null) {
        user.setEnabled(true);
        userRepository.save(user);
      } else {
        throw new UsernameNotFoundException("User not found with id: " + userId);
      }
    } else {
      throw new AccessDeniedException("Insufficient permissions to enable user.");
    }
  }

}
