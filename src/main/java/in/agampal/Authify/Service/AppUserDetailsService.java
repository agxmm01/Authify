package in.agampal.Authify.Service;

import in.agampal.Authify.Entity.UserEntity;
import in.agampal.Authify.Repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
@Component
@RequiredArgsConstructor
//@AllArgsConstructor
public class AppUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        return User.builder()
                .username(existingUser.getEmail())
                .password(existingUser.getPassword())
                .authorities(new ArrayList<>())
                // .disabled(!existingUser.getIsAccountVerified()) // false = enabled
                .build();
    }
}
