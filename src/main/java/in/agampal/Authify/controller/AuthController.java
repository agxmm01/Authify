package in.agampal.Authify.controller;

import in.agampal.Authify.Repository.UserRepository;
import in.agampal.Authify.Service.AppUserDetailsService;
import in.agampal.Authify.Service.ProfileService;
import in.agampal.Authify.io.AuthRequest;
import in.agampal.Authify.io.ResetPasswordRequest;
import in.agampal.Authify.util.JwtUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;

    private final JwtUtil jwtUtil;

    private final AuthenticationManager authenticationManager;

    private final AppUserDetailsService userDetailsService;

    private final ProfileService profileService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest) {
        try {
            authenticate(authRequest.getEmail(),authRequest.getPassword());
            final UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getEmail());
            final String jwtToken = jwtUtil.generateToken(userDetails);
            ResponseCookie cookie = ResponseCookie.from("JWT_TOKEN", jwtToken)
                    .httpOnly(true)
                    .path("/")
                    .maxAge(Duration.ofDays(1))
                    .sameSite("Strict")
                    .build();

            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(new AuthRequest(authRequest.getEmail(), jwtToken));

        }catch (BadCredentialsException ex) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", true);
            error.put("message", "Incorrect email or password");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }

        catch (DisabledException ex) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", true);
            error.put("message", "User Account is Disabled");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }

        catch (Exception ex) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", true);
            error.put("message", "Authentication Failed");
            System.out.println("User exists: " + userRepository.findByEmail(authRequest.getEmail()));
            System.out.println("Password raw: " + authRequest.getPassword());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    private void authenticate(String email, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email,password));
    }

    @GetMapping("/is-authenticated")
    public ResponseEntity<Boolean> isAuthenticated(@CurrentSecurityContext(expression = "authentication?.name" )String email){
        return ResponseEntity.ok(email != null);
    }

    @PostMapping("/send-reset-otp")
    public void sendResetOtpEmail(@RequestParam String email) {
        try{
            profileService.sendResetOtp(email);
        }catch (Exception ex){
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        }
    }

    @PostMapping("/reset-password")
    public void resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try{
            profileService.resetPassword(request.getEmail(),request.getOtp(),request.getNewPassword());
        }catch (Exception ex){
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        }
    }

    @PostMapping("/send-otp")
public void sendVerifyOtp(@RequestParam String email){
    try{
        profileService.sendOtp(email);
    } catch (Exception e) {
        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    @PostMapping("/verify-otp")
    public void verifyEmail(@RequestBody Map<String, Object> request) {

        if (request.get("email") == null || request.get("otp") == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "Missing email or OTP"
            );
        }

        try {
            String email = request.get("email").toString();
            String otp   = request.get("otp").toString();

            profileService.verifyOtp(email, otp);

        } catch (Exception e) {
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage()
            );
        }
    }
}
