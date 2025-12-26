package in.agampal.Authify.controller;

import in.agampal.Authify.Service.EmailService;
import in.agampal.Authify.Service.ProfileService;
import in.agampal.Authify.io.ProfileRequest;
import in.agampal.Authify.io.ProfileResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class ProfileController {

    private final EmailService emailService;
    private final ProfileService profileService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ProfileResponse registerUser(@Valid @RequestBody ProfileRequest request){
        ProfileResponse response = profileService.createProfile(request);
        emailService.sendWelcomeEmail(response.getEmail(),response.getName());
        return response;
    }

    @GetMapping("/profile")
    public ProfileResponse getProfile(@CurrentSecurityContext(expression = "authentication?.name")String email){
       return profileService.getProfile(email);
    }
}
