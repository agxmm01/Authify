package in.agampal.Authify.controller;

import in.agampal.Authify.Service.ProfileService;
import in.agampal.Authify.io.ProfileRequest;
import in.agampal.Authify.io.ProfileResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class ProfileController {

    private final ProfileService profileService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ProfileResponse registerUser(@Valid @RequestBody ProfileRequest request){
        ProfileResponse response = profileService.createProfile(request);
        // TODO : send email
        return response;
    }
}
