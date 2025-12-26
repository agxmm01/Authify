package in.agampal.Authify.Service;

import in.agampal.Authify.io.ProfileRequest;
import in.agampal.Authify.io.ProfileResponse;
import org.springframework.stereotype.Service;

@Service
public interface ProfileService {
    ProfileResponse createProfile(ProfileRequest request);

    ProfileResponse getProfile(String email);

    void sendResetOtp(String email);

    void resetPassword(String email, String otp, String newPassword);

    void sendOtp(String email);

    void verifyOtp(String email, String otp);

//    String getLoggedInUserId(String email);

}
