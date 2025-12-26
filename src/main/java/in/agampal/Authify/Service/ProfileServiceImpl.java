package in.agampal.Authify.Service;

import in.agampal.Authify.Entity.UserEntity;
import in.agampal.Authify.Repository.UserRepository;
import in.agampal.Authify.io.ProfileRequest;
import in.agampal.Authify.io.ProfileResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor
public class ProfileServiceImpl implements ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Override
    public ProfileResponse createProfile(ProfileRequest request) {
        UserEntity newProfile = convertToUserEntity(request);
        if(!userRepository.existsByEmail(request.getEmail())) {
            newProfile = userRepository.save(newProfile);
            return convertToProfileResponse(newProfile);
        }
        // #region agent log
        try {Files.write(Paths.get("c:\\Users\\Acer\\Desktop\\Authify\\.cursor\\debug.log"),(String.format("{\"sessionId\":\"debug-session\",\"runId\":\"post-fix\",\"hypothesisId\":\"A\",\"location\":\"ProfileServiceImpl.java:19\",\"message\":\"createProfile entry\",\"data\":{\"requestEmail\":\"%s\",\"requestName\":\"%s\"},\"timestamp\":%d}%n",request.getEmail()!=null?request.getEmail():"null",request.getName()!=null?request.getName():"null",System.currentTimeMillis())).getBytes(),StandardOpenOption.CREATE,StandardOpenOption.APPEND);}catch(Exception e){}
        // #endregion

        // #region agent log
        try {Files.write(Paths.get("c:\\Users\\Acer\\Desktop\\Authify\\.cursor\\debug.log"),(String.format("{\"sessionId\":\"debug-session\",\"runId\":\"post-fix\",\"hypothesisId\":\"A\",\"location\":\"ProfileServiceImpl.java:21\",\"message\":\"Entity before save\",\"data\":{\"createdAtType\":\"%s\",\"createdAtValue\":\"%s\",\"updatedAtType\":\"%s\",\"updatedAtValue\":\"%s\",\"id\":%s},\"timestamp\":%d}%n",newProfile.getCreatedAt()!=null?newProfile.getCreatedAt().getClass().getName():"null",newProfile.getCreatedAt()!=null?newProfile.getCreatedAt().toString():"null",newProfile.getUpdatedAt()!=null?newProfile.getUpdatedAt().getClass().getName():"null",newProfile.getUpdatedAt()!=null?newProfile.getUpdatedAt().toString():"null",newProfile.getId()!=null?newProfile.getId().toString():"null",System.currentTimeMillis())).getBytes(),StandardOpenOption.CREATE,StandardOpenOption.APPEND);}catch(Exception e){}
        // #endregion

        // #region agent log
        try {Files.write(Paths.get("c:\\Users\\Acer\\Desktop\\Authify\\.cursor\\debug.log"),(String.format("{\"sessionId\":\"debug-session\",\"runId\":\"post-fix\",\"hypothesisId\":\"B\",\"location\":\"ProfileServiceImpl.java:23\",\"message\":\"Entity after save - SUCCESS\",\"data\":{\"createdAtType\":\"%s\",\"createdAtValue\":\"%s\",\"updatedAtType\":\"%s\",\"updatedAtValue\":\"%s\",\"id\":%s},\"timestamp\":%d}%n",newProfile.getCreatedAt()!=null?newProfile.getCreatedAt().getClass().getName():"null",newProfile.getCreatedAt()!=null?newProfile.getCreatedAt().toString():"null",newProfile.getUpdatedAt()!=null?newProfile.getUpdatedAt().getClass().getName():"null",newProfile.getUpdatedAt()!=null?newProfile.getUpdatedAt().toString():"null",newProfile.getId()!=null?newProfile.getId().toString():"null",System.currentTimeMillis())).getBytes(),StandardOpenOption.CREATE,StandardOpenOption.APPEND);}catch(Exception e){}
        // #endregion

        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already Exists");

    }

    @Override
    public ProfileResponse getProfile(String email) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(()-> new UsernameNotFoundException("User not found " + email));

        return convertToProfileResponse(existingUser);
    }

    @Override
    public void sendResetOtp(String email) {
        UserEntity existingEntity = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found " + email));

        // Generate 6 digit Otp
        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));

        // calculate expiry time (current time + 15 mins in milliseconds)
        long expiryTime = System.currentTimeMillis() + (15 * 60*1000);

        // Update the profile/user
        existingEntity.setResetOtp(otp);
        existingEntity.setResetOtpExpireAt(expiryTime);

        // save into the database
        userRepository.save(existingEntity);

        try {
            emailService.sendResetOtpEmail(existingEntity.getEmail(), existingEntity.getResetOtp());
        } catch (Exception ex) {
            throw new RuntimeException("Unable to send email");
        }
    }

    @Override
    public void resetPassword(String email, String otp, String newPassword) {
        UserEntity exisitingEntity = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found " + email));
        if(exisitingEntity.getResetOtp()==null || !exisitingEntity.getResetOtp().equals(otp)){
            throw new RuntimeException("Invalid OTP");
        }

        if (exisitingEntity.getResetOtpExpireAt() < System.currentTimeMillis()) {
            throw new RuntimeException("OTP expired");
        }

        exisitingEntity.setPassword(passwordEncoder.encode(newPassword));
        exisitingEntity.setResetOtp(null);
        exisitingEntity.setResetOtpExpireAt(0L);

        userRepository.save(exisitingEntity);

    }

    @Override
    public void sendOtp(String email) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found " + email));
        if (existingUser.getIsAccountVerified() != null && existingUser.getIsAccountVerified()) {
            return;
        }

        // Generate 6 digit Otp
        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));

        // calculate expiry time (current time + 24 hours in milliseconds)
        long expiryTime = System.currentTimeMillis() + (24* 60 * 60 *1000);

        //Update the user/profile
        existingUser.setVerifyOtp(otp);
        existingUser.setVerifyOtpExpireAt(expiryTime);

        //Save the configuration to database
        userRepository.save(existingUser);
    }

    @Override
    public void verifyOtp(String email, String otp) {

    }

    @Override
    public String getLoggedInUserId(String email) {
       UserEntity existingUser = userRepository.findByEmail(email)
               .orElseThrow(() -> new UsernameNotFoundException("User not found " + email));
       return existingUser.getUserId();
    }

    private ProfileResponse convertToProfileResponse(UserEntity newProfile) {
        return ProfileResponse.builder()
                .name(newProfile.getName())
                .email(newProfile.getEmail())
                .userId(newProfile.getUserId())
                .isAccountVerified(newProfile.getIsAccountVerified())
                .build();
    }

    private UserEntity convertToUserEntity(ProfileRequest request) {
        return UserEntity.builder()
                .email(request.getEmail())
                .userId(UUID.randomUUID().toString())
                .name(request.getName())
                .password(passwordEncoder.encode(request.getPassword()))
                .isAccountVerified(false)
                .resetOtpExpireAt(0L)
                .verifyOtp(null)
                .verifyOtpExpireAt(0L)
                .resetOtp(null)
                .build();
    }
}
