package in.agampal.Authify.Service;

import in.agampal.Authify.Entity.UserEntity;
import in.agampal.Authify.Repository.UserRepository;
import in.agampal.Authify.io.ProfileRequest;
import in.agampal.Authify.io.ProfileResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ProfileServiceImpl implements ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
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
                .isAccountVerified(true)
                .resetOtpExpireAt(0L)
                .verifyOtp(null)
                .verifyOtpExpireAt(0L)
                .resetOtp(null)
                .build();
    }
}
