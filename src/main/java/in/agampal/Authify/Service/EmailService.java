package in.agampal.Authify.Service;


import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender mailSender;

        @Value("${app.mail.from}")
        private String fromEmail;

        public void sendWelcomeEmail(String toEmail, String name) {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("Welcome to Authify");
            message.setText("Hello, " + name+"\n\n Thank you for registering with us! \n\n Regards, \nAuthify team");
            mailSender.send(message);
        }

        public void sendResetOtpEmail(String email , String otp) {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(email);
            message.setSubject("Password Reset OTP");
            message.setText("Your OTP for resetting your password is " + otp + ". Use this OTP for resetting your password.\n\n Note :" +
                    "This OTP expires in 15 minutes. \n\n Regards, \n Authify team ");
            mailSender.send(message);
        }
}
