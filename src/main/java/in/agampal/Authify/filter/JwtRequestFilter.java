package in.agampal.Authify.filter;

import in.agampal.Authify.Service.AppUserDetailsService;
import in.agampal.Authify.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@AllArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {
    private final AppUserDetailsService appUserDetailsService;
    private final JwtUtil jwtUtil;
    private static final List<String> PUBLIC_URLS = List.of("/login","/register","/send-reset-otp","/reset-password","/logout","/send-otp","/verify-otp");
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String path = request.getServletPath();
        if (PUBLIC_URLS.stream().anyMatch(path::endsWith)) {
            filterChain.doFilter(request, response);
            return;
        }
        String jwt = null;
        String email = null;

        // 1. Check the authorization header
        final String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.toLowerCase().startsWith("bearer ")) {
            jwt = authorizationHeader.substring(7);
}

        //2. If it is not found in the header
        if(jwt == null) {
            Cookie[] cookies = request.getCookies();
            if(cookies != null){
                for (Cookie cookie : cookies) {
                    if("JWT_TOKEN".equals(cookie.getName())) {
                        jwt = cookie.getValue();
                        break;
                    }
                }
            }
        }

        //3. Validate the token and set the security Context

        if(jwt != null) {
            try {
                email = jwtUtil.extractEmail(jwt);
                if(email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                   UserDetails userDetails=  appUserDetailsService.loadUserByUsername(email);
                   if(jwtUtil.validateToken(jwt,userDetails)) {
                       UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                       authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                       SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                   }
                }
            } catch (Exception e) {
                // JWT is invalid/expired - don't set authentication, let Spring Security handle it
                // Don't throw exception - just continue without authentication
            }
        }
        filterChain.doFilter(request, response);
    }
}
