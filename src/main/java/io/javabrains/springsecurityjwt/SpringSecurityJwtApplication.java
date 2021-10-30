package io.javabrains.springsecurityjwt;

import io.javabrains.springsecurityjwt.configurations.SwaggerConfig;
import io.javabrains.springsecurityjwt.utilities.JwtUtil;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@Import(SwaggerConfig.class)
public class SpringSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }
    @Bean
    public JwtUtil utilBean()throws Exception{
        return new JwtUtil();
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return  NoOpPasswordEncoder.getInstance();
    }
}
