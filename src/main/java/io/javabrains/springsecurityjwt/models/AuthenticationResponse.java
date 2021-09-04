package io.javabrains.springsecurityjwt.models;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AuthenticationResponse  {
    private final String jwt;

}
