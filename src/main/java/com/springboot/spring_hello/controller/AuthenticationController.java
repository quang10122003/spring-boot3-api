package com.springboot.spring_hello.controller;

import java.text.ParseException;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springboot.spring_hello.DTO.Request.AuthenticationRequest;
import com.springboot.spring_hello.DTO.Request.IntrospectRequest;
import com.springboot.spring_hello.DTO.response.ApiResponse;
import com.springboot.spring_hello.DTO.response.AuthenticationReponse;
import com.springboot.spring_hello.DTO.response.IntrospectResponse;
import com.springboot.spring_hello.service.interfaces.AuthenticationService;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE,makeFinal = true)
public class AuthenticationController {
    AuthenticationService authenticationService;

    @PostMapping("/login")
    ApiResponse<AuthenticationReponse> authenticate(@RequestBody AuthenticationRequest authenticationRequest){
        AuthenticationReponse result = authenticationService.authentication(authenticationRequest);
        return ApiResponse.<AuthenticationReponse>builder()
               .code(200)
               .result(result)
               .build();
    }
// check token 
    @PostMapping("/Introspect")
    ApiResponse<IntrospectResponse> authenticateIntrospect(@RequestBody IntrospectRequest introspectRequest) throws Exception, ParseException{
        IntrospectResponse result = authenticationService.introspect(introspectRequest);
        return ApiResponse.<IntrospectResponse>builder()
        .code(200)
        .result(result)
        .build();
    }
}
