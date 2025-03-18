package com.spring_auth.jwtauth.exception;

import com.spring_auth.jwtauth.dto.MessageResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.Date;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(TokenRefreshException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public MessageResponse handleTokenRefreshException(TokenRefreshException ex, WebRequest request) {
        return new MessageResponse(ex.getMessage());
    }
    
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public MessageResponse globalExceptionHandler(Exception ex, WebRequest request) {
        return new MessageResponse(ex.getMessage());
    }
} 