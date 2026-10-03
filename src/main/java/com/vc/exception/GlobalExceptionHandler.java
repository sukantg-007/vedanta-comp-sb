package com.vc.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingRequestCookieException;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

import java.time.LocalDateTime;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(
            InvalidRefreshTokenException.class
    )
    public ResponseEntity<ErrorResponse>
    handleInvalidRefreshToken(
            InvalidRefreshTokenException exception,
            HttpServletRequest request
    ) {
        ErrorResponse errorResponse =
                new ErrorResponse(
                        LocalDateTime.now(),
                        HttpStatus.UNAUTHORIZED.value(),
                        HttpStatus.UNAUTHORIZED
                                .getReasonPhrase(),
                        exception.getMessage(),
                        request.getRequestURI()
                );

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(errorResponse);
    }

    @ExceptionHandler(
            org.springframework.security
                    .authentication
                    .BadCredentialsException.class
    )
    public ResponseEntity<ErrorResponse>
    handleBadCredentials(
            Exception exception,
            HttpServletRequest request
    ) {
        ErrorResponse errorResponse =
                new ErrorResponse(
                        LocalDateTime.now(),
                        HttpStatus.UNAUTHORIZED.value(),
                        HttpStatus.UNAUTHORIZED
                                .getReasonPhrase(),
                        "Invalid email or password",
                        request.getRequestURI()
                );

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(errorResponse);
    }

    @ExceptionHandler(
            MissingRequestCookieException.class
    )
    public ResponseEntity<ErrorResponse>
    handleMissingCookie(
            MissingRequestCookieException exception,
            HttpServletRequest request
    ) {
        ErrorResponse errorResponse =
                new ErrorResponse(
                        LocalDateTime.now(),
                        HttpStatus.UNAUTHORIZED.value(),
                        HttpStatus.UNAUTHORIZED
                                .getReasonPhrase(),
                        "Refresh token is missing",
                        request.getRequestURI()
                );

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(errorResponse);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse>
    handleGeneralException(
            Exception exception,
            HttpServletRequest request
    ) {
        ErrorResponse errorResponse =
                new ErrorResponse(
                        LocalDateTime.now(),
                        HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        HttpStatus.INTERNAL_SERVER_ERROR
                                .getReasonPhrase(),
                        "An unexpected error occurred",
                        request.getRequestURI()
                );

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse);
    }
}