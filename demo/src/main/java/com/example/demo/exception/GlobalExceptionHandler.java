//package com.example.demo.exception;
//
//import com.example.demo.dto.AuthDto;
//import jakarta.persistence.EntityNotFoundException;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.dao.DataIntegrityViolationException;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.validation.FieldError;
//import org.springframework.web.bind.MethodArgumentNotValidException;
//import org.springframework.web.bind.annotation.ExceptionHandler;
//import org.springframework.web.bind.annotation.RestControllerAdvice;
//import org.springframework.web.context.request.WebRequest;
//
//import java.util.HashMap;
//import java.util.Map;
//
//@Slf4j
//@RestControllerAdvice
//public class GlobalExceptionHandler {
//
//    @ExceptionHandler(MethodArgumentNotValidException.class)
//    public ResponseEntity<Map<String, String>> handleValidationExceptions(
//            MethodArgumentNotValidException ex) {
//        Map<String, String> errors = new HashMap<>();
//        ex.getBindingResult().getAllErrors().forEach((error) -> {
//            String fieldName = ((FieldError) error).getField();
//            String errorMessage = error.getDefaultMessage();
//            errors.put(fieldName, errorMessage);
//        });
//
//        log.error("Validation error: {}", errors);
//        return ResponseEntity.badRequest().body(errors);
//    }
//
//    @ExceptionHandler(EntityNotFoundException.class)
//    public ResponseEntity<AuthDto.MessageResponse> handleEntityNotFoundException(
//            EntityNotFoundException ex, WebRequest request) {
//        log.error("Entity not found: {}", ex.getMessage());
//
//        return ResponseEntity.status(HttpStatus.NOT_FOUND)
//                .body(AuthDto.MessageResponse.builder()
//                        .message("요청한 리소스를 찾을 수 없습니다.")
//                        .build());
//    }
//
//    @ExceptionHandler(DataIntegrityViolationException.class)
//    public ResponseEntity<AuthDto.MessageResponse> handleDataIntegrityViolationException(
//            DataIntegrityViolationException ex, WebRequest request) {
//        log.error("Data integrity violation: {}", ex.getMessage());
//
//        String message = "데이터 무결성 제약 조건을 위반했습니다.";
//        if (ex.getMessage().contains("username")) {
//            message = "이미 존재하는 사용자명입니다.";
//        } else if (ex.getMessage().contains("email")) {
//            message = "이미 존재하는 이메일입니다.";
//        }
//
//        return ResponseEntity.badRequest()
//                .body(AuthDto.MessageResponse.builder()
//                        .message(message)
//                        .build());
//    }
//
//    @ExceptionHandler(RuntimeException.class)
//    public ResponseEntity<AuthDto.MessageResponse> handleRuntimeException(
//            RuntimeException ex, WebRequest request) {
//        log.error("Runtime exception: {}", ex.getMessage());
//
//        return ResponseEntity.badRequest()
//                .body(AuthDto.MessageResponse.builder()
//                        .message(ex.getMessage())
//                        .build());
//    }
//
//    @ExceptionHandler(Exception.class)
//    public ResponseEntity<AuthDto.MessageResponse> handleGenericException(
//            Exception ex, WebRequest request) {
//        log.error("Unexpected error: {}", ex.getMessage(), ex);
//
//        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//                .body(AuthDto.MessageResponse.builder()
//                        .message("서버 내부 오류가 발생했습니다.")
//                        .build());
//    }
//}
