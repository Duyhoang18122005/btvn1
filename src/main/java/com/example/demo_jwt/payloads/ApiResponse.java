package com.example.demo_jwt.payloads;

public class ApiResponse<T> {
    private int code;
    private boolean success;
    private String message;
    private T object;

    public ApiResponse() {
    }

    public ApiResponse(int code, boolean success, String message, T object) {
        this.code = code;
        this.success = success;
        this.message = message;
        this.object = object;
    }

    public static <T> ApiResponse<T> success(String message, T object) {
        return new ApiResponse<>(200, true, message, object);
    }

    public static <T> ApiResponse<T> error(int code, String message) {
        return new ApiResponse<>(code, false, message, null);
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public T getObject() {
        return object;
    }

    public void setObject(T object) {
        this.object = object;
    }
} 