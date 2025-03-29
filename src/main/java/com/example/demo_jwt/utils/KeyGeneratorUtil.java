package com.example.demo_jwt.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class KeyGeneratorUtil {
    
    public static void generateKeyPair() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();


        File directory = new File("src/main/resources/certs");
        if (!directory.exists()) {
            directory.mkdirs();
        }


        try (FileOutputStream fos = new FileOutputStream("src/main/resources/certs/public.pem")) {
            String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                    Base64.getEncoder().encodeToString(publicKey.getEncoded()) +
                    "\n-----END PUBLIC KEY-----";
            fos.write(publicKeyPEM.getBytes());
        }


        try (FileOutputStream fos = new FileOutputStream("src/main/resources/certs/private.pem")) {
            String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                    Base64.getEncoder().encodeToString(privateKey.getEncoded()) +
                    "\n-----END PRIVATE KEY-----";
            fos.write(privateKeyPEM.getBytes());
        }


        File targetDirectory = new File("target/classes/certs");
        if (!targetDirectory.exists()) {
            targetDirectory.mkdirs();
        }

        // Lưu public key vào target
        try (FileOutputStream fos = new FileOutputStream("target/classes/certs/public.pem")) {
            String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                    Base64.getEncoder().encodeToString(publicKey.getEncoded()) +
                    "\n-----END PUBLIC KEY-----";
            fos.write(publicKeyPEM.getBytes());
        }

        // Lưu private key vào target
        try (FileOutputStream fos = new FileOutputStream("target/classes/certs/private.pem")) {
            String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                    Base64.getEncoder().encodeToString(privateKey.getEncoded()) +
                    "\n-----END PRIVATE KEY-----";
            fos.write(privateKeyPEM.getBytes());
        }
    }

    public static void main(String[] args) {
        try {
            generateKeyPair();
            System.out.println("Đã tạo thành công cặp khóa RSA trong thư mục src/main/resources/certs và target/classes/certs!");
            System.out.println("Vui lòng kiểm tra các file:");
            System.out.println("- src/main/resources/certs/public.pem");
            System.out.println("- src/main/resources/certs/private.pem");
            System.out.println("- target/classes/certs/public.pem");
            System.out.println("- target/classes/certs/private.pem");
        } catch (Exception e) {
            System.err.println("Lỗi khi tạo cặp khóa RSA: " + e.getMessage());
            e.printStackTrace();
        }
    }
} 