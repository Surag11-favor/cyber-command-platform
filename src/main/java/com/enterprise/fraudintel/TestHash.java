package com.enterprise.fraudintel;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;

public class TestHash {
    public static void main(String[] args) {
        try {
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            String hash = encoder.encode("admin123");
            Files.write(Paths.get("generated_hash.txt"), hash.getBytes());
            System.out.println("SUCCESSFULLY GENERATED HASH");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
