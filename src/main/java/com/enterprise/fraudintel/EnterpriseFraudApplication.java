package com.enterprise.fraudintel;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.net.URI;
import java.net.URISyntaxException;

@SpringBootApplication
public class EnterpriseFraudApplication {
    public static void main(String[] args) {
        // Cloud Protocol Bridge: Handle Heroku/Railway DATABASE_URL format
        String databaseUrl = System.getenv("DATABASE_URL");
        if (databaseUrl != null && databaseUrl.startsWith("postgres://")) {
            try {
                URI uri = new URI(databaseUrl);
                String userInfo = uri.getUserInfo();
                if (userInfo != null) {
                    String[] userParts = userInfo.split(":");
                    System.setProperty("CUSTOM_DB_USER", userParts[0]);
                    if (userParts.length > 1) {
                        System.setProperty("CUSTOM_DB_PASS", userParts[1]);
                    }
                }
                
                String port = uri.getPort() == -1 ? "5432" : String.valueOf(uri.getPort());
                String dbUrl = "jdbc:postgresql://" + uri.getHost() + ":" + port + uri.getPath() + "?sslmode=require";
                System.setProperty("CUSTOM_JDBC_URL", dbUrl);
                
                System.out.println("DATABASE_URL Handshake: SECURED");
            } catch (URISyntaxException e) {
                System.err.println("DATABASE_URL Handshake: FAILED - " + e.getMessage());
            }
        }
        
        SpringApplication.run(EnterpriseFraudApplication.class, args);
    }
}
