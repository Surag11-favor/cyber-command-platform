package com.enterprise.fraudintel.controller;

import com.enterprise.fraudintel.entity.AuditLog;
import com.enterprise.fraudintel.entity.ScanResult;
import com.enterprise.fraudintel.repository.AuditLogRepository;
import com.enterprise.fraudintel.repository.ScanResultRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@RestController
@RequestMapping("/api/analysis")
public class ScanController {

    private final ScanResultRepository scanResultRepository;
    private final AuditLogRepository auditLogRepository;

    public ScanController(ScanResultRepository scanResultRepository, AuditLogRepository auditLogRepository) {
        this.scanResultRepository = scanResultRepository;
        this.auditLogRepository = auditLogRepository;
    }

    @PostMapping("/scan")
    public Map<String, Object> runScan(@RequestBody Map<String, String> request, Principal principal) {
        String content = request.get("content");
        
        String riskLevel;
        double riskScore;
        String sentiment;
        String summary;

        if (content == null || content.trim().isEmpty()) {
            riskLevel = "LOW";
            riskScore = 0.0;
            sentiment = "Neutral";
            summary = "Empty payload provided.";
        } else {
            String url = content.trim().toLowerCase();
            
            // 1. Check if URL starts with https
            if (!url.startsWith("https")) {
                riskLevel = "HIGH";
                riskScore = 95.0;
                sentiment = "Highly Suspicious";
                summary = "URL does not use secure HTTPS. Flagged as HIGH RISK.";
            } 
            // 2. Check length (>50 chars) or multiple hyphens
            else if (url.length() > 50 || url.split("-").length - 1 > 1) {
                riskLevel = "MEDIUM"; // Considered SUSPICIOUS
                riskScore = 65.0;
                sentiment = "Negative";
                summary = "URL is excessively long or contains multiple hyphens. Flagged as SUSPICIOUS.";
            } 
            // 3. Known clean domains
            else if (url.contains("google.com") || url.contains("railway.app")) {
                riskLevel = "LOW";
                riskScore = 5.0;
                sentiment = "Positive";
                summary = "Domain matches known safe entity. Marked as TRUSTED.";
            } 
            // 4. Default fallback
            else {
                riskLevel = "LOW";
                riskScore = 20.0;
                sentiment = "Neutral";
                summary = "Standard URL verified. No immediate threats detected.";
            }
        }
        
        // Persist Result
        ScanResult result = new ScanResult();
        result.setPayload(content);
        result.setRiskScore(riskScore);
        result.setRiskLevel(riskLevel);
        result.setSocialMediaSentiment(sentiment);
        scanResultRepository.save(result);

        // Audit Log
        AuditLog log = new AuditLog();
        log.setAction("SCAN_PERFORMED");
        log.setPerformedBy(principal != null ? principal.getName() : "Anonymous");
        log.setDetails("Scanned URL: " + (content != null && content.length() > 30 ? content.substring(0, 30) + "..." : content));
        auditLogRepository.save(log);
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("riskScore", riskScore);
        response.put("riskLevel", riskLevel);
        response.put("sentiment", sentiment);
        response.put("summary", summary);
        
        return response;
    }
}
