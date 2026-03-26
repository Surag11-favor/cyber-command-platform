package com.enterprise.fraudintel.controller;

import com.enterprise.fraudintel.entity.AuditLog;
import com.enterprise.fraudintel.entity.ScanResult;
import com.enterprise.fraudintel.repository.AuditLogRepository;
import com.enterprise.fraudintel.repository.ScanResultRepository;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import com.enterprise.fraudintel.service.ScanService;

@RestController
@RequestMapping("/api")
public class ScanController {

    private final ScanResultRepository scanResultRepository;
    private final AuditLogRepository auditLogRepository;
    private final ScanService scanService;

    public ScanController(ScanResultRepository scanResultRepository, AuditLogRepository auditLogRepository, ScanService scanService) {
        this.scanResultRepository = scanResultRepository;
        this.auditLogRepository = auditLogRepository;
        this.scanService = scanService;
    }

    // Handles: POST /api/scans/analyze  (form-encoded "payload" param from the frontend)
    @PostMapping("/scans/analyze")
    public Map<String, Object> runScan(@RequestParam("payload") String payload, Principal principal) {

        // Delegate to ScanService for actual detection
        Map<String, Object> analysisResult = scanService.analyzeUrl(payload);

        String riskRating = (String) analysisResult.get("riskRating");
        double threatScore = (Double) analysisResult.get("threatScore");
        String summary = (String) analysisResult.get("summary");

        // Persist Result
        ScanResult result = new ScanResult();
        result.setPayload(payload);
        result.setRiskScore(threatScore);
        result.setRiskLevel(riskRating);
        result.setSocialMediaSentiment(summary);
        scanResultRepository.save(result);

        // Audit Log
        AuditLog log = new AuditLog();
        log.setAction("SCAN_PERFORMED");
        log.setPerformedBy(principal != null ? principal.getName() : "Anonymous");
        log.setDetails("Scanned URL: " + (payload != null && payload.length() > 30 ? payload.substring(0, 30) + "..." : payload));
        auditLogRepository.save(log);

        Map<String, Object> response = new HashMap<>(analysisResult);
        response.put("status", "success");
        response.put("payloadSnippet", payload.length() > 80 ? payload.substring(0, 80) + "..." : payload);

        return response;
    }

    // Legacy fallback: POST /api/analysis/scan (JSON body)
    @PostMapping("/analysis/scan")
    public Map<String, Object> runScanLegacy(@RequestBody Map<String, String> request, Principal principal) {
        String content = request.get("content");
        if (content == null) content = request.get("payload");

        Map<String, Object> analysisResult = scanService.analyzeUrl(content);

        String riskRating = (String) analysisResult.get("riskRating");
        double threatScore = (Double) analysisResult.get("threatScore");
        String summary = (String) analysisResult.get("summary");

        ScanResult result = new ScanResult();
        result.setPayload(content);
        result.setRiskScore(threatScore);
        result.setRiskLevel(riskRating);
        result.setSocialMediaSentiment(summary);
        scanResultRepository.save(result);

        AuditLog log = new AuditLog();
        log.setAction("SCAN_PERFORMED");
        log.setPerformedBy(principal != null ? principal.getName() : "Anonymous");
        log.setDetails("Scanned URL: " + (content != null && content.length() > 30 ? content.substring(0, 30) + "..." : content));
        auditLogRepository.save(log);

        Map<String, Object> response = new HashMap<>(analysisResult);
        response.put("status", "success");
        response.put("payloadSnippet", content != null ? (content.length() > 80 ? content.substring(0, 80) + "..." : content) : "");

        return response;
    }
}
