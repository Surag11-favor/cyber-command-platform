package com.enterprise.fraudintel.controller;

import com.enterprise.fraudintel.entity.AuditLog;
import com.enterprise.fraudintel.entity.ScanResult;
import com.enterprise.fraudintel.entity.MitigationRule;
import com.enterprise.fraudintel.repository.AuditLogRepository;
import com.enterprise.fraudintel.repository.ScanResultRepository;
import com.enterprise.fraudintel.repository.MitigationRuleRepository;
import com.enterprise.fraudintel.service.ScanService;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.*;

@RestController
@RequestMapping("/api")
public class ScanController {

    private final ScanResultRepository scanResultRepository;
    private final AuditLogRepository auditLogRepository;
    private final MitigationRuleRepository mitigationRuleRepository;
    private final ScanService scanService;

    public ScanController(ScanResultRepository scanResultRepository, 
                          AuditLogRepository auditLogRepository, 
                          MitigationRuleRepository mitigationRuleRepository,
                          ScanService scanService) {
        this.scanResultRepository = scanResultRepository;
        this.auditLogRepository = auditLogRepository;
        this.mitigationRuleRepository = mitigationRuleRepository;
        this.scanService = scanService;
    }

    @PostMapping("/scans/analyze")
    public Map<String, Object> runScan(@RequestParam("payload") String payload, Principal principal) {
        try {
            long startTime = System.currentTimeMillis();
            Map<String, Object> analysisResult = scanService.analyzeUrl(payload);
            long elapsed = System.currentTimeMillis() - startTime;

            String riskRating = String.valueOf(analysisResult.get("riskRating"));
            Object scoreObj = analysisResult.get("threatScore");
            double threatScore = scoreObj instanceof Number ? ((Number) scoreObj).doubleValue() : 0.0;
            String summary = String.valueOf(analysisResult.get("summary"));

            // Truncate summary for DB storage
            String dbSummary = summary.length() > 250 ? summary.substring(0, 250) : summary;

            ScanResult result = new ScanResult();
            result.setPayload(payload);
            result.setRiskScore(threatScore);
            result.setRiskLevel(riskRating);
            result.setSocialMediaSentiment(dbSummary);
            scanResultRepository.save(result);

            AuditLog log = new AuditLog();
            log.setAction("DEEP_SCAN");
            log.setPerformedBy(principal != null ? principal.getName() : "Anonymous");
            
            // Detailed Global Intelligence breakdown for audit
            String auditDetail = String.format("Global Intel Pulse: %s | Risk: %s (%s%%) | Duration: %dms | Findings: %d", 
                payload, riskRating, String.format("%.0f", threatScore), elapsed, 
                analysisResult.get("phases") != null ? ((List<?>)analysisResult.get("phases")).size() : 0);
                
            log.setDetails(auditDetail);
            auditLogRepository.save(log);

            Map<String, Object> response = new HashMap<>(analysisResult);
            response.put("status", "success");
            response.put("scanDurationMs", elapsed);
            return response;

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("riskRating", "HIGH");
            errorResponse.put("threatScore", 95.0);
            errorResponse.put("summary", "Engine Error: " + e.getMessage());
            
            List<Map<String, Object>> phases = new ArrayList<>();
            Map<String, Object> errorPhase = new HashMap<>();
            errorPhase.put("name", "Engine Fault");
            errorPhase.put("findings", Arrays.asList("✗ CRITICAL: " + e.getMessage()));
            errorPhase.put("durationMs", 0);
            phases.add(errorPhase);
            errorResponse.put("phases", phases);
            
            return errorResponse;
        }
    }

    @PostMapping("/mitigations/fix-all")
    public Map<String, Object> fixAll(Principal principal) {
        try {
            List<MitigationRule> rules = mitigationRuleRepository.findAll();
            for (MitigationRule rule : rules) {
                rule.setEnabled(true);
            }
            mitigationRuleRepository.saveAll(rules);

            AuditLog log = new AuditLog();
            log.setAction("ULTRA_FIX");
            log.setPerformedBy(principal != null ? principal.getName() : "VORTEX-ADMIN");
            log.setDetails("UNIVERSAL MITIGATION OVERRIDE: All security protocols activated across the platform.");
            auditLogRepository.save(log);

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "All 32+ mitigation protocols across 4 zones have been activated.");
            return response;
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("status", "error");
            response.put("message", "Mitigation failed: " + e.getMessage());
            return response;
        }
    }
}
