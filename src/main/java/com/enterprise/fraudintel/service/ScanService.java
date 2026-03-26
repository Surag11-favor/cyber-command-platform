package com.enterprise.fraudintel.service;

import com.enterprise.fraudintel.entity.AuditLog;
import com.enterprise.fraudintel.entity.MitigationRule;
import com.enterprise.fraudintel.repository.AuditLogRepository;
import com.enterprise.fraudintel.repository.MitigationRuleRepository;
import org.springframework.stereotype.Service;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.*;

@Service
public class ScanService {

    private final MitigationRuleRepository ruleRepository;
    private final AuditLogRepository auditLogRepository;

    public ScanService(MitigationRuleRepository ruleRepository, AuditLogRepository auditLogRepository) {
        this.ruleRepository = ruleRepository;
        this.auditLogRepository = auditLogRepository;
    }

    // Suspicious TLDs commonly used in phishing
    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "bid", "pw", "buzz", "click", "rest", "cam"
    );

    // Deceptive keywords often found in fraudulent links
    private static final Set<String> DECEPTIVE_KEYWORDS = Set.of(
        "login", "verify", "secure", "account", "update", "signin", "banking", "support", "billing"
    );

    // Social Media specific detection
    private static final Set<String> SOCIAL_MEDIA_BRANDS = Set.of(
        "facebook", "twitter", "instagram", "tiktok", "linkedin", "snapchat", "youtube", "whatsapp", "telegram", "x", "paypal"
    );

    private static final Set<String> SHORTENER_DOMAINS = Set.of(
        "bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly", "ow.ly", "rebrand.ly"
    );

    private static final Set<String> SOCIAL_SCAM_KEYWORDS = Set.of(
        "giveaway", "free followers", "followers", "nft raffle", "crypto gift", "claim", "hack", "disabled"
    );

    public Map<String, Object> analyzeUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return buildResponse("LOW", 0.0, "Empty payload provided.", new ArrayList<>());
        }

        String url = rawUrl.trim().toLowerCase();
        double totalScore = 0.0;
        List<String> findings = new ArrayList<>();

        // ─────── PHASE 1: URL Surface Analysis ───────
        // 0. Shortener Detection (Cloaking Warning)
        for (String shortener : SHORTENER_DOMAINS) {
            if (url.contains(shortener)) {
                totalScore += 15.0;
                findings.add("URL Shortener detected — potential cloaking vector");
                break;
            }
        }

        // 0.1 Deceptive Keyword Heuristics
        for (String keyword : DECEPTIVE_KEYWORDS) {
            if (url.contains(keyword)) {
                totalScore += 10.0;
                findings.add("Deceptive keyword in URL: \"" + keyword + "\"");
            }
        }

        // 1. Protocol Layer
        if (!url.startsWith("https://")) {
            totalScore += 30.0;
            findings.add("Non-HTTPS protocol — data in cleartext transit");
        }

        // ─────── PHASE 2: Domain Intelligence ───────
        try {
            URL parsedUrl = URI.create(url.startsWith("http") ? url : "https://" + url).toURL();
            String host = parsedUrl.getHost();
            String path = parsedUrl.getPath();
            
            String[] parts = host.split("\\.");
            String domain = parts.length >= 2 ? parts[parts.length - 2] : host;
            String tld = parts.length >= 1 ? parts[parts.length - 1] : "";

            // 2. Entropy & TLD Reputation
            double domainEntropy = calculateEntropy(domain);
            if (domainEntropy > 4.2) {
                totalScore += 20.0;
                findings.add("High entropy domain name (score: " + String.format("%.2f", domainEntropy) + ") — possible DGA");
            }
            if (SUSPICIOUS_TLDS.contains(tld)) {
                totalScore += 25.0;
                findings.add("Suspicious TLD registered (." + tld + ")");
                for (String brand : SOCIAL_MEDIA_BRANDS) {
                    if (domain.contains(brand)) {
                        totalScore += 30.0;
                        findings.add("Social media brand impersonation in domain");
                        break;
                    }
                }
            }

            // 2.1 Subdomain enumeration risk
            if (parts.length > 3) {
                totalScore += 10.0;
                findings.add("Excessive subdomain depth (" + parts.length + " levels) — evasion technique");
            }

            // 2.2 IP-based hosting check
            if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                totalScore += 20.0;
                findings.add("Direct IP hosting detected — bypasses DNS reputation checks");
            }

            // 2.3 Path depth & suspicious path fragments
            if (path != null && !path.isEmpty()) {
                String[] pathParts = path.split("/");
                if (pathParts.length > 6) {
                    totalScore += 5.0;
                    findings.add("Deep URL path structure (" + pathParts.length + " segments)");
                }
                if (path.contains("..") || path.contains("%2e%2e")) {
                    totalScore += 25.0;
                    findings.add("Path traversal pattern detected");
                }
                if (path.contains(".php") || path.contains(".asp") || path.contains("wp-login") || path.contains("wp-admin")) {
                    totalScore += 10.0;
                    findings.add("Server-side endpoint exposure in path");
                }
            }

            // ─────── PHASE 3: Live Content Analysis ───────
            String pageContent = fetchPageContent(url);
            if (pageContent != null && !pageContent.isEmpty()) {
                int contentLength = pageContent.length();
                findings.add("Page fetched successfully (" + (contentLength / 1024) + " KB analyzed)");

                // 3.1 Script obfuscation
                if (pageContent.contains("eval(unescape(") || pageContent.contains("document.write(unescape(")) {
                    totalScore += 45.0;
                    findings.add("Malicious script obfuscation detected (eval/unescape)");
                }

                // 3.2 Base64 encoded payloads
                if (pageContent.contains("atob(") || pageContent.contains("btoa(")) {
                    totalScore += 15.0;
                    findings.add("Base64 encoding functions detected in scripts");
                }

                // 3.3 Suspicious external resources
                boolean hasSuspiciousExternalSource = false;
                for (String susTld : SUSPICIOUS_TLDS) {
                    if (pageContent.contains("." + susTld + "/") || pageContent.contains("." + susTld + "\"") || pageContent.contains("." + susTld + "'")) {
                        hasSuspiciousExternalSource = true;
                        break;
                    }
                }
                if (hasSuspiciousExternalSource) {
                    totalScore += 40.0;
                    findings.add("Suspicious external payload integration from high-risk TLD");
                }

                // 3.4 Form credential harvesting
                if (pageContent.contains("<form")) {
                    boolean hasCredentialFields = pageContent.contains("password") || pageContent.contains("creditcard") || pageContent.contains("ssn") || pageContent.contains("pin");
                    if (hasCredentialFields && pageContent.contains("action=")) {
                        totalScore += 35.0;
                        findings.add("Credential harvesting form detected with external action");
                    } else if (hasCredentialFields) {
                        totalScore += 15.0;
                        findings.add("Sensitive input fields detected on page");
                    }
                }

                // 3.5 Hidden elements & zero-size iframes
                if (pageContent.contains("display:none") || pageContent.contains("visibility:hidden") || pageContent.contains("height:0") || pageContent.contains("width:0")) {
                    totalScore += 10.0;
                    findings.add("Hidden DOM elements detected — possible stealth payload");
                }

                // 3.6 Meta redirect / refresh check
                if (pageContent.contains("meta http-equiv=\"refresh\"") || pageContent.contains("window.location") || pageContent.contains("location.replace")) {
                    totalScore += 15.0;
                    findings.add("Automatic redirect mechanism detected");
                }

                // 3.7 Social scam content matching
                long contentScamMatches = SOCIAL_SCAM_KEYWORDS.stream().filter(pageContent::contains).count();
                if (contentScamMatches > 3) {
                    totalScore += (10.0 * contentScamMatches);
                    findings.add("High density of social scam keywords (" + contentScamMatches + " matches)");
                } else if (contentScamMatches > 0 && SUSPICIOUS_TLDS.contains(tld)) {
                    totalScore += (15.0 * contentScamMatches);
                    findings.add("Social scam keywords on suspicious domain (" + contentScamMatches + " matches)");
                }

                // 3.8 External script count
                int scriptCount = countOccurrences(pageContent, "<script");
                int iframeCount = countOccurrences(pageContent, "<iframe");
                if (scriptCount > 10) {
                    totalScore += 10.0;
                    findings.add("High script density (" + scriptCount + " script tags)");
                }
                if (iframeCount > 2) {
                    totalScore += 15.0;
                    findings.add("Multiple iframe embeds (" + iframeCount + " detected)");
                }

            } else if (totalScore > 20) {
                totalScore += 15.0; 
                findings.add("Target content unreachable on suspicious link — possible evasion");
            } else {
                findings.add("Target content could not be retrieved for deep analysis");
            }

        } catch (Exception e) {
            return buildResponse("HIGH", 95.0, "Deep analysis failure: target payload severely malformed or hostile", findings);
        }

        // ─────── PHASE 4: Final Aggregation ───────
        double finalScore = Math.min(totalScore, 100.0);
        String riskLevel;
        if (finalScore >= 70.0) {
            riskLevel = "HIGH";
        } else if (finalScore >= 40.0) {
            riskLevel = "MEDIUM";
        } else {
            riskLevel = "LOW";
        }
        
        String summaryText = findings.isEmpty() ? "All heuristic checks passed. URL appears safe." 
                                                : findings.size() + " findings detected across " + (findings.stream().filter(f -> f.startsWith("Page fetched") || f.startsWith("Target content")).count() > 0 ? "live content" : "surface") + " analysis.";

        applyMitigationRules(riskLevel.equals("HIGH") ? "BLOCK" : (riskLevel.equals("MEDIUM") ? "CHALLENGE" : "NONE"), "", String.join(", ", findings));

        return buildResponse(riskLevel, finalScore, summaryText, findings);
    }

    private String fetchPageContent(String urlString) {
        try {
            String normalizedUrlString = urlString.startsWith("http") ? urlString : "https://" + urlString;
            HttpURLConnection conn = (HttpURLConnection) URI.create(normalizedUrlString).toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Enterprise-Threat-Intel/1.0");
            conn.setInstanceFollowRedirects(true);
            
            if (conn.getResponseCode() == 200) {
                try (Scanner scanner = new Scanner(conn.getInputStream()).useDelimiter("\\A")) {
                    return scanner.hasNext() ? scanner.next().toLowerCase() : "";
                }
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private void applyMitigationRules(String actionLabel, String url, String reason) {
        if (ruleRepository == null || auditLogRepository == null) return;

        List<MitigationRule> activeRules = ruleRepository.findAll().stream()
            .filter(MitigationRule::isEnabled)
            .filter(r -> r.getAction().equalsIgnoreCase(actionLabel))
            .toList();

        if (!activeRules.isEmpty()) {
            AuditLog log = new AuditLog();
            log.setAction(actionLabel);
            log.setPerformedBy("SYSTEM-ENGINE");
            log.setDetails(actionLabel + " applied due to: " + reason);
            auditLogRepository.save(log);
        }
    }

    private double calculateEntropy(String s) {
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) freq.put(c, freq.getOrDefault(c, 0) + 1);
        double entropy = 0.0;
        for (int count : freq.values()) {
            double p = (double) count / s.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private int countOccurrences(String text, String pattern) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(pattern, idx)) != -1) {
            count++;
            idx += pattern.length();
        }
        return count;
    }

    private Map<String, Object> buildResponse(String riskLevel, double score, String summary, List<String> findings) {
        Map<String, Object> response = new HashMap<>();
        response.put("riskRating", riskLevel);       // HIGH, MEDIUM, LOW
        response.put("threatScore", score);           // 0.0 - 100.0
        response.put("summary", summary);
        response.put("findings", findings);           // Detailed list of findings
        return response;
    }
}
