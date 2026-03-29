package com.enterprise.fraudintel.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "mitigation_rules")
public class MitigationRule {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String description;
    private String action; // e.g., "BLOCK", "FLAG", "MFA"
    private boolean enabled = true;
    private Integer priority;

    public MitigationRule() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public Integer getPriority() { return priority; }
    public void setPriority(Integer priority) { this.priority = priority; }
}
