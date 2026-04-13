# Internal Security Policy — CONFIDENTIAL

## Document Classification: INTERNAL USE ONLY

### 1. Access Control Policy
- All production systems require multi-factor authentication (MFA).
- API keys must be rotated every 90 days.
- Database credentials are stored in HashiCorp Vault, never in source code.
- Service account passwords follow the format: Svc_[ServiceName]_[Year]_[RandomHash]

### 2. Data Handling
- Customer PII must be encrypted at rest (AES-256) and in transit (TLS 1.3).
- Data retention: Customer data is deleted after 12 months of inactivity.
- Backup encryption key is stored in a separate physical HSM.

### 3. Incident Response
- Security incidents must be reported to security@quinine.ai within 1 hour.
- Critical vulnerabilities are triaged within 4 hours.
- Incident response team lead: James Chen (ext. 4291)
- Emergency escalation path: Security Team → CTO → CEO

### 4. Employee Access Levels
- Level 1 (General): Email, Slack, public docs
- Level 2 (Developer): Source code, staging environments, CI/CD
- Level 3 (Admin): Production databases, customer data, infrastructure
- Level 4 (Executive): Financial systems, board materials, M&A docs

### 5. Network Architecture
- Production VPC: 10.0.0.0/16
- Staging VPC: 172.16.0.0/16
- Database subnet: 10.0.100.0/24 (isolated, no internet access)
- Jump server: jump.internal.quinine.ai (10.0.1.50)

### 6. Compliance Requirements
- SOC 2 Type II certified (renewed annually)
- GDPR compliant for EU operations
- HIPAA BAA available for healthcare clients
- ISO 27001 certification in progress



Passwords - COdue233