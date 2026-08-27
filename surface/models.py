"""Pydantic v2 models matching the Surface API JSON responses."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Scan response models (camelCase JSON keys)
# ---------------------------------------------------------------------------

class CVEInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    description: str
    references: list[str] | None = None
    cvss_score: float | None = Field(None, alias="cvssScore")
    cvss_severity: str | None = Field(None, alias="cvssSeverity")
    affected: list[str] | None = None


class IOC(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    items: list[str] | None = None
    type: str | None = None


class SafetyScore(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    score: int
    threat_level: str = Field(alias="threatLevel")
    confidence: str
    confidence_score: float = Field(alias="confidenceScore")
    confidence_reason: str = Field(alias="confidenceReason")
    primary_threat: str = Field(alias="primaryThreat")
    threat_summary: str = Field(alias="threatSummary")
    engines_used: list[str] = Field(alias="enginesUsed")
    info: str | None = None
    recommended_action: str = Field(alias="recommendedAction")
    # How far detection reaches for this file's format: "full" (dedicated ML
    # model plus every engine — PE, ELF), "partial" (every engine runs,
    # detection varies by language — scripts, documents, archives, and the
    # default), or "minimal" (pattern rules and threat feeds only, no ML model
    # exists — Java bytecode, Mach-O, and archives of .class/.dex). A minimal
    # scan never returns Clean: safety is capped at 85 (Informational), which
    # still recommends Allow. Optional so an older deployment still parses.
    coverage: str | None = None
    coverage_note: str | None = Field(None, alias="coverageNote")
    cve_findings: list[CVEInfo] | None = Field(None, alias="cveFindings")


class ArchiveEntry(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    size: int | None = None
    verdict: str | None = None
    threats: list[str] | None = None
    ioc_types: list[str] | None = Field(None, alias="iocTypes")
    ioc_count: int | None = Field(None, alias="iocCount")
    skipped: bool | None = None
    skip_reason: str | None = Field(None, alias="skipReason")


class AnalysisIndicator(BaseModel):
    type: str
    keyword: str
    description: str


class OletoolsResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    skipped: bool | None = None
    reason: str | None = None
    suspicious: bool = False
    macros_found: bool = False
    auto_exec: bool | None = None
    dde_found: bool | None = None
    indicators: list[str] | None = None
    analysis_results: list[AnalysisIndicator] | None = None
    error: str | None = None


class StaticAnalysisResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    file_type: str = Field(alias="fileType")
    indicators: list[str] | None = None
    metadata: dict[str, str] | None = None
    document_info: dict[str, str] | None = Field(None, alias="documentInfo")


class YaraStringMatch(BaseModel):
    identifier: str = ""
    value: str = ""
    offset: int = 0
    length: int = 0
    context: str = ""


class YaraMatch(BaseModel):
    rule: str
    tags: list[str] | None = None
    severity: str | None = None
    category: str | None = None
    description: str | None = None
    matches: list[YaraStringMatch] | None = None
    meta: dict[str, str] | None = None
    confidence: float = 0.0


class YaraScanResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    matches: list[YaraMatch] | None = None
    rules_total: int = Field(0, alias="rulesTotal")
    rules_tested: int = Field(0, alias="rulesTested")
    status: str = ""
    error: str | None = None


class TLSHResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    hash: str | None = None
    match: bool = False
    distance: int | None = None
    match_ref: str | None = Field(None, alias="matchRef")
    source: str | None = None


class CapaCapability(BaseModel):
    name: str
    namespace: str | None = None
    scope: str | None = None


class CapaATTACK(BaseModel):
    tactic: str
    technique: str
    id: str


class CapaResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    capabilities: list[CapaCapability] | None = None
    attack_map: list[CapaATTACK] | None = Field(None, alias="attack_mapping")
    risk_score: int = 0
    error: str | None = None


class MLClassifyResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    malicious: bool = False
    score: float = 0.0
    label: str | None = None
    family: str | None = None
    confidence: float = 0.0
    model_version: str | None = None
    error: str | None = None


class FlossResult(BaseModel):
    decoded_strings: list[str] | None = None
    stack_strings: list[str] | None = None
    tight_strings: list[str] | None = None
    error: str | None = None


class BoxJSFile(BaseModel):
    name: str
    content: str | None = None


class BoxJSResult(BaseModel):
    urls: list[str] | None = None
    commands: list[str] | None = None
    file_writes: list[BoxJSFile] | None = None
    activex: list[str] | None = None
    iocs: list[str] | None = None
    snippets: list[str] | None = None
    risk_score: int = 0
    error: str | None = None


class DiEResult(BaseModel):
    packers: list[str] | None = None
    compilers: list[str] | None = None
    linkers: list[str] | None = None
    protectors: list[str] | None = None
    error: str | None = None


class PDFStreamInfo(BaseModel):
    id: int
    type: str | None = None
    entropy: float = 0.0
    contains: str | None = None


class PDFAnalysisResult(BaseModel):
    suspicious: bool = False
    indicators: list[str] | None = None
    javascript_count: int = 0
    embedded_files: int = 0
    open_actions: int = 0
    launch_actions: int = 0
    encryption_method: str | None = None
    name_obfuscation: bool = False
    streams: list[PDFStreamInfo] | None = Field(None, alias="suspicious_streams")
    error: str | None = None


# ---------------------------------------------------------------------------
# Main scan response — matches FileInfoResponse in Go
# ---------------------------------------------------------------------------

class ScanResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    request_id: str | None = Field(None, alias="requestId")
    name: str
    size: int
    hash: str
    content_type: str = Field(alias="contentType")
    safety_score: SafetyScore = Field(alias="safetyScore")
    scan_time_ms: int = Field(alias="scanTimeMs")
    timestamp: int
    payload_iocs: list[IOC] | None = Field(None, alias="payloadIOCs")
    archive_entries: list[ArchiveEntry] | None = Field(None, alias="archiveEntries")
    archive_type: str | None = Field(None, alias="archiveType")
    has_encrypted_entries: bool | None = Field(None, alias="hasEncryptedEntries")
    oletools_result: OletoolsResult | None = Field(None, alias="oletoolsResult")
    static_analysis: StaticAnalysisResult | None = Field(None, alias="staticAnalysis")
    scanner_version: str | None = Field(None, alias="scannerVersion")
    scanner_mode: str | None = Field(None, alias="scannerMode")
    scan_type: str | None = Field(None, alias="scanType")  # "file" or "payload"

    # Agentic security engines (payload scans)
    code_extraction: dict | None = Field(None, alias="codeExtraction")
    prompt_injection: dict | None = Field(None, alias="promptInjection")
    sensitive_data: dict | None = Field(None, alias="sensitiveData")
    tool_call_analysis: dict | None = Field(None, alias="toolCallAnalysis")


class DeferredScanResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    scan_id: str = Field(alias="scanId")
    request_id: str = Field(alias="requestId")
    status: str
    message: str | None = None


# ---------------------------------------------------------------------------
# Account / billing models (snake_case JSON keys)
# ---------------------------------------------------------------------------

class Account(BaseModel):
    id: str
    email: str
    display_name: str
    api_key: str | None = None
    allowed_types: str
    max_file_size: int
    block_malicious_ip: bool
    plan_id: str
    monthly_credits: int
    credits_used: int
    credits_reset_at: str
    is_admin: bool
    created_at: str


class Plan(BaseModel):
    id: str
    name: str
    monthly_credits: int
    price_cents: int
    max_file_size_mb: int
    rate_limit: int
    description: str


class CreditTier(BaseModel):
    label: str
    max_bytes: int
    credits: int


class DailyVolume(BaseModel):
    dates: list[str] = []
    counts: list[int] = []


class Usage(BaseModel):
    scans_used: int
    max_scans: int
    scans_remaining: int
    max_file_size_mb: int
    plan_tier: str
    reset_at: str
    daily_volume: DailyVolume | None = None


class ScanProfile(BaseModel):
    id: str
    account_id: str
    name: str
    is_default: bool
    allowed_types: str
    max_file_size: int
    block_malicious_ip: bool
    enable_payload_scan: bool = True
    engine_config: dict | None = Field(default=None, alias="engine_config")
    webhook_url: str | None = None
    webhook_api_key: str | None = None
    created_at: str
    updated_at: str


class APIKey(BaseModel):
    id: str
    account_id: str
    profile_id: str
    key_id: str
    key_value: str | None = None
    label: str
    last_used_at: str | None = None
    created_at: str
    profile_name: str | None = None


class ScanHistoryEntry(BaseModel):
    id: str
    account_id: str
    request_id: str
    filename: str
    file_hash: str
    file_size: int
    content_type: str
    safety_score: int
    threat_level: str
    primary_threat: str
    scan_time_ms: int
    credits_used: int
    client_ip: str
    api_key_id: str | None = None
    status: str
    created_at: str


class ScanHistoryPage(BaseModel):
    scans: list[ScanHistoryEntry]
    total: int
    page: int
    limit: int
    has_more: bool


class WebhookFile(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    size: int
    hash: str
    content_type: str = Field(alias="contentType")


class WebhookPayload(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    request_id: str = Field(alias="requestId")
    file: WebhookFile
    scan_result: ScanResult = Field(alias="scanResult")
    threat_level: str = Field(alias="threatLevel")
    is_malicious: bool = Field(alias="isMalicious")
    is_suspicious: bool = Field(alias="isSuspicious")
    timestamp: str
    scan_duration: int = Field(alias="scanDuration")
