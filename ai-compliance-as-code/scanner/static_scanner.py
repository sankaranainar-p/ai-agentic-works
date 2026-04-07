"""
static_scanner.py — Lightweight regex-based pre-scanner for the
AI Compliance-as-Code VS Code plugin.

Analyses a raw code string BEFORE sending it to the LLM and returns a
``context_hint`` dict that is injected into the user-turn prompt, giving
the model a focused starting point so it does not have to re-derive
obvious structural facts from scratch.

Usage:
    from scanner.static_scanner import scan
    hint = scan(code_string, file_path="src/payments/PaymentController.java")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class SensitiveField:
    name: str                   # normalised name, e.g. "card_number"
    raw_token: str              # exactly as found in source, e.g. "cardNumber"
    category: str               # "pii" | "auth" | "financial" | "health"
    line: int
    context: str                # "assignment" | "param" | "dict_key" | "json_key"
                                # | "column_def" | "class_field" | "log_call"


@dataclass
class Endpoint:
    method: str                 # GET | POST | PUT | PATCH | DELETE | *
    path: str                   # "/api/users" or "" if not determinable
    visibility: str             # "public" | "protected" | "admin" | "unknown"
    auth_mechanism: str         # "jwt" | "session" | "api_key" | "oauth" | "none" | "unknown"
    line: int


@dataclass
class OutboundCall:
    url: str                    # full URL string as found in source
    protocol: str               # "http" | "https" | "unknown"
    line: int
    call_site: str              # "requests" | "fetch" | "axios" | "RestTemplate" | "http.client" | etc.


@dataclass
class ContextHint:
    language: Optional[str]                    # "python" | "java" | "javascript" | "typescript" | "ruby" | None
    framework: Optional[str]                   # "FastAPI" | "Spring" | "Express" | "Django" | "Flask" | "Rails" | None
    framework_confidence: float                # 0.0–1.0
    sensitive_fields: list[SensitiveField]     = field(default_factory=list)
    endpoints: list[Endpoint]                  = field(default_factory=list)
    outbound_calls: list[OutboundCall]         = field(default_factory=list)
    risk_indicators: list[str]                 = field(default_factory=list)
    line_count: int                            = 0

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Sensitive field patterns
# PII, authentication credentials, financial data, health data.
# Keys are normalised canonical names; values are all raw spelling variants
# the scanner will match (regex word-boundary safe tokens).
# ---------------------------------------------------------------------------

_SENSITIVE_FIELD_CATALOG: dict[str, dict] = {
    # ── PII ──────────────────────────────────────────────────────────────
    "email": {
        "category": "pii",
        "variants": ["email", "emailAddress", "email_address", "userEmail",
                     "user_email", "e_mail", "eMail"],
    },
    "phone": {
        "category": "pii",
        "variants": ["phone", "phoneNumber", "phone_number", "mobileNumber",
                     "mobile_number", "tel", "telephone", "mobile"],
    },
    "full_name": {
        "category": "pii",
        "variants": ["fullName", "full_name", "firstName", "first_name",
                     "lastName", "last_name", "surname", "givenName",
                     "given_name", "familyName", "family_name"],
    },
    "date_of_birth": {
        "category": "pii",
        "variants": ["dob", "dateOfBirth", "date_of_birth", "birthDate",
                     "birth_date", "birthday"],
    },
    "address": {
        "category": "pii",
        "variants": ["address", "streetAddress", "street_address", "postalCode",
                     "postal_code", "zipCode", "zip_code", "homeAddress",
                     "billingAddress", "billing_address"],
    },
    "national_id": {
        "category": "pii",
        "variants": ["ssn", "nationalId", "national_id", "taxId", "tax_id",
                     "passportNumber", "passport_number", "nino", "sin",
                     "socialSecurityNumber"],
    },
    "ip_address": {
        "category": "pii",
        "variants": ["ipAddress", "ip_address", "remoteIp", "remote_ip",
                     "clientIp", "client_ip", "sourceIp", "source_ip"],
    },
    # ── Authentication / credentials ─────────────────────────────────────
    "password": {
        "category": "auth",
        "variants": ["password", "passwd", "pwd", "userPassword", "user_password",
                     "rawPassword", "raw_password", "plainPassword", "plain_password",
                     "passwordHash", "password_hash", "hashedPassword", "hashed_password"],
    },
    "secret": {
        "category": "auth",
        "variants": ["secret", "secretKey", "secret_key", "apiSecret", "api_secret",
                     "clientSecret", "client_secret", "appSecret", "app_secret"],
    },
    "token": {
        "category": "auth",
        "variants": ["token", "accessToken", "access_token", "refreshToken",
                     "refresh_token", "authToken", "auth_token", "bearerToken",
                     "bearer_token", "sessionToken", "session_token", "jwtToken",
                     "jwt_token", "idToken", "id_token"],
    },
    "api_key": {
        "category": "auth",
        "variants": ["apiKey", "api_key", "xApiKey", "x_api_key", "serviceKey",
                     "service_key", "privateKey", "private_key"],
    },
    # ── Financial / cardholder data ──────────────────────────────────────
    "card_number": {
        "category": "financial",
        "variants": ["cardNumber", "card_number", "pan", "PAN", "primaryAccountNumber",
                     "primary_account_number", "creditCardNumber", "credit_card_number",
                     "ccNumber", "cc_number", "cardNo", "card_no"],
    },
    "cvv": {
        "category": "financial",
        "variants": ["cvv", "CVV", "cvc", "CVC", "cvv2", "CVV2", "cvc2", "CVC2",
                     "securityCode", "security_code", "cardSecurityCode",
                     "card_security_code", "cid", "CID"],
    },
    "card_expiry": {
        "category": "financial",
        "variants": ["expiryDate", "expiry_date", "expirationDate", "expiration_date",
                     "cardExpiry", "card_expiry", "expMonth", "exp_month",
                     "expYear", "exp_year"],
    },
    "bank_account": {
        "category": "financial",
        "variants": ["accountNumber", "account_number", "bankAccount", "bank_account",
                     "iban", "IBAN", "bic", "BIC", "routingNumber", "routing_number",
                     "sortCode", "sort_code"],
    },
    # ── Health data ──────────────────────────────────────────────────────
    "health_record": {
        "category": "health",
        "variants": ["diagnosis", "medicalRecord", "medical_record", "healthData",
                     "health_data", "patientId", "patient_id", "nhsNumber",
                     "nhs_number", "prescription"],
    },
    # ── Crypto / MiCA ─────────────────────────────────────────────────────
    "wallet_address": {
        "category": "crypto_address",
        "variants": ["toAddress", "to_address", "fromAddress", "from_address",
                     "walletAddress", "wallet_address", "recipientAddress",
                     "recipient_address", "senderAddress", "sender_address"],
    },
    "transfer_amount": {
        "category": "transfer_amount",
        "variants": ["amount", "transferAmount", "transfer_amount", "sendAmount",
                     "send_amount", "txAmount", "tx_amount"],
    },
    "crypto_asset": {
        "category": "crypto_asset",
        "variants": ["asset", "tokenId", "token_id", "cryptoAsset", "crypto_asset",
                     "assetId", "asset_id", "ticker", "symbol"],
    },
}

# Build a flat lookup: raw_variant → (canonical_name, category)
_VARIANT_TO_CANONICAL: dict[str, tuple[str, str]] = {}
for _canonical, _meta in _SENSITIVE_FIELD_CATALOG.items():
    for _variant in _meta["variants"]:
        _VARIANT_TO_CANONICAL[_variant] = (_canonical, _meta["category"])

# Compiled pattern: word-boundary match on all variants, longest first
_ALL_VARIANTS_SORTED = sorted(_VARIANT_TO_CANONICAL.keys(), key=len, reverse=True)
_SENSITIVE_FIELD_RE = re.compile(
    r'(?<![a-zA-Z0-9_])(' + '|'.join(re.escape(v) for v in _ALL_VARIANTS_SORTED) + r')(?![a-zA-Z0-9_])'
)

# Context indicators that increase signal quality: these prefixes/suffixes
# suggest the match is a field definition rather than a comment word.
_CONTEXT_PATTERNS: list[tuple[re.Pattern, str]] = [
    # log_call must come before assignment: `logger.info(f"...password={password}")` would
    # otherwise match the assignment pattern `password=` before reaching log_call.
    (re.compile(r'log(?:ger)?\.\w+\s*\([^)]*\b({token})\b'),                                                  "log_call"),
    (re.compile(r'(?:private|public|protected|final|static|readonly|var|let|const|val)\s+\S+\s+({token})\b'), "class_field"),
    (re.compile(r'({token})\s*[:=]'),                                                                          "assignment"),
    (re.compile(r'["\']({token})["\']'),                                                                       "dict_key"),
    (re.compile(r'def\s+\w+\s*\([^)]*\b({token})\b'),                                                         "param"),
    (re.compile(r'function\s+\w+\s*\([^)]*\b({token})\b'),                                                    "param"),
    (re.compile(r'\b({token})\b[^)]*\)'),                                                                      "call_arg"),
    (re.compile(r'Column\s*\(\s*["\']({token})["\']'),                                                        "column_def"),
    (re.compile(r'@\w*[Cc]olumn[^)]*\({token}\)'),                                                            "column_def"),
]


# ---------------------------------------------------------------------------
# Framework detection
# ---------------------------------------------------------------------------

_FRAMEWORK_SIGNATURES: list[dict] = [
    {
        "name": "FastAPI",
        "language": "python",
        "patterns": [
            re.compile(r'from\s+fastapi\b'),
            re.compile(r'import\s+fastapi\b'),
            re.compile(r'FastAPI\s*\('),
            re.compile(r'@(?:app|router)\.(get|post|put|delete|patch)\s*\('),
            re.compile(r'APIRouter\s*\('),
        ],
        "weight": 1.0,
    },
    {
        "name": "Flask",
        "language": "python",
        "patterns": [
            re.compile(r'from\s+flask\b'),
            re.compile(r'import\s+flask\b'),
            re.compile(r'Flask\s*\(__name__\)'),
            re.compile(r'@app\.route\s*\('),
            re.compile(r'@bp\.route\s*\('),
        ],
        "weight": 1.0,
    },
    {
        "name": "Django",
        "language": "python",
        "patterns": [
            re.compile(r'from\s+django\b'),
            re.compile(r'import\s+django\b'),
            re.compile(r'from\s+django\.db\s+import'),
            re.compile(r'urlpatterns\s*='),
            re.compile(r'from\s+rest_framework\b'),
        ],
        "weight": 1.0,
    },
    {
        "name": "Spring",
        "language": "java",
        "patterns": [
            re.compile(r'import\s+org\.springframework\b'),
            re.compile(r'@RestController\b'),
            re.compile(r'@SpringBootApplication\b'),
            re.compile(r'@RequestMapping\s*\('),
            re.compile(r'@GetMapping|@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping'),
            re.compile(r'@Autowired\b'),
            re.compile(r'@Service\b|@Repository\b|@Component\b'),
        ],
        "weight": 1.0,
    },
    {
        "name": "Express",
        "language": "javascript",
        "patterns": [
            re.compile(r"require\s*\(\s*['\"]express['\"]\s*\)"),
            re.compile(r"from\s+['\"]express['\"]"),
            re.compile(r'(?:app|router)\.(get|post|put|delete|patch)\s*\('),
            re.compile(r'express\.Router\s*\('),
            re.compile(r'res\.json\s*\(|res\.send\s*\(|res\.status\s*\('),
        ],
        "weight": 1.0,
    },
    {
        "name": "NestJS",
        "language": "typescript",
        "patterns": [
            re.compile(r"from\s+['\"]@nestjs/"),
            re.compile(r'@Controller\s*\('),
            re.compile(r'@Injectable\s*\(\s*\)'),
            re.compile(r'@Get\s*\(|@Post\s*\(|@Put\s*\(|@Delete\s*\('),
            re.compile(r'@Module\s*\('),
        ],
        "weight": 1.0,
    },
    {
        "name": "Rails",
        "language": "ruby",
        "patterns": [
            re.compile(r'class\s+\w+\s*<\s*ApplicationController'),
            re.compile(r'class\s+\w+\s*<\s*ActionController::Base'),
            re.compile(r'before_action\s+:'),
            re.compile(r'resources?\s+:\w+'),
            re.compile(r'ActiveRecord::Base'),
        ],
        "weight": 1.0,
    },
]


# ---------------------------------------------------------------------------
# Endpoint detection
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERNS: list[tuple[re.Pattern, str]] = [
    # FastAPI / Flask style
    (re.compile(r'@(?:app|router|bp)\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']'), "decorator"),
    # Spring MVC
    (re.compile(r'@(?:Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']'), "spring_method_mapping"),
    (re.compile(r'@RequestMapping\s*\([^)]*["\']([^"\']+)["\']'), "spring_request_mapping"),
    # Express
    (re.compile(r'(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']'), "express_route"),
    # NestJS
    (re.compile(r'@(?:Get|Post|Put|Patch|Delete)\s*\(\s*["\']([^"\']+)["\']'), "nest_decorator"),
]

# Auth decorators / middleware that indicate endpoint protection level
_AUTH_PROTECTED_RE = re.compile(
    r'@(?:login_required|require_login|authenticated|jwt_required|'
    r'token_required|Secured|PreAuthorize|RolesAllowed|'
    r'UseGuards|AuthGuard|permission_required)\b'
    r'|requireAuth\s*\('
    r'|passport\.authenticate\s*\('
    r'|verifyToken\s*\('
    r'|authenticate\s*\(',
    re.IGNORECASE,
)
_AUTH_ADMIN_RE = re.compile(
    r"hasRole\(['\"]ADMIN|@AdminOnly|role.*admin|isAdmin|require_role.*admin",
    re.IGNORECASE,
)
_AUTH_JWT_RE = re.compile(r'jwt|bearer|JWTAuth|jwt_required', re.IGNORECASE)
_AUTH_SESSION_RE = re.compile(r'session|login_required|@authenticated', re.IGNORECASE)
_AUTH_APIKEY_RE = re.compile(r'api_key|ApiKey|x-api-key|X-API-Key', re.IGNORECASE)
_AUTH_OAUTH_RE = re.compile(r'oauth|OAuth|@OAuthToken', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Outbound HTTP/HTTPS call detection
# ---------------------------------------------------------------------------

_HTTP_URL_RE = re.compile(r'["\']?(https?://[^\s"\'<>)\]]+)["\']?')

_CALL_SITE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\brequests\.(get|post|put|patch|delete|head|options)\s*\('), "requests"),
    (re.compile(r'\bhttpx\.(get|post|put|patch|delete|head)\s*\('),            "httpx"),
    (re.compile(r'\burllib\.request\b|\burllib2\b'),                           "urllib"),
    (re.compile(r'\bfetch\s*\('),                                              "fetch"),
    (re.compile(r'\baxios\.(get|post|put|patch|delete)\s*\('),                "axios"),
    (re.compile(r'\bRestTemplate\b'),                                          "RestTemplate"),
    (re.compile(r'\bWebClient\b'),                                             "WebClient"),
    (re.compile(r'\bHttpClient\b|\bHttpClientBuilder\b'),                      "HttpClient"),
    (re.compile(r'\bgot\.(get|post|put|patch|delete)\s*\('),                  "got"),
    (re.compile(r'\bsuperagent\b'),                                            "superagent"),
    (re.compile(r'\bnet/http\b|http\.Get\s*\(|http\.Post\s*\('),              "go_http"),
]


# ---------------------------------------------------------------------------
# MiCA-specific compiled patterns (used by _derive_mica_indicators)
# ---------------------------------------------------------------------------

# walletService.send() or walletService.transfer() — the transfer call site
_WALLET_SEND_RE = re.compile(
    r'walletService\s*\.\s*(?:send|transfer)\s*\(',
    re.IGNORECASE,
)

# KYC / identity verification calls: verifyIdentity, kycCheck, identityVerified,
# verifyKYC, kycPassed, checkIdentity
_KYC_CHECK_RE = re.compile(
    r'\b(?:verifyIdentity|kycCheck|identityVerif|verifyKYC|kycPassed|checkIdentity'
    r'|kyc_check|kyc_verified|identity_check)\s*[\(\.]',
    re.IGNORECASE,
)

# Originator info fields required by the travel rule
_ORIGINATOR_RE = re.compile(
    r'\b(?:originator|originatorName|originator_name|originatorAccount'
    r'|originator_account|beneficiaryName|beneficiary_name|travelRule'
    r'|travel_rule|senderInfo|sender_info)\b',
    re.IGNORECASE,
)

# Audit / logging calls
_AUDIT_LOG_RE = re.compile(
    r'\b(?:audit(?:Log|log|Trail|trail|Event|event)?'
    r'|log(?:ger)?\.(?:info|warn|error|debug|audit)'
    r'|AuditService|auditService|emitEvent|emit_event)\s*[\(\.]',
    re.IGNORECASE,
)

# Numeric literal > 1000 (covers 1001, 5000, 10000, 1_000_000 …)
_LARGE_AMOUNT_RE = re.compile(r'\b([1-9]\d{3,})\b')


def _derive_mica_indicators(code: str, hint: ContextHint) -> list[str]:
    """Return MiCA-specific risk indicators derived from full-file analysis.

    Checks performed:
      missing_kyc_check      — walletService.send() present but no KYC call
      travel_rule_threshold  — amount field with literal > 1000 and no originator info
      missing_audit_log      — walletService.send() present but no audit/log call
      duplicate_transfer     — walletService.send() called more than once
    """
    indicators: list[str] = []

    send_calls = _WALLET_SEND_RE.findall(code)
    if not send_calls:
        return indicators  # no transfer calls → none of the four apply

    # missing_kyc_check: transfer present, no KYC verification anywhere in file
    if not _KYC_CHECK_RE.search(code):
        indicators.append("missing_kyc_check")

    # missing_audit_log: transfer present, no audit/log call anywhere in file
    if not _AUDIT_LOG_RE.search(code):
        indicators.append("missing_audit_log")

    # duplicate_transfer: walletService.send() called more than once
    if len(send_calls) > 1:
        indicators.append("duplicate_transfer")

    # travel_rule_threshold: amount field present with a value > 1000
    #   AND no originator/travel-rule info in scope
    has_amount = any(
        f.name == "transfer_amount" for f in hint.sensitive_fields
    )
    if has_amount:
        large = _LARGE_AMOUNT_RE.search(code)
        if large and not _ORIGINATOR_RE.search(code):
            indicators.append("travel_rule_threshold")

    return indicators


# ---------------------------------------------------------------------------
# Risk indicator derivation
# ---------------------------------------------------------------------------

def _derive_risk_indicators(hint: ContextHint) -> list[str]:
    indicators: list[str] = []

    # Unencrypted outbound calls
    http_calls = [c for c in hint.outbound_calls if c.protocol == "http"]
    if http_calls:
        indicators.append("unencrypted_http_outbound")

    # Financial fields present → PCI scope likely
    financial = [f for f in hint.sensitive_fields if f.category == "financial"]
    if financial:
        indicators.append("cardholder_data_in_scope")

    # CVV specifically mentioned
    cvv_fields = [f for f in hint.sensitive_fields if f.name == "cvv"]
    if cvv_fields:
        indicators.append("sad_cvv_present")

    # Auth credentials
    auth_fields = [f for f in hint.sensitive_fields if f.category == "auth"]
    if auth_fields:
        indicators.append("auth_credentials_in_scope")

    # PII fields
    pii_fields = [f for f in hint.sensitive_fields if f.category == "pii"]
    if pii_fields:
        indicators.append("personal_data_in_scope")

    # Public endpoint with sensitive fields
    public_endpoints = [e for e in hint.endpoints if e.visibility == "public"]
    if public_endpoints and (financial or pii_fields or auth_fields):
        indicators.append("sensitive_fields_on_public_endpoint")

    # Fields found in log calls
    logged = [f for f in hint.sensitive_fields if f.context == "log_call"]
    if logged:
        indicators.append("sensitive_data_in_log_call")

    # Both HTTP and HTTPS mixed in the same file
    protocols = {c.protocol for c in hint.outbound_calls}
    if "http" in protocols and "https" in protocols:
        indicators.append("mixed_http_https_outbound")

    # Password-like field names
    pwd_fields = [f for f in hint.sensitive_fields if f.name == "password"]
    if pwd_fields:
        indicators.append("password_field_present")

    # Crypto address fields (MiCA Art.68/70)
    crypto_addr = [f for f in hint.sensitive_fields if f.category == "crypto_address"]
    if crypto_addr:
        indicators.append("crypto_address_in_scope")

    return indicators


def _derive_risk_indicators_full(code: str, hint: ContextHint) -> list[str]:
    """Extend base indicators with MiCA-specific checks that need the full source."""
    base = _derive_risk_indicators(hint)
    base.extend(_derive_mica_indicators(code, hint))
    return base


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(code: str, file_path: str = "") -> dict:
    """Scan *code* and return a ``context_hint`` dict.

    Args:
        code:       Raw source code as a string.
        file_path:  Optional file path hint used for language inference.

    Returns:
        A plain dict representation of :class:`ContextHint`.
    """
    lines = code.splitlines()
    hint = ContextHint(
        language=None,
        framework=None,
        framework_confidence=0.0,
        line_count=len(lines),
    )

    hint.language = _detect_language(code, file_path)
    hint.framework, hint.framework_confidence = _detect_framework(code)
    hint.sensitive_fields = _detect_sensitive_fields(lines)
    hint.endpoints = _detect_endpoints(lines)
    hint.outbound_calls = _detect_outbound_calls(lines)
    hint.risk_indicators = _derive_risk_indicators_full(code, hint)

    return hint.to_dict()


# ---------------------------------------------------------------------------
# Private detection helpers
# ---------------------------------------------------------------------------

def _detect_language(code: str, file_path: str) -> Optional[str]:
    """Infer language from file extension first, then code heuristics."""
    ext = Path(file_path).suffix.lower() if file_path else ""
    ext_map = {
        ".py": "python", ".java": "java", ".kt": "kotlin",
        ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
        ".tsx": "typescript", ".rb": "ruby", ".go": "go",
        ".cs": "csharp", ".php": "php",
    }
    if ext in ext_map:
        return ext_map[ext]

    # Heuristic fallback
    if re.search(r'\bdef\s+\w+\s*\(|import\s+\w+|from\s+\w+\s+import', code):
        return "python"
    if re.search(r'public\s+(class|interface|enum)\s+\w+', code):
        return "java"
    if re.search(r'(?:const|let|var)\s+\w+\s*=|=>|require\s*\(', code):
        return "javascript"
    if re.search(r'interface\s+\w+\s*\{|:\s*(?:string|number|boolean)\b', code):
        return "typescript"
    if re.search(r'class\s+\w+\s*<\s*\w+Controller|def\s+\w+\s*$', code, re.MULTILINE):
        return "ruby"
    return None


def _detect_framework(code: str) -> tuple[Optional[str], float]:
    """Return (framework_name, confidence) for the best matching framework."""
    best_name: Optional[str] = None
    best_score = 0.0

    for sig in _FRAMEWORK_SIGNATURES:
        hits = sum(1 for p in sig["patterns"] if p.search(code))
        if hits == 0:
            continue
        score = (hits / len(sig["patterns"])) * sig["weight"]
        if score > best_score:
            best_score = score
            best_name = sig["name"]

    confidence = min(round(best_score, 2), 1.0)
    return best_name, confidence


def _detect_sensitive_fields(lines: list[str]) -> list[SensitiveField]:
    """Find sensitive field references line-by-line."""
    found: list[SensitiveField] = []
    seen: set[tuple[str, int]] = set()  # (canonical, line) dedup

    for lineno, line in enumerate(lines, start=1):
        # Skip pure comment lines
        stripped = line.lstrip()
        if stripped.startswith(('#', '//', '*', '/*', '--')):
            continue

        for match in _SENSITIVE_FIELD_RE.finditer(line):
            raw_token = match.group(1)
            canonical, category = _VARIANT_TO_CANONICAL[raw_token]
            key = (canonical, lineno)
            if key in seen:
                continue
            seen.add(key)

            context = _classify_field_context(line, raw_token)
            found.append(SensitiveField(
                name=canonical,
                raw_token=raw_token,
                category=category,
                line=lineno,
                context=context,
            ))

    return found


def _classify_field_context(line: str, token: str) -> str:
    """Return the structural context for a field match in a line."""
    for pattern, ctx_name in _CONTEXT_PATTERNS:
        filled = re.compile(pattern.pattern.replace('{token}', re.escape(token)))
        if filled.search(line):
            return ctx_name
    return "reference"


def _detect_endpoints(lines: list[str]) -> list[Endpoint]:
    """Detect API endpoint definitions with their visibility."""
    endpoints: list[Endpoint] = []
    code_block = "\n".join(lines)

    # Scan line-by-line with a small look-behind window for auth decorators
    for lineno, line in enumerate(lines, start=1):
        for pattern, style in _ENDPOINT_PATTERNS:
            m = pattern.search(line)
            if not m:
                continue

            # Extract method and path based on capture groups
            if style == "decorator":
                method = m.group(1).upper()
                path = m.group(2)
            elif style == "spring_method_mapping":
                # @GetMapping("/path") — method encoded in annotation name
                annotation = re.search(r'@(Get|Post|Put|Patch|Delete)Mapping', line, re.IGNORECASE)
                method = annotation.group(1).upper() if annotation else "*"
                path = m.group(1)
            elif style == "spring_request_mapping":
                method_search = re.search(r'method\s*=\s*RequestMethod\.(\w+)', line)
                method = method_search.group(1).upper() if method_search else "*"
                path = m.group(1)
            elif style == "express_route":
                method = m.group(1).upper()
                path = m.group(2)
            elif style == "nest_decorator":
                annotation = re.search(r'@(Get|Post|Put|Patch|Delete)\s*\(', line, re.IGNORECASE)
                method = annotation.group(1).upper() if annotation else "*"
                path = m.group(1)
            else:
                method = "*"
                path = m.group(1) if m.lastindex >= 1 else ""

            # Look at the 10 lines above for auth context
            window_start = max(0, lineno - 11)
            window = "\n".join(lines[window_start:lineno])

            if _AUTH_ADMIN_RE.search(window):
                visibility = "admin"
            elif _AUTH_PROTECTED_RE.search(window):
                visibility = "protected"
            else:
                visibility = "public"

            # Determine auth mechanism from the window
            if _AUTH_JWT_RE.search(window):
                auth_mechanism = "jwt"
            elif _AUTH_OAUTH_RE.search(window):
                auth_mechanism = "oauth"
            elif _AUTH_SESSION_RE.search(window):
                auth_mechanism = "session"
            elif _AUTH_APIKEY_RE.search(window):
                auth_mechanism = "api_key"
            elif visibility == "public":
                auth_mechanism = "none"
            else:
                auth_mechanism = "unknown"

            endpoints.append(Endpoint(
                method=method,
                path=path,
                visibility=visibility,
                auth_mechanism=auth_mechanism,
                line=lineno,
            ))
            break  # one match per line is sufficient

    return endpoints


def _detect_outbound_calls(lines: list[str]) -> list[OutboundCall]:
    """Detect outbound HTTP/HTTPS calls and classify their protocol."""
    calls: list[OutboundCall] = []

    for lineno, line in enumerate(lines, start=1):
        url_match = _HTTP_URL_RE.search(line)
        if not url_match:
            continue

        url = url_match.group(1).rstrip('.,;)')
        protocol = "https" if url.startswith("https://") else "http"

        # Identify the HTTP client library
        call_site = "unknown"
        for pattern, name in _CALL_SITE_PATTERNS:
            if pattern.search(line):
                call_site = name
                break

        calls.append(OutboundCall(
            url=url,
            protocol=protocol,
            line=lineno,
            call_site=call_site,
        ))

    return calls


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json, sys, textwrap

    _SAMPLE = textwrap.dedent("""\
        from fastapi import FastAPI, Depends
        from fastapi.security import OAuth2PasswordBearer

        app = FastAPI()
        oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

        @app.post("/api/v1/payments")
        def create_payment(card_number: str, cvv: str, email: str):
            import requests
            response = requests.post("http://payment-processor.internal/charge",
                                     json={"pan": card_number, "cvv": cvv})
            print(f"Processing payment for {email}, card: {card_number}")
            return response.json()

        @app.get("/api/v1/users/{user_id}")
        def get_user(user_id: str, token: str = Depends(oauth2_scheme)):
            pass
    """)

    sample_code = sys.stdin.read() if not sys.stdin.isatty() else _SAMPLE
    result = scan(sample_code, file_path="payments.py")
    print(json.dumps(result, indent=2))
