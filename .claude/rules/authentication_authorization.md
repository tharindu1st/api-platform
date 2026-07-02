# Go Authentication and Authorization Rules

Standards and patterns for ensuring secure authentication, authorization, token verification, and multi-tenant isolation across all Go services.

---

## GO-AUTH-001: Fail-Closed Authentication

### Severity

Critical

### Description

Authentication processes must always fail-closed. If an authentication check encounters an error, execution must terminate immediately, denying access to the resource.

### Rationale

Allowing execution to continue after an error, or failing to return early, can lead to authentication bypasses where unauthenticated requests are accidentally processed as valid.

### Non-Compliant Code

```go
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("Authorization")
        err := validateToken(token)
        if err != nil {
            // ERROR: Logs the error but falls through to the next handler
            log.Printf("auth failed: %v", err)
        }
        next.ServeHTTP(w, r)
    })
}

```

### Compliant Code

```go
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("Authorization")
        err := validateToken(token)
        if err != nil {
            log.Printf("auth failed: %v", err)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return // CORRECT: Execution terminates immediately
        }
        next.ServeHTTP(w, r)
    })
}

```
---

## GO-AUTH-002: Strict Asymmetric JWT Verification

### Severity

Critical

### Description

JWT signature verification must strictly enforce asymmetric algorithms (`RSA` or `EdDSA`). Symmetric algorithms (`HS256`, `HS384`, `HS512`) and the `none` algorithm must be explicitly rejected during signature validation.

### Rationale

If symmetric key algorithms are accepted by an asymmetric verification sequence, an attacker can sign a malicious JWT using the public key as a HMAC secret key, completely bypassing token signature verification.

### Non-Compliant Code

```go
// ERROR: Accepts any algorithm provided in the token header
token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
    return publicKey, nil 
})

```

### Compliant Code

```go
// CORRECT: Explicitly checks and restricts allowed signing methods
token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
    switch token.Method.(type) {
    case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodEd25519:
        return publicKey, nil
    default:
        return nil, fmt.Errorf("unexpected or forbidden signing method: %v", token.Header["alg"])
    }
})

```

---

## GO-AUTH-003: Secure Token Handling and Logging

### Severity

Medium

### Description

Raw authentication tokens, credentials, or secrets must never be written to application logs on failure. If part of a token is required for correlation or debugging, it must be masked to only show identifiers.

### Rationale

Logging raw tokens exposes sensitive credentials to log management platforms, increasing the surface area for account takeovers if log data is leaked or compromised.

### Non-Compliant Code

```go
// ERROR: Logging the full authentication token in plain text
if err != nil {
    log.Printf("failed to parse token %s: %v", r.Header.Get("Authorization"), err)
}

```

### Compliant Code

```go
// CORRECT: Masking the token before logging
func maskToken(token string) string {
    if len(token) <= 8 {
        return "[MASKED]"
    }
    return token[:4] + "..." + token[len(token)-4:]
}

if err != nil {
    masked := maskToken(r.Header.Get("Authorization"))
    log.Printf("failed to parse token %s: %v", masked, err)
}

```

---

## GO-AUTH-004: Routing and Path Traversal Protection

### Severity

High

### Description

Authentication and authorization layers must protect against routing anomalies. Applications must use clean paths to evaluate middleware execution, preventing attackers from bypassing auth controls via path traversal sequence tricks (`..`).

### Rationale

Attackers manipulate URLs (e.g., `//auth/../private`) to confuse naive path matching algorithms, tricking security layers into treating a restricted path as an unauthenticated/public path.

### Non-Compliant Code

```go
// ERROR: String prefix matching on raw path is vulnerable to bypasses
if strings.HasPrefix(r.URL.Path, "/public/") {
    next.ServeHTTP(w, r) // Bypasses auth checks
    return
}

```

### Compliant Code

```go
// CORRECT: Path sanitization and structured router group scoping
func NewRouter() http.Handler {
    mux := http.NewServeMux() // Go 1.22+ handles routing cleaning automatically
    
    // Explicit public routes
    mux.HandleFunc("GET /public/", publicHandler)
    
    // Explicitly protected sub-router or structured middleware chaining
    protectedMux := http.NewServeMux()
    protectedMux.HandleFunc("GET /private/", privateHandler)
    
    mux.Handle("/private/", AuthMiddleware(protectedMux))
    return mux
}

```

---

## GO-AUTH-005: Multi-Tenant Isolation (Anti-Privilege Escalation)

### Severity

Critical

### Description

Data queries and state mutations must enforce structural boundaries using multi-tenant context verification. User actions must be strictly constrained to their authorized `organization_id` or `tenant_id` pulled securely from the parsed token claims.

### Rationale

Relying strictly on an identifier provided directly in the request body or URL path parameters allows users to perform Cross-Organization Privilege Escalation by swapping resource IDs.

### Non-Compliant Code

```go
// ERROR: Trusting the organization ID from input without matching JWT identity
func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
    targetOrgID := r.URL.Query().Get("org_id") 
    userID := r.URL.Query().Get("user_id")
    
    db.Where("id = ? AND organization_id = ?", userID, targetOrgID).Delete(&User{})
}

```

### Compliant Code

```go
// CORRECT: Forcing database execution context to rely on JWT claims context
func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
    // Extracted safely inside AuthMiddleware and injected into Request Context
    ctxOrgID, ok := r.Context().Value(OrgIDContextKey).(string)
    if !ok || ctxOrgID == "" {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    
    userID := r.URL.Query().Get("user_id")
    
    // Query is strictly sandboxed inside the tenant domain checked by security token
    err := db.Where("id = ? AND organization_id = ?", userID, ctxOrgID).Delete(&User{}).Error
    if err != nil {
        http.Error(w, "Internal Error", http.StatusInternalServerError)
        return
    }
}

```