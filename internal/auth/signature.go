package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Credentials holds AWS-style credentials
type Credentials struct {
	AccessKey string
	SecretKey string
	Region    string
}

// SignatureV4 handles AWS Signature Version 4 authentication
type SignatureV4 struct {
	creds Credentials
}

// NewSignatureV4 creates a new signature validator
func NewSignatureV4(accessKey, secretKey, region string) *SignatureV4 {
	return &SignatureV4{
		creds: Credentials{
			AccessKey: accessKey,
			SecretKey: secretKey,
			Region:    region,
		},
	}
}

// authHeader represents parsed Authorization header
type authHeader struct {
	Algorithm     string
	Credential    string
	SignedHeaders []string
	Signature     string
	AccessKey     string
	Date          string
	Region        string
	Service       string
}

var authHeaderRegex = regexp.MustCompile(`AWS4-HMAC-SHA256\s+Credential=([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=([a-f0-9]+)`)

// ValidateRequest validates an incoming HTTP request's AWS Signature V4
func (s *SignatureV4) ValidateRequest(r *http.Request) error {
	authHeaderValue := r.Header.Get("Authorization")
	if authHeaderValue == "" {
		return fmt.Errorf("missing Authorization header")
	}

	auth, err := parseAuthHeader(authHeaderValue)
	if err != nil {
		return fmt.Errorf("invalid Authorization header: %w", err)
	}

	// Verify access key matches
	if auth.AccessKey != s.creds.AccessKey {
		return fmt.Errorf("invalid access key")
	}

	// Get the request date
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		return fmt.Errorf("missing X-Amz-Date header")
	}

	// Parse the date and check if it's within acceptable range (15 minutes)
	requestTime, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return fmt.Errorf("invalid X-Amz-Date format: %w", err)
	}

	timeDiff := time.Since(requestTime)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > 15*time.Minute {
		return fmt.Errorf("request timestamp too old or too far in future")
	}

	// Calculate the expected signature
	expectedSig := s.calculateSignature(r, auth, amzDate)

	// Compare signatures
	if !hmac.Equal([]byte(auth.Signature), []byte(expectedSig)) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}

// parseAuthHeader parses the AWS4-HMAC-SHA256 Authorization header
func parseAuthHeader(header string) (*authHeader, error) {
	matches := authHeaderRegex.FindStringSubmatch(header)
	if len(matches) != 4 {
		return nil, fmt.Errorf("malformed authorization header")
	}

	credential := matches[1]
	signedHeaders := strings.Split(matches[2], ";")
	signature := matches[3]

	// Parse credential: AccessKey/Date/Region/Service/aws4_request
	credParts := strings.Split(credential, "/")
	if len(credParts) != 5 {
		return nil, fmt.Errorf("invalid credential format")
	}

	return &authHeader{
		Algorithm:     "AWS4-HMAC-SHA256",
		Credential:    credential,
		SignedHeaders: signedHeaders,
		Signature:     signature,
		AccessKey:     credParts[0],
		Date:          credParts[1],
		Region:        credParts[2],
		Service:       credParts[3],
	}, nil
}

// calculateSignature computes the expected AWS Signature V4
func (s *SignatureV4) calculateSignature(r *http.Request, auth *authHeader, amzDate string) string {
	// Step 1: Create canonical request
	canonicalRequest := s.createCanonicalRequest(r, auth.SignedHeaders)

	// Step 2: Create string to sign
	dateStamp := amzDate[:8] // YYYYMMDD
	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, s.creds.Region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		scope,
		hashSHA256(canonicalRequest),
	)

	// Step 3: Calculate signature
	signingKey := s.deriveSigningKey(dateStamp)
	signature := hmacSHA256(signingKey, stringToSign)

	return hex.EncodeToString(signature)
}

// createCanonicalRequest creates the canonical request string
func (s *SignatureV4) createCanonicalRequest(r *http.Request, signedHeaders []string) string {
	// HTTP method
	method := r.Method

	// Canonical URI (URL-encoded path)
	// Use RawPath if available (preserves encoding), otherwise encode the path
	canonicalURI := r.URL.RawPath
	if canonicalURI == "" {
		canonicalURI = r.URL.Path
		if canonicalURI == "" {
			canonicalURI = "/"
		} else {
			// URI-encode the path segments
			canonicalURI = uriEncodePath(canonicalURI)
		}
	}

	// Canonical query string
	canonicalQueryString := s.createCanonicalQueryString(r.URL.Query())

	// Canonical headers
	canonicalHeaders := s.createCanonicalHeaders(r, signedHeaders)

	// Signed headers (lowercase, sorted, semicolon-separated)
	signedHeadersStr := strings.Join(signedHeaders, ";")

	// Hashed payload
	hashedPayload := r.Header.Get("X-Amz-Content-Sha256")
	if hashedPayload == "" {
		hashedPayload = "UNSIGNED-PAYLOAD"
	}

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeadersStr,
		hashedPayload,
	)
}

// createCanonicalQueryString creates the canonical query string
func (s *SignatureV4) createCanonicalQueryString(query url.Values) string {
	if len(query) == 0 {
		return ""
	}

	// Sort parameter names
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build canonical query string
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		values := query[k]
		sort.Strings(values)
		for _, v := range values {
			pairs = append(pairs, fmt.Sprintf("%s=%s",
				url.QueryEscape(k),
				url.QueryEscape(v),
			))
		}
	}

	return strings.Join(pairs, "&")
}

// createCanonicalHeaders creates the canonical headers string
func (s *SignatureV4) createCanonicalHeaders(r *http.Request, signedHeaders []string) string {
	headers := make([]string, 0, len(signedHeaders))

	for _, h := range signedHeaders {
		var value string
		if h == "host" {
			value = r.Host
		} else {
			value = r.Header.Get(h)
		}
		// Trim and collapse whitespace
		value = strings.TrimSpace(value)
		headers = append(headers, fmt.Sprintf("%s:%s\n", h, value))
	}

	return strings.Join(headers, "")
}

// deriveSigningKey derives the signing key for AWS Signature V4
func (s *SignatureV4) deriveSigningKey(dateStamp string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+s.creds.SecretKey), dateStamp)
	kRegion := hmacSHA256(kDate, s.creds.Region)
	kService := hmacSHA256(kRegion, "s3")
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

// hmacSHA256 computes HMAC-SHA256
func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// hashSHA256 computes SHA256 hash and returns hex string
func hashSHA256(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// IsPresignedRequest returns true if the request uses pre-signed URL authentication
// (query parameters instead of Authorization header).
func IsPresignedRequest(r *http.Request) bool {
	return r.URL.Query().Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256"
}

// ValidatePresignedURL validates an AWS pre-signed URL request.
// Auth parameters are carried in query params (X-Amz-Algorithm, X-Amz-Credential,
// X-Amz-Date, X-Amz-Expires, X-Amz-SignedHeaders, X-Amz-Signature).
func (s *SignatureV4) ValidatePresignedURL(r *http.Request) error {
	q := r.URL.Query()

	credential := q.Get("X-Amz-Credential")
	amzDate := q.Get("X-Amz-Date")
	expiresStr := q.Get("X-Amz-Expires")
	signedHeadersParam := q.Get("X-Amz-SignedHeaders")
	signature := q.Get("X-Amz-Signature")

	if credential == "" || amzDate == "" || expiresStr == "" || signedHeadersParam == "" || signature == "" {
		return fmt.Errorf("missing required pre-signed URL parameters")
	}

	// Parse and validate credential
	credParts := strings.Split(credential, "/")
	if len(credParts) != 5 {
		return fmt.Errorf("invalid credential format")
	}
	if credParts[0] != s.creds.AccessKey {
		return fmt.Errorf("invalid access key")
	}

	// Parse request time
	requestTime, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return fmt.Errorf("invalid X-Amz-Date format: %w", err)
	}

	// Parse and check expiry
	expires, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid X-Amz-Expires: %w", err)
	}
	if time.Now().After(requestTime.Add(time.Duration(expires) * time.Second)) {
		return fmt.Errorf("pre-signed URL has expired")
	}

	// Compute and compare signature
	signedHeaders := strings.Split(signedHeadersParam, ";")
	expectedSig := s.calculatePresignedSignature(r, signedHeaders, amzDate)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}

// calculatePresignedSignature computes the expected signature for a pre-signed URL.
func (s *SignatureV4) calculatePresignedSignature(r *http.Request, signedHeaders []string, amzDate string) string {
	canonicalRequest := s.createPresignedCanonicalRequest(r, signedHeaders)

	dateStamp := amzDate[:8]
	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, s.creds.Region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		scope,
		hashSHA256(canonicalRequest),
	)

	signingKey := s.deriveSigningKey(dateStamp)
	return hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
}

// createPresignedCanonicalRequest builds the canonical request for a pre-signed URL.
// X-Amz-Signature is excluded from the query string, and the payload hash is
// always UNSIGNED-PAYLOAD (pre-signed URLs do not sign the body).
func (s *SignatureV4) createPresignedCanonicalRequest(r *http.Request, signedHeaders []string) string {
	canonicalURI := r.URL.RawPath
	if canonicalURI == "" {
		canonicalURI = r.URL.Path
		if canonicalURI == "" {
			canonicalURI = "/"
		} else {
			canonicalURI = uriEncodePath(canonicalURI)
		}
	}

	// Exclude X-Amz-Signature from the canonical query string
	query := r.URL.Query()
	delete(query, "X-Amz-Signature")
	canonicalQueryString := s.createCanonicalQueryString(query)

	canonicalHeaders := s.createCanonicalHeaders(r, signedHeaders)
	signedHeadersStr := strings.Join(signedHeaders, ";")

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		r.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeadersStr,
		"UNSIGNED-PAYLOAD",
	)
}

// uriEncodePath encodes a path according to AWS Signature V4 spec
// It encodes all characters except unreserved characters and forward slashes
func uriEncodePath(path string) string {
	var buf strings.Builder
	for _, r := range path {
		if isUnreserved(r) || r == '/' {
			buf.WriteRune(r)
		} else {
			// Percent-encode the character
			encoded := url.PathEscape(string(r))
			buf.WriteString(encoded)
		}
	}
	return buf.String()
}

// isUnreserved returns true if the rune is an unreserved character per RFC 3986
func isUnreserved(r rune) bool {
	return (r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '_' || r == '.' || r == '~'
}
