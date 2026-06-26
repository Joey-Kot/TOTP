package main

import (
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPBKDF2WerkzeugHash(t *testing.T) {
	key := pbkdf2Key([]byte("secret"), []byte("salt"), 1000, sha256.Size, sha256.New)
	stored := "pbkdf2:sha256:1000$salt$" + hex.EncodeToString(key)

	if !checkPasswordHash(stored, "secret") {
		t.Fatal("expected password to verify")
	}
	if checkPasswordHash(stored, "wrong") {
		t.Fatal("expected wrong password to fail")
	}
}

func TestTOTP(t *testing.T) {
	secret := "12345678901234567890"
	encoded := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Unix(59, 0)

	if got := totpCode([]byte(secret), uint64(now.Unix()/30), 8); got != "94287082" {
		t.Fatalf("totp code = %s", got)
	}
	if !verifyTOTP(encoded, "287082", now, 0) {
		t.Fatal("expected 6 digit totp to verify")
	}
}

func TestTOTPReplayCacheRejectsSameCounterReuse(t *testing.T) {
	secret := "12345678901234567890"
	encoded := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Unix(59, 0)
	var replay totpReplayCache

	code := totpCode([]byte(secret), uint64(now.Unix()/30), 6)
	if !replay.verifyAndConsume(encoded, code, now, 1) {
		t.Fatal("expected first totp use to verify")
	}
	if replay.verifyAndConsume(encoded, code, now, 1) {
		t.Fatal("expected repeated totp use in same counter to fail")
	}
	if replay.verifyAndConsume(encoded, code, now.Add(30*time.Second), 1) {
		t.Fatal("expected repeated totp use to fail while still inside validation window")
	}

	nextCode := totpCode([]byte(secret), uint64(now.Add(30*time.Second).Unix()/30), 6)
	if !replay.verifyAndConsume(encoded, nextCode, now.Add(30*time.Second), 1) {
		t.Fatal("expected next counter totp to verify")
	}
}

func TestLoginWrongPasswordDoesNotConsumeTOTP(t *testing.T) {
	secret := "12345678901234567890"
	encoded := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	key := pbkdf2Key([]byte("correct"), []byte("salt"), 1000, sha256.Size, sha256.New)
	s := server{
		cfg: config{
			Username:        "alice",
			PasswordHash:    "pbkdf2:sha256:1000$salt$" + hex.EncodeToString(key),
			TOTPSecret:      encoded,
			CookieSecret:    "0123456789abcdef0123456789abcdef",
			CookieMaxAge:    time.Hour,
			DefaultRedirect: "/",
		},
		tpl:     template.Must(template.New("login").Parse(loginHTML)),
		limiter: newLoginLimiter(0, time.Minute),
	}
	code := totpCode([]byte(secret), uint64(time.Now().Unix()/30), 6)

	wrong := httptest.NewRecorder()
	s.login(wrong, loginRequest("alice", "wrong", code))
	if wrong.Code != http.StatusOK {
		t.Fatalf("wrong password response = %d, want %d", wrong.Code, http.StatusOK)
	}

	correct := httptest.NewRecorder()
	s.login(correct, loginRequest("alice", "correct", code))
	if correct.Code != http.StatusFound {
		t.Fatalf("correct password response = %d, want %d", correct.Code, http.StatusFound)
	}
}

func TestTokenRoundTrip(t *testing.T) {
	s := server{cfg: config{
		Username:     "alice",
		CookieSecret: "cookie-secret",
		CookieMaxAge: time.Hour,
	}}

	token := s.makeToken("alice")
	if !s.verifyToken(token) {
		t.Fatal("expected token to verify")
	}
	if s.verifyToken(token + "x") {
		t.Fatal("expected tampered token to fail")
	}
}

func TestTokenRoundTripOnlyTOTP(t *testing.T) {
	s := server{cfg: config{
		OnlyTOTP:     true,
		CookieSecret: "cookie-secret",
		CookieMaxAge: time.Hour,
	}}

	token := s.makeToken(s.authSubject())
	if !s.verifyToken(token) {
		t.Fatal("expected only-totp token to verify")
	}
}

func TestLoadConfigOnlyTOTPDoesNotRequirePassword(t *testing.T) {
	t.Setenv("AUTH_USERNAME", "")
	t.Setenv("AUTH_PASSWORD_HASH", "")
	t.Setenv("TOTP_SECRET", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	t.Setenv("COOKIE_SECRET", "0123456789abcdef0123456789abcdef")

	cfg, err := loadConfig([]string{"--only-totp"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.OnlyTOTP {
		t.Fatal("expected only-totp config")
	}
}

func TestLoadConfigRequiresPasswordByDefault(t *testing.T) {
	t.Setenv("AUTH_USERNAME", "")
	t.Setenv("AUTH_PASSWORD_HASH", "")
	t.Setenv("TOTP_SECRET", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	t.Setenv("COOKIE_SECRET", "0123456789abcdef0123456789abcdef")

	if _, err := loadConfig(nil); err == nil {
		t.Fatal("expected missing username and password hash to fail")
	}
}

func TestOTPAuthURL(t *testing.T) {
	got := otpAuthURL("izual.site", "admin@example.com", "ABCDEF123456")
	want := "otpauth://totp/izual.site:admin@example.com?algorithm=SHA1&digits=6&issuer=izual.site&period=30&secret=ABCDEF123456"
	if got != want {
		t.Fatalf("otpAuthURL = %q, want %q", got, want)
	}
}

func TestRandomTOTPSecret(t *testing.T) {
	secret, err := randomTOTPSecret(20)
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" {
		t.Fatal("expected secret")
	}
	if _, err := decodeBase32Secret(secret); err != nil {
		t.Fatalf("expected valid base32 secret: %v", err)
	}
}

func TestSafeRedirect(t *testing.T) {
	s := server{cfg: config{
		DefaultRedirect: "https://chat.izual.site:11006/",
		RedirectHosts:   []string{"admin.izual.site", ".trusted.example"},
	}}
	r := &http.Request{Host: "chat.izual.site:11006"}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "relative path", in: "/room?a=1", want: "/room?a=1"},
		{name: "current host", in: "https://chat.izual.site:11006/room", want: "https://chat.izual.site:11006/room"},
		{name: "default host", in: "https://chat.izual.site/profile", want: "https://chat.izual.site/profile"},
		{name: "extra host", in: "https://admin.izual.site/", want: "https://admin.izual.site/"},
		{name: "suffix host", in: "https://app.trusted.example/", want: "https://app.trusted.example/"},
		{name: "external host", in: "https://evil.example/", want: "https://chat.izual.site:11006/"},
		{name: "http current host", in: "http://chat.izual.site:11006/room", want: "https://chat.izual.site:11006/"},
		{name: "http loopback not otherwise allowed", in: "http://127.0.0.1:9092/room", want: "https://chat.izual.site:11006/"},
		{name: "scheme relative", in: "//evil.example/", want: "https://chat.izual.site:11006/"},
		{name: "javascript", in: "javascript:alert(1)", want: "https://chat.izual.site:11006/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.safeRedirect(tt.in, r); got != tt.want {
				t.Fatalf("safeRedirect(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	local := &http.Request{Host: "127.0.0.1:9092"}
	localServer := server{cfg: config{DefaultRedirect: "/"}}
	if got := localServer.safeRedirect("http://127.0.0.1:9092/room", local); got != "http://127.0.0.1:9092/room" {
		t.Fatalf("local safeRedirect = %q", got)
	}
}

func TestLoginLimiter(t *testing.T) {
	limiter := newLoginLimiter(2, time.Minute)
	now := time.Unix(1000, 0)

	if !limiter.allow("ip", now) {
		t.Fatal("first attempt should be allowed")
	}
	limiter.recordFailure("ip", now)
	if !limiter.allow("ip", now) {
		t.Fatal("second attempt should be allowed")
	}
	limiter.recordFailure("ip", now)
	if limiter.allow("ip", now) {
		t.Fatal("third attempt should be blocked")
	}
	if !limiter.allow("ip", now.Add(time.Minute)) {
		t.Fatal("attempt after window should be allowed")
	}
}

func loginRequest(username, password, code string) *http.Request {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("code", code)
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.0.2.1:12345"
	return r
}
