package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	defaultCookieName        = "izual_auth"
	defaultCookieAge         = 7 * 24 * time.Hour
	defaultListenAddr        = "127.0.0.1:9092"
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 10 * time.Second
	defaultWriteTimeout      = 10 * time.Second
	defaultIdleTimeout       = 60 * time.Second
)

type config struct {
	Username        string
	PasswordHash    string
	TOTPSecret      string
	CookieSecret    string
	CookieName      string
	CookieDomain    string
	CookieMaxAge    time.Duration
	ListenAddr      string
	DefaultRedirect string
	SecureCookie    bool
	OnlyTOTP        bool
	RedirectHosts   []string
	RateLimitMax    int
	RateLimitWindow time.Duration
}

type server struct {
	cfg        config
	tpl        *template.Template
	limiter    *loginLimiter
	totpReplay totpReplayCache
}

type tokenPayload struct {
	Username  string `json:"u"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type loginLimiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	entries map[string]loginAttempt
}

type loginAttempt struct {
	failures int
	first    time.Time
}

type totpReplayCache struct {
	mu       sync.Mutex
	counters map[int64]struct{}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		if err := runHashPassword(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 2 && os.Args[1] == "create" && os.Args[2] == "token" {
		if err := runCreateToken(os.Args[3:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfg, err := loadConfig(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	srv := &server{
		cfg:     cfg,
		tpl:     template.Must(template.New("login").Parse(loginHTML)),
		limiter: newLoginLimiter(cfg.RateLimitMax, cfg.RateLimitWindow),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/verify", srv.verify)
	mux.HandleFunc("/login", srv.login)
	mux.HandleFunc("/logout", srv.logout)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
	}

	log.Printf("totp-auth listening on http://%s", cfg.ListenAddr)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func loadConfig(args []string) (config, error) {
	var cfg config

	fs := flag.NewFlagSet("totp-auth", flag.ExitOnError)
	fs.StringVar(&cfg.ListenAddr, "listen", getenv("LISTEN_ADDR", defaultListenAddr), "listen address")
	fs.StringVar(&cfg.CookieName, "cookie-name", getenv("COOKIE_NAME", defaultCookieName), "auth cookie name")
	fs.StringVar(&cfg.CookieDomain, "cookie-domain", os.Getenv("COOKIE_DOMAIN"), "auth cookie domain")
	fs.DurationVar(&cfg.CookieMaxAge, "cookie-max-age", getDuration("COOKIE_MAX_AGE", defaultCookieAge), "auth cookie max age")
	fs.StringVar(&cfg.DefaultRedirect, "default-redirect", getenv("DEFAULT_REDIRECT", "/"), "redirect target when rd is absent")
	fs.BoolVar(&cfg.SecureCookie, "secure-cookie", getBool("SECURE_COOKIE", true), "mark auth cookie as Secure")
	fs.BoolVar(&cfg.OnlyTOTP, "only-totp", getBool("ONLY_TOTP", false), "only require TOTP code, without username and password")
	redirectHosts := fs.String("allowed-redirect-hosts", os.Getenv("ALLOWED_REDIRECT_HOSTS"), "comma-separated extra hosts allowed in rd redirects")
	fs.IntVar(&cfg.RateLimitMax, "login-rate-limit", getInt("LOGIN_RATE_LIMIT_ATTEMPTS", 5), "max failed login attempts per rate-limit window; 0 disables")
	fs.DurationVar(&cfg.RateLimitWindow, "login-rate-window", getDuration("LOGIN_RATE_LIMIT_WINDOW", 5*time.Minute), "failed login rate-limit window")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	cfg.Username = os.Getenv("AUTH_USERNAME")
	cfg.PasswordHash = os.Getenv("AUTH_PASSWORD_HASH")
	cfg.TOTPSecret = os.Getenv("TOTP_SECRET")
	cfg.CookieSecret = os.Getenv("COOKIE_SECRET")

	var missing []string
	for name, value := range map[string]string{
		"TOTP_SECRET":   cfg.TOTPSecret,
		"COOKIE_SECRET": cfg.CookieSecret,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if !cfg.OnlyTOTP {
		for name, value := range map[string]string{
			"AUTH_USERNAME":      cfg.Username,
			"AUTH_PASSWORD_HASH": cfg.PasswordHash,
		} {
			if value == "" {
				missing = append(missing, name)
			}
		}
	}
	if len(missing) > 0 {
		return cfg, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}
	if cfg.CookieMaxAge <= 0 {
		return cfg, errors.New("cookie max age must be positive")
	}
	if len(cfg.CookieSecret) < 32 {
		return cfg, errors.New("COOKIE_SECRET must be at least 32 characters")
	}
	totpKey, err := decodeBase32Secret(cfg.TOTPSecret)
	if err != nil {
		return cfg, errors.New("TOTP_SECRET must be valid base32")
	}
	if len(totpKey) < 10 {
		return cfg, errors.New("TOTP_SECRET must decode to at least 10 bytes")
	}
	if cfg.RateLimitMax < 0 {
		return cfg, errors.New("login rate limit must not be negative")
	}
	if cfg.RateLimitMax > 0 && cfg.RateLimitWindow <= 0 {
		return cfg, errors.New("login rate-limit window must be positive")
	}
	cfg.RedirectHosts = parseCSV(*redirectHosts)

	return cfg, nil
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	cookie, err := r.Cookie(s.cfg.CookieName)
	if err == nil && s.verifyToken(cookie.Value) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("OK"))
		return
	}

	originalURL := r.Header.Get("X-Original-URL")
	if originalURL == "" {
		originalURL = "/"
	}

	loginURL := "/login?rd=" + url.QueryEscape(originalURL)
	w.Header().Set("Location", loginURL)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	rd := r.URL.Query().Get("rd")
	if rd == "" {
		rd = s.cfg.DefaultRedirect
	}
	rd = s.safeRedirect(rd, r)

	data := struct {
		Title    string
		Error    string
		RD       string
		OnlyTOTP bool
	}{
		Title:    "Authentication",
		RD:       rd,
		OnlyTOTP: s.cfg.OnlyTOTP,
	}

	if r.Method == http.MethodPost {
		clientID := clientIP(r)
		if !s.limiter.allow(clientID, time.Now()) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		username := r.Form.Get("username")
		password := r.Form.Get("password")
		code := r.Form.Get("code")

		usernameOK := constantTimeStringEqual(username, s.cfg.Username)
		passwordOK := checkPasswordHash(s.cfg.PasswordHash, password) && usernameOK
		totpOK := false
		if s.cfg.OnlyTOTP || passwordOK {
			totpOK = s.totpReplay.verifyAndConsume(s.cfg.TOTPSecret, code, time.Now(), 1)
		}

		if (s.cfg.OnlyTOTP || passwordOK) && totpOK {
			s.limiter.reset(clientID)
			http.SetCookie(w, &http.Cookie{
				Name:     s.cfg.CookieName,
				Value:    s.makeToken(s.authSubject()),
				Path:     "/",
				Domain:   s.cfg.CookieDomain,
				MaxAge:   int(s.cfg.CookieMaxAge.Seconds()),
				Secure:   s.cfg.SecureCookie,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, rd, http.StatusFound)
			return
		}

		s.limiter.recordFailure(clientID, time.Now())
		if s.cfg.OnlyTOTP {
			data.Error = "TOTP 错误"
		} else {
			data.Error = "用户名、密码或 TOTP 错误"
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.Execute(w, data); err != nil {
		log.Printf("render login page: %v", err)
	}
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		MaxAge:   -1,
		Secure:   s.cfg.SecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *server) makeToken(username string) string {
	now := time.Now()
	payload := tokenPayload{
		Username:  username,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.cfg.CookieMaxAge).Unix(),
	}
	body, _ := json.Marshal(payload)
	bodyPart := base64.RawURLEncoding.EncodeToString(body)
	sig := sign([]byte(bodyPart), []byte(s.cfg.CookieSecret))
	return bodyPart + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (s *server) verifyToken(token string) bool {
	bodyPart, sigPart, ok := strings.Cut(token, ".")
	if !ok || bodyPart == "" || sigPart == "" {
		return false
	}

	wantSig := sign([]byte(bodyPart), []byte(s.cfg.CookieSecret))
	gotSig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil || hmac.Equal(gotSig, wantSig) == false {
		return false
	}

	body, err := base64.RawURLEncoding.DecodeString(bodyPart)
	if err != nil {
		return false
	}

	var payload tokenPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}

	now := time.Now().Unix()
	if payload.Username != s.authSubject() || payload.ExpiresAt < now {
		return false
	}
	if payload.IssuedAt > now+60 {
		return false
	}
	return true
}

func sign(message, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

func (s *server) authSubject() string {
	if s.cfg.OnlyTOTP {
		return "totp"
	}
	return s.cfg.Username
}

func verifyTOTP(secret, code string, now time.Time, validWindow int) bool {
	_, ok := matchingTOTPCounter(secret, code, now, validWindow)
	return ok
}

func matchingTOTPCounter(secret, code string, now time.Time, validWindow int) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return 0, false
		}
	}

	key, err := decodeBase32Secret(secret)
	if err != nil {
		return 0, false
	}

	counter := now.Unix() / 30
	for offset := -validWindow; offset <= validWindow; offset++ {
		candidate := counter + int64(offset)
		if candidate < 0 {
			continue
		}
		if totpCode(key, uint64(candidate), 6) == code {
			return candidate, true
		}
	}
	return 0, false
}

func (c *totpReplayCache) verifyAndConsume(secret, code string, now time.Time, validWindow int) bool {
	counter, ok := matchingTOTPCounter(secret, code, now, validWindow)
	if !ok {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	current := now.Unix() / 30
	c.pruneLocked(current, validWindow)
	if _, used := c.counters[counter]; used {
		return false
	}
	if c.counters == nil {
		c.counters = make(map[int64]struct{})
	}
	c.counters[counter] = struct{}{}
	return true
}

func (c *totpReplayCache) pruneLocked(current int64, validWindow int) {
	if len(c.counters) == 0 {
		return
	}
	oldestAccepted := current - int64(validWindow)
	for counter := range c.counters {
		if counter < oldestAccepted {
			delete(c.counters, counter)
		}
	}
}

func decodeBase32Secret(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if rem := len(cleaned) % 8; rem != 0 {
		cleaned += strings.Repeat("=", 8-rem)
	}
	return base32.StdEncoding.DecodeString(cleaned)
}

func totpCode(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

func checkPasswordHash(stored, password string) bool {
	method, salt, hashValue, ok := splitWerkzeugHash(stored)
	if !ok {
		return false
	}

	methodParts := strings.Split(method, ":")
	if len(methodParts) < 2 || methodParts[0] != "pbkdf2" {
		return false
	}

	hashName := methodParts[1]
	iterations := 1000000
	if len(methodParts) >= 3 {
		parsed, err := strconv.Atoi(methodParts[2])
		if err != nil || parsed <= 0 {
			return false
		}
		iterations = parsed
	}

	hashFunc, size, ok := passwordHash(hashName)
	if !ok {
		return false
	}

	got := pbkdf2Key([]byte(password), []byte(salt), iterations, size, hashFunc)
	want, err := hex.DecodeString(hashValue)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func splitWerkzeugHash(stored string) (method, salt, hashValue string, ok bool) {
	first := strings.IndexByte(stored, '$')
	last := strings.LastIndexByte(stored, '$')
	if first <= 0 || last <= first+1 || last == len(stored)-1 {
		return "", "", "", false
	}
	return stored[:first], stored[first+1 : last], stored[last+1:], true
}

func passwordHash(name string) (func() hash.Hash, int, bool) {
	switch strings.ToLower(name) {
	case "sha1":
		return sha1.New, sha1.Size, true
	case "sha256":
		return sha256.New, sha256.Size, true
	case "sha512":
		return sha512.New, sha512.Size, true
	default:
		return nil, 0, false
	}
}

func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	var block [4]byte

	for i := 1; i <= numBlocks; i++ {
		prf.Reset()
		_, _ = prf.Write(salt)
		binary.BigEndian.PutUint32(block[:], uint32(i))
		_, _ = prf.Write(block[:])
		u := prf.Sum(nil)

		t := make([]byte, len(u))
		copy(t, u)
		for j := 1; j < iter; j++ {
			prf.Reset()
			_, _ = prf.Write(u)
			u = prf.Sum(nil)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		dk = append(dk, t...)
	}

	return dk[:keyLen]
}

func runHashPassword(args []string) error {
	fs := flag.NewFlagSet("hash-password", flag.ExitOnError)
	iterations := fs.Int("iterations", 1000000, "PBKDF2 iterations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iterations <= 0 {
		return errors.New("iterations must be positive")
	}

	password := strings.Join(fs.Args(), " ")
	if password == "" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		password = strings.TrimRight(string(data), "\r\n")
	}
	if password == "" {
		return errors.New("password is required as an argument or stdin")
	}

	salt, err := randomSalt(16)
	if err != nil {
		return err
	}

	key := pbkdf2Key([]byte(password), []byte(salt), *iterations, sha256.Size, sha256.New)
	fmt.Printf("pbkdf2:sha256:%d$%s$%s\n", *iterations, salt, hex.EncodeToString(key))
	return nil
}

func randomSalt(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf), nil
}

func runCreateToken(args []string) error {
	fs := flag.NewFlagSet("create token", flag.ExitOnError)
	issuer := fs.String("issuer", getenv("TOTP_ISSUER", "totp-auth"), "TOTP issuer name")
	account := fs.String("account", getenv("AUTH_USERNAME", "admin"), "TOTP account name")
	secretBytes := fs.Int("secret-bytes", 20, "random secret size in bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *issuer == "" {
		return errors.New("issuer is required")
	}
	if *account == "" {
		return errors.New("account is required")
	}
	if *secretBytes < 10 {
		return errors.New("secret-bytes must be at least 10")
	}

	secret, err := randomTOTPSecret(*secretBytes)
	if err != nil {
		return err
	}

	fmt.Printf("TOTP_SECRET=%s\n", secret)
	fmt.Printf("otpauth_url=%s\n", otpAuthURL(*issuer, *account, secret))
	return nil
}

func (s *server) safeRedirect(candidate string, r *http.Request) string {
	if isAllowedRedirect(candidate, r.Host, s.cfg.DefaultRedirect, s.cfg.RedirectHosts) {
		return candidate
	}
	if isAllowedRedirect(s.cfg.DefaultRedirect, r.Host, "", s.cfg.RedirectHosts) {
		return s.cfg.DefaultRedirect
	}
	return "/"
}

func isAllowedRedirect(candidate, requestHost, defaultRedirect string, extraHosts []string) bool {
	if candidate == "" || strings.ContainsFunc(candidate, unicode.IsControl) {
		return false
	}
	if strings.HasPrefix(candidate, "/") && !strings.HasPrefix(candidate, "//") && !strings.HasPrefix(candidate, "/\\") {
		return true
	}

	u, err := url.Parse(candidate)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Host)) {
		return false
	}

	allowed := append([]string{requestHost}, extraHosts...)
	if defaultRedirect != "" {
		if defaultURL, err := url.Parse(defaultRedirect); err == nil && defaultURL.Host != "" {
			allowed = append(allowed, defaultURL.Host)
		}
	}
	return hostAllowed(u.Host, allowed)
}

func hostAllowed(candidate string, allowed []string) bool {
	candidateHost := normalizeHost(candidate)
	if candidateHost == "" {
		return false
	}
	for _, host := range allowed {
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" {
			continue
		}
		if strings.HasPrefix(host, ".") {
			suffix := strings.TrimPrefix(host, ".")
			if candidateHost != suffix && strings.HasSuffix(candidateHost, "."+suffix) {
				return true
			}
			continue
		}
		if candidateHost == normalizeHost(host) {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(strings.ToLower(parsedHost), "[]")
	}
	return strings.Trim(host, "[]")
}

func isLoopbackHost(host string) bool {
	host = normalizeHost(host)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{
		max:     max,
		window:  window,
		entries: make(map[string]loginAttempt),
	}
}

func (l *loginLimiter) allow(key string, now time.Time) bool {
	if l == nil || l.max <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok {
		return true
	}
	if now.Sub(entry.first) >= l.window {
		delete(l.entries, key)
		return true
	}
	return entry.failures < l.max
}

func (l *loginLimiter) recordFailure(key string, now time.Time) {
	if l == nil || l.max <= 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok || now.Sub(entry.first) >= l.window {
		l.entries[key] = loginAttempt{failures: 1, first: now}
		return
	}
	entry.failures++
	l.entries[key] = entry
}

func (l *loginLimiter) reset(key string) {
	if l == nil || l.max <= 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(host)
	if remoteIP != nil && remoteIP.IsLoopback() {
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			if parsed := net.ParseIP(realIP); parsed != nil {
				return parsed.String()
			}
		}
		if forwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwardedFor != "" {
			first, _, _ := strings.Cut(forwardedFor, ",")
			if parsed := net.ParseIP(strings.TrimSpace(first)); parsed != nil {
				return parsed.String()
			}
		}
	}
	if remoteIP != nil {
		return remoteIP.String()
	}
	return host
}

func randomTOTPSecret(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "="), nil
}

func otpAuthURL(issuer, account, secret string) string {
	label := issuer + ":" + account
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(label) + "?" + q.Encode()
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func getDuration(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func parseCSV(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func getBool(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

const loginHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f7f5;
      --panel: #ffffff;
      --text: #111111;
      --muted: #6f6f6f;
      --line: #d9d9d6;
      --line-strong: #9f9f9a;
      --danger: #b42318;
      --focus: #111111;
    }

    * {
      box-sizing: border-box;
    }

    html,
    body {
      min-height: 100%;
    }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 16px;
      line-height: 1.5;
    }

    main {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 32px 16px;
    }

    .panel {
      width: min(100%, 400px);
      padding: 32px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 18px 50px rgba(0, 0, 0, 0.08);
    }

    h1 {
      margin: 0 0 24px;
      font-size: 28px;
      font-weight: 600;
      line-height: 1.2;
    }

    form {
      display: grid;
      gap: 12px;
    }

    label {
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 14px;
    }

    input {
      width: 100%;
      min-height: 48px;
      padding: 12px 14px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #ffffff;
      color: var(--text);
      font: inherit;
      outline: none;
      transition: border-color 120ms ease, box-shadow 120ms ease;
    }

    input:focus {
      border-color: var(--focus);
      box-shadow: 0 0 0 3px rgba(17, 17, 17, 0.12);
    }

    input::placeholder {
      color: var(--line-strong);
    }

    button {
      width: 100%;
      min-height: 48px;
      margin-top: 4px;
      border: 0;
      border-radius: 6px;
      background: #111111;
      color: #ffffff;
      font: inherit;
      font-weight: 600;
      cursor: pointer;
      transition: background 120ms ease, transform 120ms ease;
    }

    button:hover {
      background: #2b2b2b;
    }

    button:active {
      transform: translateY(1px);
    }

    .error {
      min-height: 24px;
      margin: 16px 0 0;
      color: var(--danger);
      font-size: 14px;
    }

    @media (max-width: 480px) {
      main {
        align-items: start;
        padding-top: 48px;
      }

      .panel {
        padding: 24px;
      }

      h1 {
        font-size: 24px;
      }
    }
  </style>
</head>
<body>
  <main>
    <section class="panel" aria-labelledby="login-title">
      <h1 id="login-title">{{ .Title }}</h1>
      <form method="post" action="/login?rd={{ .RD | urlquery }}">
        {{ if not .OnlyTOTP }}
        <label>
          Username
          <input name="username" autocomplete="username">
        </label>
        <label>
          Password
          <input name="password" type="password" autocomplete="current-password">
        </label>
        {{ end }}
        <label>
          TOTP code
          <input name="code" inputmode="numeric" autocomplete="one-time-code" autofocus>
        </label>
        <button type="submit">Continue</button>
      </form>
      <div class="error" role="status" aria-live="polite">{{ .Error }}</div>
    </section>
  </main>
</body>
</html>
`
