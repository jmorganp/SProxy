package main

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/elazarl/goproxy"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
	"gopkg.in/yaml.v3"
)

type IPInfo struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Country string `json:"country"`
	Postal  string `json:"postal"`
	Region  string `json:"region"`
}

type genProxy struct {
	ipInfo                   *IPInfo
	city, country, proxyType string
}

type CacheItem struct {
	Content    []byte
	StatusCode int
	Header     http.Header
	ExpiresAt  time.Time
}

type Cache struct {
	items map[string]*CacheItem
	mu    sync.RWMutex
}

type Config struct {
	Credentials struct {
		User       string `yaml:"proxy-user"`
		Pass       string `yaml:"proxy-pass"`
		TgBotToken string `yaml:"tgBotToken"`
	} `yaml:"credientials"`
	Telegram struct {
		ChatIDs []int64 `yaml:"chat_ids"`
	} `yaml:"telegram"`
}

type Tg struct {
	bot      *tgbotapi.BotAPI
	chat_ids []int64
}

func (tg *Tg) NotifyWebhook(msg string) {

	if len(tg.chat_ids) > 0 {
		for _, chatID := range tg.chat_ids {
			time.Sleep(time.Millisecond * 500)
			creds := tgbotapi.NewMessage(chatID, msg)
			if _, err := tg.bot.Send(creds); err != nil {
				fmt.Println(fmt.Errorf("failed to send telegram webhook to chat ID %v with length %v: %s", chatID, len(msg), err))
			}
		}
	}
}

func (tg *Tg) proxyNotify(ipInfo IPInfo, proxyURL string) {
	pu, _ := url.Parse(proxyURL)
	pi, _ := getProxyIPInfo(pu)
	msg := fmt.Sprintf(proxyMsg, ipInfo.IP, ipInfo.Country, ipInfo.Region, ipInfo.City, ipInfo.Postal, pi.IP)
	msg = msg + fmt.Sprintf(proxyInfo, pi.Country, pi.Region, pi.City, pi.Postal)
	tg.NotifyWebhook(msg)
}

const (
	StartPort = 10001
	MaxPorts  = 1000

	USMaxPorts           = 19999
	GBMaxPorts           = 19999
	TopCountriesMaxPorts = 9999
	CountryMaxPorts      = 999 // actual: US-EG have >= 9999 while the rest have 999
	StateMaxPorts        = 99
	TopCityMaxPorts      = 49

	GateStartPort = 10001
	GateMaxPorts  = 29999 // actual: 10001-39999

	ProxyURLBase       = "http://%s:%s@%s.smartproxy.com:%d"
	ProxyDuration      = 30 * time.Minute
	DefaultUser        = "user-%s-sessionduration-30"
	USZipUser          = "user-%s-sessionduration-30-country-us-zip-%s"
	OtherCountriesUser = "user-%s-country-%s-sessionduration-30"
	OtherCitiesUser    = "user-%s-country-%s-city-%s-sessionduration-30"

	proxyMsg  = "NEW PROXY SESSION\n\nClient IP: %s\nCountry: %s\nRegion: %s\nCity: %s\nPostal: %s\n\nProxy IP: %s\n"
	proxyInfo = "Country: %s\nRegion: %s\nCity: %s\nPostal: %s"

	PROXY_PORT = 8888
)

var (
	User = ""
	Pass = ""
	// Maps to track last port used
	lastPortUsedCountry = map[string]int{}
	lastPortUsedState   = map[string]int{}
	lastPortUsedCity    = map[string]int{}
	lastPortUsedGate    = map[string]int{}

	ipInfoCache   = map[string][]byte{}
	proxyURLCache = map[string][]byte{}

	ipInfoMutex        = map[string]*sync.Mutex{}
	proxyActivityMutex = map[string]*sync.Mutex{}
	proxyURLCacheMutex = map[string]*sync.Mutex{}
	reverseProxyMutex  = map[string]*sync.Mutex{}
	sessionMutex       = map[string]*sync.Mutex{}

	proxyActivity  = map[string]*time.Time{}
	reverseProxies = map[string]*httputil.ReverseProxy{}
	transportMap   = map[string]*http.Transport{}

	dbMutex sync.Mutex

	// Mutex for thread-safe access to maps
	cityMutex, countryMutex, gateMutex, stateMutex sync.Mutex

	HttpError      = errors.New("HttpError")
	ProxyError     = errors.New("ProxyError")
	ProxyURLError  = errors.New("ProxyURLError")
	targetURLError = errors.New("targetURLError")
)

func main() {
	db, err := sql.Open("sqlite3", "./proxy.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createTables(db)

	cache := NewCache()

	file, err := os.Open("config.yaml")
	if err != nil {
		log.Fatalf("Error opening YAML file: %v", err)
	}
	defer file.Close()

	var cfg Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		log.Fatalf("error decoding YAML file: %v", err)
	}

	User = cfg.Credentials.User
	Pass = cfg.Credentials.Pass

	tg_bot, err := tgbotapi.NewBotAPI(cfg.Credentials.TgBotToken)
	if err != nil {
		log.Fatalf("telegram NewBotAPI: %v", err)
	}

	tg := Tg{
		bot:      tg_bot,
		chat_ids: cfg.Telegram.ChatIDs,
	}

	sessionlessReverseProxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {

			log.Printf("Forwarding request to host (Sessionless): %s\n", req.URL.String())
			if requestIP := req.Header.Get("Request-IP"); requestIP != "" {
				log.Printf("Request-IP: %s\n", requestIP)
			}
			if sessionID := req.Header.Get("Session-ID"); sessionID != "" {
				log.Printf("Session-ID: %s\n", sessionID)
			}
			// For Debugging
			// dump, err := httputil.DumpRequest(req, true)
			// if err != nil {
			// 	log.Printf("Failed to dump request: %v", err)
			// } else {
			// 	fmt.Printf("Request Details (Proxy Director):\n%s\n", string(dump))
			// }
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: false,
		},
		ModifyResponse: func(resp *http.Response) error {
			if isStaticFile(resp.Request.URL.Path) && resp.StatusCode == http.StatusOK {
				if resp.Body == nil {
					return errors.New("response body is nil")
				}
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				resp.Body.Close()
				resp.Body = io.NopCloser(strings.NewReader(string(body)))

				cache.Set(resp.Request.URL.String(), body, resp.StatusCode, resp.Header, 24*time.Hour)
			}

			// For debugging
			// dump, err := httputil.DumpResponse(resp, false)
			// if err != nil {
			// 	log.Printf("Failed to dump response: %v", err)
			// }

			// fmt.Printf("\nResponse (reverseProxyModifyResponse):\n%s\n", string(dump))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			errMsg := fmt.Sprintf("\nSessionless Proxy error:\n %v\nURL: %s", err, req.URL.String())
			log.Print(errMsg)
			go tg.NotifyWebhook(errMsg)
		},
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Println("Unable to determine client IP")
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusInternalServerError, "Unable to determine client IP")
		}

		if clientIP != "127.0.0.1" && clientIP != "::1" {
			log.Printf("Forbidden (IP: %s)", clientIP)
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, "Forbidden")
		}

		// return cached static files
		if isStaticFile(r.URL.Path) {
			r_url := r.URL.String()
			if item, found := cache.Get(r_url); found {

				log.Printf("Cached static file found: %s", r_url)

				resp := goproxy.NewResponse(r, item.Header.Get("Content-Type"), item.StatusCode, string(item.Content))
				for key, values := range item.Header {
					for _, value := range values {
						resp.Header.Set(key, value)
					}
				}
				return r, resp
			}
		}

		requestIP, _, err := net.SplitHostPort(r.Header.Get("Request-IP"))
		sessionID := r.Header.Get("Session-ID")

		if err != nil || sessionID == "" {
			sRecorder := httptest.NewRecorder()
			sessionlessReverseProxy.ServeHTTP(sRecorder, r)

			resp := &http.Response{
				StatusCode: sRecorder.Code,
				Header:     sRecorder.Header(),
				Body:       io.NopCloser(sRecorder.Body),
				Request:    r,
			}
			return r, resp
		}

		r.Header.Del("Request-IP")
		r.Header.Del("Session-ID")

		ipInfo, err := getIPInfo(requestIP)
		if err != nil {
			log.Printf("Unable to fetch IP information for %s", requestIP)
			saveProxyURLToCache(sessionID, "NULL")
		}

		host := r.Host
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusBadGateway, "Host not found")
		}
		ip := ips[0].String()
		targetURL := &url.URL{
			Scheme: r.URL.Scheme,
			Host:   net.JoinHostPort(ip, "80"),
		}

		if r.URL.Scheme == "https" {
			targetURL.Host = net.JoinHostPort(ip, "443")
		}

		createProxy := func() *url.URL {

			if externalProxyURL := generateProxyURL(ipInfo, targetURL, host); externalProxyURL == "" {
				log.Printf("Unable to generate proxy URL for %s (%s)", requestIP, sessionID)

				saveProxyURLToCache(sessionID, "NULL")
				saveProxyURLToDB(db, &dbMutex, requestIP, "NULL", sessionID)

				msg := fmt.Sprintf(proxyMsg, ipInfo.IP, ipInfo.Country, ipInfo.Region, ipInfo.City, ipInfo.Postal, "NULL")
				go tg.NotifyWebhook(msg)

			} else {
				saveProxyURLToCache(sessionID, externalProxyURL)
				saveProxyURLToDB(db, &dbMutex, requestIP, externalProxyURL, sessionID)
				go tg.proxyNotify(ipInfo, externalProxyURL)

				externalProxyURLParsed, _ := url.Parse(externalProxyURL)
				return externalProxyURLParsed
			}
			return nil
		}

		sm, exists := sessionMutex[sessionID]
		if !exists {
			sessionMutex[sessionID] = &sync.Mutex{}
			sm, _ = sessionMutex[sessionID]
		}
		sm.Lock()

		var reverseProxy *httputil.ReverseProxy

		recorder := httptest.NewRecorder()

		if reverseProxy, exists := getReverseProxy(sessionID, reverseProxies); exists {
			last_activity := getProxyLastActivity(sessionID)
			externalProxyURL, timestamp := getProxyURLFromCache(sessionID)

			if externalProxyURL == "NULL" || time.Since(timestamp) <= ProxyDuration ||
				((last_activity != nil) && time.Since(*last_activity) <= 90*time.Second) {
				sm.Unlock()
				reverseProxy.ServeHTTP(recorder, r)

				resp := &http.Response{
					StatusCode: recorder.Code,
					Header:     recorder.Header(),
					Body:       io.NopCloser(recorder.Body),
					Request:    r,
				}
				return r, resp
			} else {
				if transport, exists := transportMap[sessionID]; exists {
					if proxyURL := createProxy(); proxyURL != nil {
						transport.Proxy = http.ProxyURL(proxyURL)
					} else {
						transport.Proxy = nil
					}

					sm.Unlock()
					reverseProxy.ServeHTTP(recorder, r)

					resp := &http.Response{
						StatusCode: recorder.Code,
						Header:     recorder.Header(),
						Body:       io.NopCloser(recorder.Body),
						Request:    r,
					}
					return r, resp
				}
			}

		}

		reverseProxy = &httputil.ReverseProxy{}

		reverseProxyDirector := func(req *http.Request) {
			originalHost := req.Host
			ips, err := net.LookupIP(originalHost) // update the requests URL: change from domain to IP address of domain
			if err != nil || len(ips) == 0 {
				log.Printf("Failed to get IP address of host: %s", originalHost)
			}
			ip = ips[0].String()

			if req.URL.Scheme == "https" {
				req.URL.Host = net.JoinHostPort(ip, "443")
			} else {
				req.URL.Host = net.JoinHostPort(ip, "80")
			}

			log.Printf("Forwarding request to host: %s\n", req.URL.String())
			log.Printf("Original host: %s\n", originalHost)

			// For Debugging

			// dump, err := httputil.DumpRequest(req, true)
			// if err != nil {
			// 	log.Printf("Failed to dump request: %v", err)
			// } else {
			// 	fmt.Printf("Request Details (Proxy Director):\n%s\n", string(dump))
			// }
		}

		reverseProxyTransport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: false,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second, // Connection timeout
				KeepAlive: 30 * time.Second, // Keep-alive timeout
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		if ProxyURL := createProxy(); ProxyURL != nil {
			reverseProxyTransport.Proxy = http.ProxyURL(ProxyURL)
		}

		// reverseProxyErrorHandler := func(w http.ResponseWriter, req *http.Request, err error) {
		// 	errMsg := fmt.Sprintf("\nProxy error:\n %v\nURL: %s", err, req.URL.String())
		// 	log.Print(errMsg)
		// 	go tg.NotifyWebhook(errMsg)

		// 	if urlErr, ok := err.(*url.Error); ok {
		// 		if _, ok := urlErr.Err.(*net.OpError); ok || urlErr.Err.Error() == "407 Proxy Authentication Required" {
		// 			// Handle network-level errors (DNS, connection refused, etc.) & Proxy Auth Error
		// 			log.Printf("Network error: %v", err)

		// 			if reverseProxyTransport.Proxy != nil {
		// 				disableReverseProxyProxy(sessionID, reverseProxyTransport)

		// 				saveProxyURLToCache(sessionID, "NULL")
		// 				saveProxyURLToDB(db, &dbMutex, requestIP, "NULL", sessionID)

		// 				http.Redirect(w, req, req.URL.String(), http.StatusTemporaryRedirect)
		// 				return
		// 			}
		// 		}
		// 	}
		// }

		// New mod & test for Proxy Error handler:

		reverseProxyErrorHandler := func(w http.ResponseWriter, req *http.Request, err error) {
			errMsg := fmt.Sprintf("\nProxy error:\n %v\nURL: %s", err, req.URL.String())
			log.Print(errMsg)
			go tg.NotifyWebhook(errMsg)

			if urlErr, ok := err.(*url.Error); ok {
				if _, ok := urlErr.Err.(*net.OpError); ok || urlErr.Err.Error() == "407 Proxy Authentication Required" {
					// Handle network-level errors (DNS, connection refused, etc.) & Proxy Auth Error
					log.Printf("Network error: %v", err)

					if reverseProxyTransport.Proxy != nil {
						disableReverseProxyProxy(sessionID, reverseProxyTransport)

						saveProxyURLToCache(sessionID, "NULL")
						saveProxyURLToDB(db, &dbMutex, requestIP, "NULL", sessionID)

						http.Redirect(w, req, req.URL.String(), http.StatusTemporaryRedirect)
						return
					}
				}
			}
		}

		reverseProxyModifyResponse := func(resp *http.Response) error {
			if isStaticFile(resp.Request.URL.Path) && resp.StatusCode == http.StatusOK {
				if resp.Body == nil {
					return errors.New("response body is nil")
				}
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				resp.Body.Close()
				resp.Body = io.NopCloser(strings.NewReader(string(body)))

				cache.Set(resp.Request.URL.String(), body, resp.StatusCode, resp.Header, 24*time.Hour)
			}

			// For debugging
			// dump, err := httputil.DumpResponse(resp, false)
			// if err != nil {
			// 	log.Printf("Failed to dump response: %v", err)
			// }

			// fmt.Printf("\nResponse (reverseProxyModifyResponse):\n%s\n", string(dump))

			setProxyLastActivity(sessionID)
			return nil
		}

		reverseProxy.Director = reverseProxyDirector
		reverseProxy.Transport = reverseProxyTransport
		reverseProxy.ErrorHandler = reverseProxyErrorHandler
		reverseProxy.ModifyResponse = reverseProxyModifyResponse

		transportMap[sessionID] = reverseProxyTransport

		saveReverseProxy(sessionID, reverseProxy, reverseProxies)

		sm.Unlock()

		reverseProxy.ServeHTTP(recorder, r)

		resp := &http.Response{
			StatusCode: recorder.Code,
			Header:     recorder.Header(),
			Body:       io.NopCloser(recorder.Body),
			Request:    r,
		}
		return r, resp
	})

	addr := fmt.Sprintf(":%d", PROXY_PORT)

	log.Printf("Starting HTTP Proxy Server on %s...", addr)
	log.Fatal(http.ListenAndServe(addr, proxy))
}

func createTables(db *sql.DB) {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS proxy_urls (
			ip TEXT PRIMARY KEY,
			sid TEXT,
			proxy_url TEXT,
			timestamp DATETIME
		);`,
	}

	for _, query := range tables {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func getIPInfo(ip string) (IPInfo, error) {
	ipm, exists := ipInfoMutex[ip]
	if !exists {
		ipInfoMutex[ip] = &sync.Mutex{}
		ipm, _ = ipInfoMutex[ip]
	}
	ipm.Lock()
	defer ipm.Unlock()

	if data, found := ipInfoCache[ip]; found {
		var ipInfo IPInfo
		json.Unmarshal(data, &ipInfo)
		return ipInfo, nil
	}

	resp, err := http.Get("http://ipinfo.io/" + ip + "/json")
	if err != nil {
		return IPInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("failed to get IP info for %s", ip)
		return IPInfo{}, fmt.Errorf("failed to get IP info")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return IPInfo{}, err
	}

	var ipInfo IPInfo
	if err := json.Unmarshal(body, &ipInfo); err != nil {
		return IPInfo{}, err
	}

	ipInfoCache[ip] = body

	return ipInfo, nil
}

func getProxyIPInfo(proxyURL *url.URL) (IPInfo, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("http://ipinfo.io/json")
	if err != nil {
		log.Println("failed to get IP info for Proxy")
		return IPInfo{}, fmt.Errorf("failed to get IP info for Proxy")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Println("failed to get IP info for Proxy")
		return IPInfo{}, fmt.Errorf("failed to get IP info for Proxy")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return IPInfo{}, err
	}

	var ipInfo IPInfo
	if err := json.Unmarshal(body, &ipInfo); err != nil {
		return IPInfo{}, err
	}

	return ipInfo, nil
}

func getReverseProxy(sid string, reverseProxies map[string]*httputil.ReverseProxy) (*httputil.ReverseProxy, bool) {
	ipm, exists := reverseProxyMutex[sid]
	if !exists {
		reverseProxyMutex[sid] = &sync.Mutex{}
		ipm, _ = reverseProxyMutex[sid]
	}
	ipm.Lock()
	defer ipm.Unlock()

	if reverseProxy, exists := reverseProxies[sid]; exists {
		return reverseProxy, true
	}
	return nil, false
}

func saveReverseProxy(sid string, proxy *httputil.ReverseProxy, reverseProxies map[string]*httputil.ReverseProxy) {
	ipm, exists := reverseProxyMutex[sid]
	if !exists {
		reverseProxyMutex[sid] = &sync.Mutex{}
		ipm, _ = reverseProxyMutex[sid]
	}
	ipm.Lock()
	defer ipm.Unlock()

	reverseProxies[sid] = proxy
}

func disableReverseProxyProxy(sid string, transport *http.Transport) {
	ipm, exists := reverseProxyMutex[sid]
	if !exists {
		reverseProxyMutex[sid] = &sync.Mutex{}
		ipm, _ = reverseProxyMutex[sid]
	}
	ipm.Lock()
	defer ipm.Unlock()

	transport.Proxy = nil
}

func generateProxyURL(ipInfo IPInfo, targetURL *url.URL, targetHost string) string {
	var proxies = []*url.URL{}
	gp := genProxy{ipInfo: &ipInfo}
	gp.city = strings.ReplaceAll(strings.ToLower(removeDiacritics(ipInfo.City)), " ", "_")
	gp.country = strings.ToLower(ipInfo.Country)

	type proxyGenFunc func() string

	generateProxy := func(generator proxyGenFunc) string {
		for i := 0; i < 3; i++ {

			proxyURL := generator()
			if proxyURL != "" {
				proxyURLParsed, _ := url.Parse(proxyURL)
				proxies = append(proxies, proxyURLParsed)
			}
		}
		if proxyURL := firstValidProxyURL(proxies, targetURL, targetHost); proxyURL != "" {
			return proxyURL
		}
		return ""
	}

	if ipInfo.Country == "US" {
		gp.proxyType = "zip"
		proxyURL := gp.generateUSProxyURL()
		proxyURLParsed, _ := url.Parse(proxyURL)
		if valid, err := validateProxyURL(proxyURLParsed, targetURL, targetHost); valid {
			return proxyURL
		} else {
			if errors.Is(err, HttpError) {

				if proxyURL := generateProxy(gp.generateUSProxyURL); proxyURL != "" {
					return proxyURL
				}
				gp.proxyType = ""
			}
		}
	}

	if proxyURL := generateProxy(gp.generateCityProxyURL); proxyURL != "" {
		return proxyURL
	}

	if proxyURL := generateProxy(gp.generateCountryProxyURL); proxyURL != "" {
		return proxyURL
	}

	proxyURL := gp.generateUSProxyURL()
	proxyURLParsed, _ := url.Parse(proxyURL)
	if valid, _ := validateProxyURL(proxyURLParsed, targetURL, targetHost); valid {
		return proxyURL
	}
	return ""
}

func (gp *genProxy) generateUSProxyURL() string {
	var lastPortUsed int
	var startPort int
	var USZipUser_ string

	switch gp.proxyType {
	case "zip":
		startPort = Countries["US"]
		lastPortUsed = nextPort(&lastPortUsedCountry, &countryMutex, "US", startPort, USMaxPorts)
		USZipUser_ = fmt.Sprintf(USZipUser, User, gp.ipInfo.Postal)
		return fmt.Sprintf(ProxyURLBase, USZipUser_, Pass, "us", lastPortUsed)
	default:
		lastPortUsed = nextPort(&lastPortUsedCountry, &countryMutex, "US", Countries["US"], USMaxPorts)
		user := fmt.Sprintf(DefaultUser, User)
		return fmt.Sprintf(ProxyURLBase, user, Pass, "us", lastPortUsed)
	}
}

func (gp *genProxy) generateCityProxyURL() string {
	var lastPortUsed int
	var startPort int

	if val, exists := TopCities[gp.city]; exists {
		startPort = val
		lastPortUsed = nextPort(&lastPortUsedCity, &cityMutex, gp.city, startPort, TopCityMaxPorts)
		user := fmt.Sprintf(DefaultUser, User)
		return fmt.Sprintf(ProxyURLBase, user, Pass, "city", lastPortUsed)
	}

	if val, exists := OtherCities[gp.country]; exists {
		for _, otherCity := range val {
			if otherCity == gp.city {
				startPort = Countries[gp.country]
				lastPortUsed = nextPort(&lastPortUsedGate, &gateMutex, gp.city, GateStartPort, GateMaxPorts)
				user := fmt.Sprintf(OtherCitiesUser, User, gp.country, gp.city)
				return fmt.Sprintf(ProxyURLBase, user, Pass, "gate", lastPortUsed)
			}
		}
	}

	return ""
}

func (gp *genProxy) generateCountryProxyURL() string {
	var lastPortUsed int
	var startPort int

	if val, exists := Countries[gp.ipInfo.Country]; exists {
		startPort = val
		lastPortUsed = nextPort(&lastPortUsedCountry, &countryMutex, gp.country, startPort, CountryMaxPorts)
		user := fmt.Sprintf(DefaultUser, User)
		return fmt.Sprintf(ProxyURLBase, user, Pass, gp.country, lastPortUsed)
	}

	for _, otherCountry := range OtherCountries {
		if gp.ipInfo.Country == otherCountry {
			lastPortUsed = nextPort(&lastPortUsedGate, &gateMutex, otherCountry, GateStartPort, GateMaxPorts)
			user := fmt.Sprintf(OtherCountriesUser, User, gp.country)
			return fmt.Sprintf(ProxyURLBase, user, Pass, "gate", lastPortUsed)
		}
	}

	return ""
}

func firstValidProxyURL(proxies []*url.URL, targetURL *url.URL, targetHost string) string {
	var once sync.Once
	var wg sync.WaitGroup
	var validProxy *url.URL

	done := make(chan struct{})
	proxyChan := make(chan *url.URL, 1)

	for _, proxy := range proxies {

		if proxy == nil {
			continue // Skip this iteration if proxy is nil
		}

		wg.Add(1)
		go func(p *url.URL) {

			if p == nil {
				return // Safeguard: exit if p is nil
			}

			defer wg.Done()

			select {
			case <-done:
			default:
				if valid, _ := validateProxyURL(p, targetURL, targetHost); valid {
					select {
					case proxyChan <- p:
						once.Do(func() { close(done) })
					case <-done:
					}
				}
			}
		}(proxy)
	}

	go func() {
		wg.Wait()
		close(proxyChan)
		once.Do(func() { close(done) })
	}()

	select {
	case validProxy = <-proxyChan:
	case <-done:
	case <-time.After(time.Second * 10):
		log.Println("Proxies validation timeout")
	}

	if validProxy != nil {
		return validProxy.String()
	}
	return ""
}

func validateProxyURL(proxyURL, targetURL *url.URL, targetHost string) (bool, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", targetURL.String(), nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	req.Host = targetHost

	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Add("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Proxy validation error:", err)
		return false, ProxyError
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, nil
	}

	log.Println("Invalid proxy response. Status code:", resp.StatusCode)
	return false, HttpError
}

func getProxyURLFromDB(db *sql.DB, sid string) (string, time.Time) {
	var proxyURL string
	var timestamp time.Time

	err := db.QueryRow("SELECT proxy_url, timestamp FROM proxy_urls WHERE sid = ?", sid).Scan(&proxyURL, &timestamp)
	if err != nil {
		return "", time.Time{}
	}

	return proxyURL, timestamp
}

func getProxyURLFromCache(sid string) (string, time.Time) {
	pucm, exists := proxyURLCacheMutex[sid]
	if !exists {
		proxyURLCacheMutex[sid] = &sync.Mutex{}
		pucm, _ = proxyURLCacheMutex[sid]
	}
	pucm.Lock()
	defer pucm.Unlock()

	data, found := proxyURLCache[sid]
	if !found {
		return "", time.Time{}
	}

	var proxyData struct {
		ProxyURL  string
		Timestamp time.Time
	}
	json.Unmarshal(data, &proxyData)

	return proxyData.ProxyURL, proxyData.Timestamp
}

func saveProxyURLToDB(db *sql.DB, dbm *sync.Mutex, ip, proxyURL, sid string) error {
	dbm.Lock()
	defer dbm.Unlock()
	_, err := db.Exec("INSERT OR REPLACE INTO proxy_urls (ip, sid, proxy_url, timestamp) VALUES (?, ?, ?, ?)", ip, sid, proxyURL, time.Now())
	return err
}

func saveProxyURLToCache(sid, proxyURL string) {
	pucm, exists := proxyURLCacheMutex[sid]
	if !exists {
		proxyURLCacheMutex[sid] = &sync.Mutex{}
		pucm, _ = proxyURLCacheMutex[sid]
	}
	pucm.Lock()
	defer pucm.Unlock()

	data := struct {
		ProxyURL  string
		Timestamp time.Time
	}{
		ProxyURL:  proxyURL,
		Timestamp: time.Now(),
	}
	proxyURLCache[sid], _ = json.Marshal(data)
}

func nextPort(lastPortUsed *map[string]int, m *sync.Mutex, key string, startPort, MaxPorts int) int {
	m.Lock()
	defer m.Unlock()

	lastPort := (*lastPortUsed)[key]
	if lastPort == 0 || (lastPort+1) >= (startPort+MaxPorts) {
		(*lastPortUsed)[key] = startPort
		return startPort
	}
	lastPort += 1
	(*lastPortUsed)[key] = lastPort
	return lastPort
}

func removeDiacritics(s string) string {
	t := transform.Chain(norm.NFD, transform.RemoveFunc(func(r rune) bool {
		return unicode.Is(unicode.Mn, r)
	}), norm.NFC)
	s, _, _ = transform.String(t, s)
	return s
}

func sendTGMessage(message, tgBotToken string, tgChatIDs *[]string) error {
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0"
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tgBotToken)

	for _, tgChatID := range *tgChatIDs {

		time.Sleep(time.Millisecond * 500)

		data := url.Values{}
		data.Set("chat_id", tgChatID)
		data.Set("parse_mode", "HTML")
		data.Set("disable_web_page_preview", "True")
		data.Set("text", message)

		req, err := http.NewRequest("POST", apiURL, bytes.NewBufferString(data.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			message, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Failed to read response body: %v", err)
			}
			log.Printf("Telegram message error:\nHTTP status code: %d\nTG message: %s", resp.StatusCode, string(message))
			return fmt.Errorf("HTTP status code: %d", resp.StatusCode)
		}
	}

	return nil
}

func NewCache() *Cache {
	return &Cache{
		items: make(map[string]*CacheItem),
	}
}

func (c *Cache) Get(key string) (*CacheItem, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, found := c.items[key]
	if !found || time.Now().After(item.ExpiresAt) {
		return nil, false
	}
	return item, true
}

func (c *Cache) Set(key string, content []byte, statusCode int, header http.Header, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = &CacheItem{
		Content:    content,
		StatusCode: statusCode,
		Header:     header,
		ExpiresAt:  time.Now().Add(ttl),
	}
}

func isStaticFile(path string) bool {
	// staticFileExtensions := []string{".css", ".js", ".html", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico"}
	staticFileExtensions := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".mp4", ".mp3", ".webm", ".woff", ".woff2", ".ttf", ".otf"}
	for _, ext := range staticFileExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func getProxyLastActivity(sid string) *time.Time {
	pam, exists := proxyActivityMutex[sid]
	if !exists {
		proxyActivityMutex[sid] = &sync.Mutex{}
		pam, _ = proxyActivityMutex[sid]
	}
	pam.Lock()
	defer pam.Unlock()

	if last_activity, exists := proxyActivity[sid]; exists {
		return last_activity
	}
	return nil
}

func setProxyLastActivity(sid string) {
	pam, exists := proxyActivityMutex[sid]
	if !exists {
		proxyActivityMutex[sid] = &sync.Mutex{}
		pam, _ = proxyActivityMutex[sid]
	}
	pam.Lock()
	defer pam.Unlock()

	t := time.Now()
	proxyActivity[sid] = &t
}
