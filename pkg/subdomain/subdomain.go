package subdomain

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/zarni99/bbrecon/pkg/config"
	"github.com/zarni99/bbrecon/pkg/output"
)

const (
	crtshAPI		= "https://crt.sh/?q=%s&output=json"
	hackertargetAPI		= "https://api.hackertarget.com/hostsearch/?q=%s"
	alienvaultAPI		= "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns"
	urlscanAPI		= "https://urlscan.io/api/v1/search/?q=domain:%s"
	bufferoverAPI		= "https://dns.bufferover.run/dns?q=%s"
	threatminerAPI		= "https://api.threatminer.org/v2/domain.php?rt=5&q=%s"
	riddlerAPI		= "https://riddler.io/search/exportcsv?q=pld:%s"
	waybackAPI		= "https://web.archive.org/cdx/search/cdx?url=*.%s&output=json&collapse=urlkey"
	commoncrawlAPI		= "https://index.commoncrawl.org/CC-MAIN-2023-14-index?url=*.%s&output=json"
	certspotterAPI		= "https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names"
	anubisAPI		= "https://jldc.me/anubis/subdomains/%s"
	leakixAPI		= "https://leakix.net/api/subdomains/%s"
	netlasAPI		= "https://app.netlas.io/api/domains/?q=%s"
	securitytrailsAPI	= "https://api.securitytrails.com/v1/domain/%s/subdomains"
	censysAPI		= "https://search.censys.io/api/v2/hosts/%s"
	shodanAPI		= "https://api.shodan.io/dns/domain/%s?key=%s"
	virusTotalAPI		= "https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s"
	threatCrowdAPI		= "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"
	rapidDNSAPI		= "https://rapiddns.io/api/v1/subdomains/%s"
	facebookCTAPI		= "https://developers.facebook.com/tools/ct/%s"
	dnsDumpsterAPI		= "https://dnsdumpster.com/"
	chaosAPI		= "https://chaos.projectdiscovery.io/v1/dns/%s"
	spyseAPI		= "https://api.spyse.com/v4/data/domain/%s"
	fullHuntAPI		= "https://fullhunt.io/api/v1/domain/%s/subdomains"
	binaryEdgeAPI		= "https://api.binaryedge.io/v2/query/domains/subdomain/%s"
	threatBookAPI		= "https://api.threatbook.cn/v3/domain/sub_domains?apikey=%s&resource=%s"
	intelxAPI		= "https://intelx.io/api/v1/subdomains/%s"

	c99API		= "https://api.c99.nl/subdomainfinder?key=%s&domain=%s&json"
	bevigilAPI	= "https://osint.bevigil.com/api/subdomains/%s"
	chinazAPI	= "https://apidata.chinaz.com/CallAPI/Alexa/GetAllSubDomain?key=%s&domain=%s"
	digitalyamaAPI	= "https://api.digitalyama.com/api/v1/subdomains/%s?apikey=%s"
	dnsdbAPI	= "https://api.dnsdb.info/dnsdb/v2/rrset/name/*.%s/ANY?limit=1000"
	dnsrepoAPI	= "https://dnsrepo.noc.org/api/subdomains/%s?apikey=%s"
	fofaAPI		= "https://fofa.so/api/v1/search/all?email=%s&key=%s&qbase64=%s"
	githubAPI	= "https://api.github.com/search/code?q=%s+in:file+extension:txt+path:/.well-known/security.txt"
	hunterAPI	= "https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s"
	quakeAPI	= "https://quake.360.cn/api/v3/search/quake_domains?keyword=%s"
	redhuntlabsAPI	= "https://api.redhuntlabs.com/v1/subdomains/%s?api_key=%s"
	robtexAPI	= "https://freeapi.robtex.com/pdns/forward/%s"
	sitedossierAPI	= "http://www.sitedossier.com/parentdomain/%s"
	whoisxmlapiAPI	= "https://subdomains.whoisxmlapi.com/api/v1?apiKey=%s&domain=%s"
	zoomeyeAPI	= "https://api.zoomeye.org/domain/search?q=%s&type=1"
	facebookAPI	= "https://graph.facebook.com/v12.0/certificates?query=%s&access_token=%s"
	builtwithAPI	= "https://api.builtwith.com/v20/api.json?KEY=%s&LOOKUP=%s"
	hudsonrockAPI	= "https://api.hudsonrock.com/v1/search/subdomains?domain=%s"
)

type Enum struct {
	target		string
	config		config.SubdomainConfig
	threads		int
	timeout		int
	client		*http.Client
	rateLimiter	*RateLimiter
}

type SourceConfig struct {
	RateLimit	int
	MaxRetries	int
	RetryBackoff	time.Duration
	Timeout		time.Duration
	LastRequest	time.Time
	RequestCount	int
	WindowStart	time.Time
	mu		sync.Mutex
}

type RateLimiter struct {
	sources	map[string]*SourceConfig
	global	*SourceConfig
	stop	chan struct{}
}

type SourceInfo struct {
	RequiresKey	bool
	Description	string
}

func GetSourcesInfo() map[string]SourceInfo {
	return map[string]SourceInfo{

		"crtsh": {
			RequiresKey:	false,
			Description:	"Certificate Transparency logs",
		},
		"hackertarget": {
			RequiresKey:	false,
			Description:	"HackerTarget API",
		},
		"alienvault": {
			RequiresKey:	false,
			Description:	"AlienVault Open Threat Exchange",
		},
		"urlscan": {
			RequiresKey:	false,
			Description:	"Urlscan.io API",
		},
		"threatminer": {
			RequiresKey:	false,
			Description:	"ThreatMiner API",
		},
		"riddler": {
			RequiresKey:	false,
			Description:	"Riddler.io API",
		},
		"wayback": {
			RequiresKey:	false,
			Description:	"Wayback Machine Archive",
		},
		"commoncrawl": {
			RequiresKey:	false,
			Description:	"CommonCrawl Archive",
		},
		"anubis": {
			RequiresKey:	false,
			Description:	"Anubis Database",
		},
		"rapiddns": {
			RequiresKey:	false,
			Description:	"RapidDNS API",
		},
		"threatcrowd": {
			RequiresKey:	false,
			Description:	"ThreatCrowd API",
		},
		"sitedossier": {
			RequiresKey:	false,
			Description:	"SiteDossier Database",
		},
		"hudsonrock": {
			RequiresKey:	false,
			Description:	"HudsonRock Database",
		},
		"digitorus": {
			RequiresKey:	false,
			Description:	"Digitorus API",
		},

		"bufferover": {
			RequiresKey:	true,
			Description:	"BufferOver API",
		},
		"certspotter": {
			RequiresKey:	true,
			Description:	"CertSpotter API",
		},
		"leakix": {
			RequiresKey:	true,
			Description:	"LeakIX API",
		},
		"netlas": {
			RequiresKey:	true,
			Description:	"Netlas API",
		},
		"securitytrails": {
			RequiresKey:	true,
			Description:	"SecurityTrails API",
		},
		"shodan": {
			RequiresKey:	true,
			Description:	"Shodan API",
		},
		"censys": {
			RequiresKey:	true,
			Description:	"Censys API",
		},
		"virustotal": {
			RequiresKey:	true,
			Description:	"VirusTotal API",
		},
		"facebookct": {
			RequiresKey:	true,
			Description:	"Facebook Certificate Transparency",
		},
		"dnsdumpster": {
			RequiresKey:	true,
			Description:	"DNSDumpster API",
		},
		"chaos": {
			RequiresKey:	true,
			Description:	"Chaos DNS API",
		},
		"spyse": {
			RequiresKey:	true,
			Description:	"Spyse API",
		},
		"fullhunt": {
			RequiresKey:	true,
			Description:	"FullHunt API",
		},
		"binaryedge": {
			RequiresKey:	true,
			Description:	"BinaryEdge API",
		},
		"threatbook": {
			RequiresKey:	true,
			Description:	"ThreatBook API",
		},
		"intelx": {
			RequiresKey:	true,
			Description:	"IntelX API",
		},
		"c99": {
			RequiresKey:	true,
			Description:	"C99 API",
		},
		"quake": {
			RequiresKey:	true,
			Description:	"Quake API",
		},
		"robtex": {
			RequiresKey:	true,
			Description:	"Robtex API",
		},
		"dnsdb": {
			RequiresKey:	true,
			Description:	"DNSDB API",
		},
		"hunter": {
			RequiresKey:	true,
			Description:	"Hunter.io API",
		},
		"fofa": {
			RequiresKey:	true,
			Description:	"FOFA API",
		},
		"zoomeye": {
			RequiresKey:	true,
			Description:	"ZoomEye API",
		},
		"whoisxmlapi": {
			RequiresKey:	true,
			Description:	"WhoisXML API",
		},

		"bevigil": {
			RequiresKey:	true,
			Description:	"BeVigil API",
		},
		"chinaz": {
			RequiresKey:	true,
			Description:	"Chinaz API",
		},
		"digitalyama": {
			RequiresKey:	true,
			Description:	"DigitalYama API",
		},
		"dnsrepo": {
			RequiresKey:	true,
			Description:	"DNSRepo API",
		},
		"github": {
			RequiresKey:	true,
			Description:	"GitHub API",
		},
		"redhuntlabs": {
			RequiresKey:	true,
			Description:	"RedHuntLabs API",
		},
		"facebook": {
			RequiresKey:	true,
			Description:	"Facebook API",
		},
		"builtwith": {
			RequiresKey:	true,
			Description:	"BuiltWith API",
		},
	}
}

func GetAllSources() []string {
	sources := make([]string, 0)
	for source := range GetSourcesInfo() {
		sources = append(sources, source)
	}
	return sources
}

func GetDefaultSources() []string {
	return []string{

		"crtsh", "hackertarget", "alienvault", "urlscan", "certspotter",
		"anubis", "rapiddns", "threatminer", "wayback", "commoncrawl",
		"riddler", "threatcrowd", "sitedossier", "hudsonrock", "digitorus",
	}
}

func NewRateLimiter(globalRate int) *RateLimiter {
	rl := &RateLimiter{
		sources:	make(map[string]*SourceConfig),
		global: &SourceConfig{
			RateLimit:	globalRate,
			MaxRetries:	3,
			RetryBackoff:	time.Second,
			Timeout:	30 * time.Second,
		},
		stop:	make(chan struct{}),
	}

	rl.sources["virustotal"] = &SourceConfig{
		RateLimit:	4,
		MaxRetries:	3,
		RetryBackoff:	2 * time.Second,
		Timeout:	30 * time.Second,
	}
	rl.sources["securitytrails"] = &SourceConfig{
		RateLimit:	5,
		MaxRetries:	3,
		RetryBackoff:	2 * time.Second,
		Timeout:	30 * time.Second,
	}
	rl.sources["shodan"] = &SourceConfig{
		RateLimit:	1,
		MaxRetries:	3,
		RetryBackoff:	2 * time.Second,
		Timeout:	30 * time.Second,
	}
	rl.sources["censys"] = &SourceConfig{
		RateLimit:	5,
		MaxRetries:	3,
		RetryBackoff:	2 * time.Second,
		Timeout:	30 * time.Second,
	}

	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stop:
			return
		}
	}
}

func (rl *RateLimiter) cleanup() {
	for _, config := range rl.sources {
		config.mu.Lock()
		if time.Since(config.WindowStart) > time.Second {
			config.RequestCount = 0
			config.WindowStart = time.Now()
		}
		config.mu.Unlock()
	}
}

func (rl *RateLimiter) Wait(source string) {
	config, exists := rl.sources[source]
	if !exists {
		config = rl.global
	}

	config.mu.Lock()
	defer config.mu.Unlock()

	if time.Since(config.WindowStart) > time.Second {
		config.RequestCount = 0
		config.WindowStart = time.Now()
	}

	if config.RequestCount >= config.RateLimit {
		time.Sleep(time.Second - time.Since(config.WindowStart))
		config.RequestCount = 0
		config.WindowStart = time.Now()
	}

	config.RequestCount++
	config.LastRequest = time.Now()
}

func (rl *RateLimiter) Stop() {
	close(rl.stop)
}

type Progress interface {
	UpdateProgress(source string, count int)
}

type ScanProgress struct {
	TotalSources		int
	CompletedSources	int
	CurrentSource		string
	SubdomainsFound		int
	StartTime		time.Time
	mu			sync.Mutex
}

func NewScanProgress(totalSources int) *ScanProgress {
	return &ScanProgress{
		TotalSources:	totalSources,
		StartTime:	time.Now(),
	}
}

func (p *ScanProgress) UpdateProgress(source string, count int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.CompletedSources++
	p.CurrentSource = source
	p.SubdomainsFound += count
}

type SubdomainConfig struct {
	ShowStats bool
}

func NewEnum(target string, config config.SubdomainConfig, threads, timeout int) *Enum {
	e := &Enum{
		target:		target,
		config:		config,
		threads:	threads,
		timeout:	timeout,
		rateLimiter:	NewRateLimiter(config.GlobalRateLimit),
	}
	e.client = e.createHTTPClient(timeout)
	return e
}

func (e *Enum) makeRequest(ctx context.Context, client *http.Client, req *http.Request, source string) (*http.Response, error) {
	config := e.rateLimiter.sources[source]
	if config == nil {
		config = e.rateLimiter.global
	}

	var resp *http.Response
	var err error
	backoff := config.RetryBackoff

	for attempt := 1; attempt <= config.MaxRetries; attempt++ {

		e.rateLimiter.Wait(source)

		newReq := req.Clone(ctx)
		if attempt > 1 {

			if req.Body != nil {
				if body, err := io.ReadAll(req.Body); err == nil {
					req.Body.Close()
					req.Body = io.NopCloser(bytes.NewBuffer(body))
					newReq.Body = io.NopCloser(bytes.NewBuffer(body))
				}
			}
		}

		ctx, cancel := context.WithTimeout(ctx, config.Timeout)
		defer cancel()

		resp, err = client.Do(newReq)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		if resp != nil {
			resp.Body.Close()
		}

		if attempt < config.MaxRetries {

			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				continue
			}
		}
	}

	return nil, fmt.Errorf("max retries exceeded: %v", err)
}

func (e *Enum) enumCrtSh(ctx context.Context, client *http.Client) ([]string, error) {
	type crtshEntry struct {
		NameValue string `json:"name_value"`
	}

	url := fmt.Sprintf(crtshAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "crtsh")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var entries []crtshEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, entry := range entries {
		subs := strings.Split(entry.NameValue, "\n")
		for _, sub := range subs {
			if sub != "" && strings.HasSuffix(sub, e.target) && e.isValidSubdomain(sub) {
				subdomains[sub] = true
			}
		}
	}

	var result []string
	for sub := range subdomains {
		result = append(result, sub)
	}

	return result, nil
}

func (e *Enum) Run(progress ...Progress) ([]output.Finding, error) {
	var findings []output.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	if e.config.EnableBruteForce && e.config.WordlistPath != "" {
		fmt.Printf("[%s] %s\n",
			color.CyanString("INFO"),
			color.YellowString("Starting subdomain bruteforcing with wordlist: %s", e.config.WordlistPath))

		wordlist, err := os.ReadFile(e.config.WordlistPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read wordlist: %v", err)
		}

		subdomains := strings.Split(string(wordlist), "\n")
		totalCount := len(subdomains)
		foundCount := 0

		fmt.Printf("[%s] Loaded %s entries from wordlist\n",
			color.CyanString("INFO"),
			color.GreenString("%d", totalCount))

		fmt.Printf("[%s] %s\n",
			color.CyanString("INFO"),
			color.YellowString("Bruteforcing subdomains..."))

		semaphore := make(chan struct{}, e.threads)
		var bruteMu sync.Mutex
		var progressCounter int
		var validSubdomains []string

		for _, subdomain := range subdomains {
			subdomain = strings.TrimSpace(subdomain)
			if subdomain == "" || strings.HasPrefix(subdomain, "#") {
				continue
			}

			semaphore <- struct{}{}
			wg.Add(1)
			go func(sub string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				fqdn := fmt.Sprintf("%s.%s", sub, e.target)

				_, err := net.LookupHost(fqdn)

				bruteMu.Lock()
				progressCounter++
				if progressCounter%100 == 0 || progressCounter == totalCount {

					percent := float64(progressCounter) / float64(totalCount) * 100
					fmt.Printf("\r[%s] Bruteforce progress: %.2f%% (%d/%d)",
						color.CyanString("BRUTE"),
						percent,
						progressCounter,
						totalCount)
				}
				bruteMu.Unlock()

				if err == nil {

					bruteMu.Lock()
					foundCount++
					validSubdomains = append(validSubdomains, fqdn)
					bruteMu.Unlock()
				}
			}(subdomain)
		}

		wg.Wait()
		fmt.Printf("\n[%s] %s valid subdomains found via bruteforcing\n",
			color.CyanString("INFO"),
			color.GreenString("%d", foundCount))

		mu.Lock()
		for _, subdomain := range validSubdomains {
			findings = append(findings, output.Finding{
				Type:	"subdomain",
				Data: map[string]interface{}{
					"subdomain":	subdomain,
					"source":	"bruteforce",
				},
			})
		}
		mu.Unlock()
	}

	if e.config.DisableAPISources {
		return findings, nil
	}

	sources := e.config.Sources
	if len(sources) == 0 {

		sources = GetAvailableSources(e.config)
	}

	rateLimiter := NewRateLimiter(10)
	defer rateLimiter.Stop()

	ctx := context.Background()
	if e.config.Debug {
		fmt.Printf("\n%s Enumerating subdomains from the following sources:\n",
			color.CyanString("[DEBUG]"))
	}

	for _, source := range sources {
		wg.Add(1)
		go func(source string) {
			defer wg.Done()
			var subdomains []string
			var err error

			rateLimiter.Wait(source)

			switch source {
			case "crtsh":
				subdomains, err = e.enumCrtSh(ctx, e.client)
			case "hackertarget":
				subdomains, err = e.enumHackertarget(ctx, e.client)
			case "alienvault":
				subdomains, err = e.enumAlienvault(ctx, e.client)
			case "urlscan":
				subdomains, err = e.enumUrlscan(ctx, e.client)
			case "bufferover":
				subdomains, err = e.enumBufferover(ctx, e.client)
			case "threatminer":
				subdomains, err = e.enumThreatminer(ctx, e.client)
			case "riddler":
				subdomains, err = e.enumRiddler(ctx, e.client)
			case "wayback":
				subdomains, err = e.enumWayback(ctx, e.client)
			case "commoncrawl":
				subdomains, err = e.enumCommonCrawl(ctx, e.client)
			case "certspotter":
				subdomains, err = e.enumCertSpotter(ctx, e.client)
			case "anubis":
				subdomains, err = e.enumAnubis(ctx, e.client)
			case "leakix":
				subdomains, err = e.enumLeakix(ctx, e.client)
			case "netlas":
				subdomains, err = e.enumNetlas(ctx, e.client)
			case "securitytrails":
				subdomains, err = e.enumSecurityTrails(ctx, e.client)
			case "shodan":
				subdomains, err = e.enumShodan(ctx, e.client)
			case "censys":
				subdomains, err = e.enumCensys(ctx, e.client)
			case "virustotal":
				subdomains, err = e.enumVirusTotal(ctx, e.client)
			case "threatcrowd":
				subdomains, err = e.enumThreatCrowd(ctx, e.client)
			case "rapiddns":
				subdomains, err = e.enumRapidDNS(ctx, e.client)
			case "facebookct":
				subdomains, err = e.enumFacebookCT(ctx, e.client)
			case "dnsdumpster":
				subdomains, err = e.enumDNSDumpster(ctx, e.client)
			case "chaos":
				subdomains, err = e.enumChaos(ctx, e.client)
			case "spyse":
				subdomains, err = e.enumSpyse(ctx, e.client)
			case "fullhunt":
				subdomains, err = e.enumFullHunt(ctx, e.client)
			case "binaryedge":
				subdomains, err = e.enumBinaryEdge(ctx, e.client)
			case "threatbook":
				subdomains, err = e.enumThreatBook(ctx, e.client)
			case "intelx":
				subdomains, err = e.enumIntelX(ctx, e.client)

			case "c99":
				subdomains, err = e.enumC99(ctx, e.client)
			case "bevigil":
				subdomains, err = e.enumBeVigil(ctx, e.client)
			case "chinaz":
				subdomains, err = e.enumChinaz(ctx, e.client)
			case "digitalyama":
				subdomains, err = e.enumDigitalYama(ctx, e.client)
			case "dnsdb":
				subdomains, err = e.enumDNSDB(ctx, e.client)
			case "dnsrepo":
				subdomains, err = e.enumDNSRepo(ctx, e.client)
			case "fofa":
				subdomains, err = e.enumFOFA(ctx, e.client)
			case "github":
				subdomains, err = e.enumGitHub(ctx, e.client)
			case "hunter":
				subdomains, err = e.enumHunter(ctx, e.client)
			case "quake":
				subdomains, err = e.enumQuake(ctx, e.client)
			case "redhuntlabs":
				subdomains, err = e.enumRedHuntLabs(ctx, e.client)
			case "robtex":
				subdomains, err = e.enumRobtex(ctx, e.client)
			case "sitedossier":
				subdomains, err = e.enumSiteDossier(ctx, e.client)
			case "whoisxmlapi":
				subdomains, err = e.enumWhoisXMLAPI(ctx, e.client)
			case "zoomeye":
				subdomains, err = e.enumZoomEye(ctx, e.client)
			case "facebook":
				subdomains, err = e.enumFacebook(ctx, e.client)
			case "builtwith":
				subdomains, err = e.enumBuiltWith(ctx, e.client)
			case "hudsonrock":
				subdomains, err = e.enumHudsonRock(ctx, e.client)
			case "digitorus":
				subdomains, err = e.enumDigitorus(ctx, e.client)
			}

			if err != nil {

				if e.config.Debug {
					fmt.Printf("[%s] Error from %s: %v\n",
						color.CyanString("DEBUG"),
						source,
						err)
				}

				if len(progress) > 0 {
					progress[0].UpdateProgress(source, 0)
				}
				return
			}

			if len(progress) > 0 {
				progress[0].UpdateProgress(source, len(subdomains))
			}

			if len(subdomains) > 0 {
				fmt.Printf("[%s] %s found %s subdomains\n",
					color.CyanString("INFO"),
					color.MagentaString(source),
					color.GreenString("%d", len(subdomains)))
			}

			mu.Lock()
			for _, subdomain := range subdomains {
				findings = append(findings, output.Finding{
					Type:	"subdomain",
					Data: map[string]interface{}{
						"subdomain":	subdomain,
						"source":	source,
					},
				})
			}
			mu.Unlock()
		}(source)
	}

	wg.Wait()
	return findings, nil
}

func (e *Enum) createHTTPClient(timeout int) *http.Client {
	return &http.Client{
		Timeout:	time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func (e *Enum) enumHackertarget(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(hackertargetAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "hackertarget")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(body), "\n")
	subdomains := make(map[string]bool)
	for _, line := range lines {
		if line != "" && strings.Contains(line, e.target) {
			parts := strings.Split(line, ",")
			if len(parts) > 0 {
				domain := parts[0]
				if strings.HasSuffix(domain, e.target) && e.isValidSubdomain(domain) {
					subdomains[domain] = true
				}
			}
		}
	}

	var result []string
	for sub := range subdomains {
		result = append(result, sub)
	}

	return result, nil
}

func (e *Enum) enumBufferover(ctx context.Context, client *http.Client) ([]string, error) {
	type bufferoverResp struct {
		FDNS	[]string	`json:"FDNS_A"`
		RDNS	[]string	`json:"RDNS"`
	}

	url := fmt.Sprintf(bufferoverAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result bufferoverResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, record := range append(result.FDNS, result.RDNS...) {
		parts := strings.Split(record, ",")
		if len(parts) > 0 && strings.HasSuffix(parts[0], e.target) {
			subdomains[parts[0]] = true
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}

	return subs, nil
}

func (e *Enum) enumAlienvault(ctx context.Context, client *http.Client) ([]string, error) {
	type alienvaultResp struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}

	url := fmt.Sprintf(alienvaultAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "alienvault")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result alienvaultResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, record := range result.PassiveDNS {
		if strings.HasSuffix(record.Hostname, e.target) && e.isValidSubdomain(record.Hostname) {
			subdomains[record.Hostname] = true
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}

	return subs, nil
}

func (e *Enum) enumUrlscan(ctx context.Context, client *http.Client) ([]string, error) {
	type urlscanResp struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}

	url := fmt.Sprintf(urlscanAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "urlscan")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result urlscanResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, entry := range result.Results {
		if strings.HasSuffix(entry.Page.Domain, e.target) && e.isValidSubdomain(entry.Page.Domain) {
			subdomains[entry.Page.Domain] = true
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}

	return subs, nil
}

func (e *Enum) enumThreatminer(ctx context.Context, client *http.Client) ([]string, error) {
	type threatminerResp struct {
		Results []string `json:"results"`
	}

	url := fmt.Sprintf(threatminerAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result threatminerResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, sub := range result.Results {
		if strings.HasSuffix(sub, e.target) {
			subdomains[sub] = true
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}

	return subs, nil
}

func (e *Enum) enumRiddler(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(riddlerAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	subdomains := make(map[string]bool)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasSuffix(line, e.target) {
			subdomains[line] = true
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}

	return subs, nil
}

func (e *Enum) enumWayback(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(waybackAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var results [][]string
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, result := range results {
		if len(result) > 0 {
			if domain := extractDomain(result[0]); domain != "" && strings.HasSuffix(domain, e.target) {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}

	return subs, nil
}

func (e *Enum) enumSecurityTrails(ctx context.Context, client *http.Client) ([]string, error) {
	if e.config.SecurityTrailsAPIKey == "" {
		return nil, fmt.Errorf("API key required")
	}

	url := fmt.Sprintf(securitytrailsAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("apikey", e.config.SecurityTrailsAPIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securitytrails API error: %d", resp.StatusCode)
	}

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var subs []string
	for _, sub := range result.Subdomains {
		subs = append(subs, sub+"."+e.target)
	}

	return subs, nil
}

func (e *Enum) enumCensys(ctx context.Context, client *http.Client) ([]string, error) {
	if e.config.CensysAPIKey == "" || e.config.CensysAPISecret == "" {
		return nil, fmt.Errorf("censys API credentials required")
	}

	url := fmt.Sprintf(censysAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(e.config.CensysAPIKey, e.config.CensysAPISecret)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("censys API error: %d", resp.StatusCode)
	}

	var result struct {
		Services []struct {
			Port	int	`json:"port"`
			Name	string	`json:"service_name"`
		} `json:"services"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var subs []string
	for _, service := range result.Services {
		if service.Name == "http" || service.Name == "https" {
			subs = append(subs, e.target)
		}
	}

	return subs, nil
}

func (e *Enum) enumShodan(ctx context.Context, client *http.Client) ([]string, error) {
	if e.config.ShodanAPIKey == "" {
		return nil, fmt.Errorf("API key required")
	}

	url := fmt.Sprintf(shodanAPI, e.target, e.config.ShodanAPIKey)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan API error: %d", resp.StatusCode)
	}

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var subs []string
	for _, sub := range result.Subdomains {
		subs = append(subs, sub+"."+e.target)
	}

	return subs, nil
}

func (e *Enum) isValidSubdomain(subdomain string) bool {
	if len(e.config.MatchSubdomains) > 0 {
		matched := false
		for _, pattern := range e.config.MatchSubdomains {
			if matchSubdomain(subdomain, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(e.config.FilterSubdomains) > 0 {
		for _, pattern := range e.config.FilterSubdomains {
			if matchSubdomain(subdomain, pattern) {
				return false
			}
		}
	}

	return true
}

func extractDomain(url string) string {
	url = strings.ToLower(url)
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "www.")

	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	return url
}

func matchSubdomain(subdomain, pattern string) bool {
	pattern = strings.TrimPrefix(pattern, "*.")
	return strings.HasSuffix(subdomain, pattern)
}

func (e *Enum) enumCommonCrawl(ctx context.Context, client *http.Client) ([]string, error) {
	type commonCrawlResp struct {
		URL string `json:"url"`
	}

	url := fmt.Sprintf(commoncrawlAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	subdomains := make(map[string]bool)

	for scanner.Scan() {
		var result commonCrawlResp
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			continue
		}

		if domain := extractSubdomain(result.URL, e.target); domain != "" {
			subdomains[domain] = true
		}
	}

	var result []string
	for sub := range subdomains {
		result = append(result, sub)
	}

	return result, nil
}

func extractSubdomain(url, target string) string {
	url = strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	if strings.HasSuffix(url, target) && url != target {
		return url
	}
	return ""
}

func (e *Enum) enumCertSpotter(ctx context.Context, client *http.Client) ([]string, error) {
	type certSpotterResp struct {
		DNSNames []string `json:"dns_names"`
	}

	url := fmt.Sprintf(certspotterAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var results []certSpotterResp
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, result := range results {
		for _, name := range result.DNSNames {
			if strings.HasSuffix(name, e.target) && name != e.target {
				subdomains[name] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumAnubis(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(anubisAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var subdomains []string
	if err := json.NewDecoder(resp.Body).Decode(&subdomains); err != nil {
		return nil, err
	}

	return subdomains, nil
}

func (e *Enum) enumLeakix(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(leakixAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, e.target) {
			domain := strings.TrimSpace(line)
			if strings.HasSuffix(domain, e.target) && domain != e.target {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumNetlas(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(netlasAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, sub := range result.Subdomains {
		if sub != "" {
			subdomains = append(subdomains, sub+"."+e.target)
		}
	}

	return subdomains, nil
}

func (e *Enum) enumVirusTotal(ctx context.Context, client *http.Client) ([]string, error) {
	if e.config.VirusTotalAPIKey == "" {
		return nil, fmt.Errorf("API key required")
	}

	url := fmt.Sprintf(virusTotalAPI, e.config.VirusTotalAPIKey, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-apikey", e.config.VirusTotalAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal API error: %d", resp.StatusCode)
	}

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Subdomains, nil
}

func (e *Enum) enumThreatCrowd(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(threatCrowdAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatcrowd API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, e.target) {
			domain := strings.TrimSpace(line)
			if strings.HasSuffix(domain, e.target) && domain != e.target {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumRapidDNS(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(rapidDNSAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rapiddns API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, e.target) {
			domain := strings.TrimSpace(line)
			if strings.HasSuffix(domain, e.target) && domain != e.target {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumFacebookCT(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(facebookCTAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facebookct API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, e.target) {
			domain := strings.TrimSpace(line)
			if strings.HasSuffix(domain, e.target) && domain != e.target && e.isValidSubdomain(domain) {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumDNSDumpster(ctx context.Context, client *http.Client) ([]string, error) {
	url := dnsDumpsterAPI
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dnsdumpster API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, e.target) {
			domain := strings.TrimSpace(line)
			if strings.HasSuffix(domain, e.target) && domain != e.target && e.isValidSubdomain(domain) {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumChaos(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(chaosAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chaos API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, e.target) {
			domain := strings.TrimSpace(line)
			if strings.HasSuffix(domain, e.target) && domain != e.target && e.isValidSubdomain(domain) {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumSpyse(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(spyseAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("spyse API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, e.target) {
			domain := strings.TrimSpace(line)
			if strings.HasSuffix(domain, e.target) && domain != e.target {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumFullHunt(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(fullHuntAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fullhunt API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, e.target) {
			domain := strings.TrimSpace(line)
			if strings.HasSuffix(domain, e.target) && domain != e.target {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumBinaryEdge(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(binaryEdgeAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("binaryedge API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, e.target) {
			domain := strings.TrimSpace(line)
			if strings.HasSuffix(domain, e.target) && domain != e.target {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumThreatBook(ctx context.Context, client *http.Client) ([]string, error) {
	if e.config.ThreatBookAPIKey == "" {
		return nil, fmt.Errorf("threatbook API key required")
	}

	url := fmt.Sprintf(threatBookAPI, e.config.ThreatBookAPIKey, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatbook API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, e.target) {
			domain := strings.TrimSpace(line)
			if strings.HasSuffix(domain, e.target) && domain != e.target {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumIntelX(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(intelxAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("intelx API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	subdomains := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, e.target) {
			domain := strings.TrimSpace(line)
			if strings.HasSuffix(domain, e.target) && domain != e.target {
				subdomains[domain] = true
			}
		}
	}

	var subs []string
	for sub := range subdomains {
		subs = append(subs, sub)
	}
	return subs, nil
}

func (e *Enum) enumC99(ctx context.Context, client *http.Client) ([]string, error) {

	apiKey := e.config.APIKeys["c99"]
	if apiKey == "" {
		return nil, fmt.Errorf("c99 API key required")
	}

	url := fmt.Sprintf(c99API, apiKey, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "c99")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Subdomains, nil
}

func (e *Enum) enumBeVigil(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["bevigil"]
	if apiKey == "" {
		return nil, fmt.Errorf("bevigil API key required")
	}

	url := fmt.Sprintf(bevigilAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-API-KEY", apiKey)

	resp, err := e.makeRequest(ctx, client, req, "bevigil")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Subdomains, nil
}

func (e *Enum) enumChinaz(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["chinaz"]
	if apiKey == "" {
		return nil, fmt.Errorf("chinaz API key required")
	}

	url := fmt.Sprintf(chinazAPI, apiKey, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "chinaz")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			Domain string `json:"domain"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, entry := range result.Data {
		subdomains = append(subdomains, entry.Domain)
	}

	return subdomains, nil
}

func (e *Enum) enumDigitalYama(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["digitalyama"]
	if apiKey == "" {
		return nil, fmt.Errorf("digitalyama API key required")
	}

	url := fmt.Sprintf(digitalyamaAPI, e.target, apiKey)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "digitalyama")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Subdomains, nil
}

func (e *Enum) enumDNSDB(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["dnsdb"]
	if apiKey == "" {
		return nil, fmt.Errorf("dnsdb API key required")
	}

	url := fmt.Sprintf(dnsdbAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-API-KEY", apiKey)

	resp, err := e.makeRequest(ctx, client, req, "dnsdb")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	var subdomains []string

	for scanner.Scan() {
		var result struct {
			Rrname string `json:"rrname"`
		}

		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			continue
		}

		domain := strings.TrimSuffix(result.Rrname, ".")
		if strings.Contains(domain, e.target) && e.isValidSubdomain(domain) {
			subdomains = append(subdomains, domain)
		}
	}

	return subdomains, nil
}

func (e *Enum) enumDNSRepo(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["dnsrepo"]
	if apiKey == "" {
		return nil, fmt.Errorf("dnsrepo API key required")
	}

	url := fmt.Sprintf(dnsrepoAPI, e.target, apiKey)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "dnsrepo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Subdomains, nil
}

func (e *Enum) enumFOFA(ctx context.Context, client *http.Client) ([]string, error) {
	email := e.config.APIKeys["fofa_email"]
	apiKey := e.config.APIKeys["fofa"]
	if email == "" || apiKey == "" {
		return nil, fmt.Errorf("fofa API credentials required")
	}

	query := fmt.Sprintf("domain=\"%s\"", e.target)
	queryBase64 := base64.StdEncoding.EncodeToString([]byte(query))

	url := fmt.Sprintf(fofaAPI, email, apiKey, queryBase64)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "fofa")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Results [][]string `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, entry := range result.Results {
		if len(entry) > 0 {
			domain := entry[0]
			if strings.HasSuffix(domain, e.target) && e.isValidSubdomain(domain) {
				subdomains = append(subdomains, domain)
			}
		}
	}

	return subdomains, nil
}

func (e *Enum) enumGitHub(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["github"]
	if apiKey == "" {
		return nil, fmt.Errorf("github API key required")
	}

	url := fmt.Sprintf(githubAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "token "+apiKey)

	resp, err := e.makeRequest(ctx, client, req, "github")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Items []struct {
			HTMLURL string `json:"html_url"`
		} `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	subdomainSet := make(map[string]bool)

	for _, item := range result.Items {

		domainPattern := regexp.MustCompile(`https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)*` + regexp.QuoteMeta(e.target))
		matches := domainPattern.FindAllStringSubmatch(item.HTMLURL, -1)
		for _, match := range matches {
			if len(match) > 0 {
				domain := strings.TrimPrefix(match[0], "http://")
				domain = strings.TrimPrefix(domain, "https://")
				if e.isValidSubdomain(domain) {
					subdomainSet[domain] = true
				}
			}
		}
	}

	var subdomains []string
	for subdomain := range subdomainSet {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

func (e *Enum) enumHunter(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["hunter"]
	if apiKey == "" {
		return nil, fmt.Errorf("hunter API key required")
	}

	url := fmt.Sprintf(hunterAPI, e.target, apiKey)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "hunter")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			Emails []struct {
				Value		string	`json:"value"`
				Domain		string	`json:"domain"`
				Verified	bool	`json:"verified"`
			} `json:"emails"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	subdomainSet := make(map[string]bool)
	for _, email := range result.Data.Emails {
		if email.Domain != "" && strings.HasSuffix(email.Domain, e.target) && e.isValidSubdomain(email.Domain) {
			subdomainSet[email.Domain] = true
		}
	}

	var subdomains []string
	for subdomain := range subdomainSet {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

func (e *Enum) enumQuake(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["quake"]
	if apiKey == "" {
		return nil, fmt.Errorf("quake API key required")
	}

	url := fmt.Sprintf(quakeAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-QuakeToken", apiKey)

	resp, err := e.makeRequest(ctx, client, req, "quake")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			Domain		string		`json:"domain"`
			Subdomains	[]string	`json:"subdomains"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, data := range result.Data {
		for _, subdomain := range data.Subdomains {
			fullDomain := subdomain + "." + data.Domain
			if e.isValidSubdomain(fullDomain) {
				subdomains = append(subdomains, fullDomain)
			}
		}
	}

	return subdomains, nil
}

func (e *Enum) enumRedHuntLabs(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["redhuntlabs"]
	if apiKey == "" {
		return nil, fmt.Errorf("redhuntlabs API key required")
	}

	url := fmt.Sprintf(redhuntlabsAPI, e.target, apiKey)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "redhuntlabs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Subdomains, nil
}

func (e *Enum) enumRobtex(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(robtexAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "robtex")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var results []struct {
		Rrname string `json:"rrname"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	subdomainSet := make(map[string]bool)
	for _, result := range results {
		domain := strings.TrimSuffix(result.Rrname, ".")
		if strings.HasSuffix(domain, e.target) && e.isValidSubdomain(domain) {
			subdomainSet[domain] = true
		}
	}

	var subdomains []string
	for subdomain := range subdomainSet {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

func (e *Enum) enumSiteDossier(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(sitedossierAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "sitedossier")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`<a href="/site/([^"]+)">`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	subdomainSet := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 {
			domain := match[1]
			if strings.HasSuffix(domain, e.target) && e.isValidSubdomain(domain) {
				subdomainSet[domain] = true
			}
		}
	}

	var subdomains []string
	for subdomain := range subdomainSet {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

func (e *Enum) enumWhoisXMLAPI(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["whoisxmlapi"]
	if apiKey == "" {
		return nil, fmt.Errorf("whoisxmlapi API key required")
	}

	url := fmt.Sprintf(whoisxmlapiAPI, apiKey, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "whoisxmlapi")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Result struct {
			Records []struct {
				Domain string `json:"domain"`
			} `json:"records"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, record := range result.Result.Records {
		if e.isValidSubdomain(record.Domain) {
			subdomains = append(subdomains, record.Domain)
		}
	}

	return subdomains, nil
}

func (e *Enum) enumZoomEye(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["zoomeye"]
	if apiKey == "" {
		return nil, fmt.Errorf("zoomeye API key required")
	}

	url := fmt.Sprintf(zoomeyeAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("API-KEY", apiKey)

	resp, err := e.makeRequest(ctx, client, req, "zoomeye")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Matches []struct {
			Name string `json:"name"`
		} `json:"matches"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, match := range result.Matches {
		if strings.HasSuffix(match.Name, e.target) && e.isValidSubdomain(match.Name) {
			subdomains = append(subdomains, match.Name)
		}
	}

	return subdomains, nil
}

func (e *Enum) enumFacebook(ctx context.Context, client *http.Client) ([]string, error) {
	accessToken := e.config.APIKeys["facebook"]
	if accessToken == "" {
		return nil, fmt.Errorf("facebook access token required")
	}

	url := fmt.Sprintf(facebookAPI, e.target, accessToken)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "facebook")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			DomainNames []string `json:"domain_names"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	subdomainSet := make(map[string]bool)
	for _, cert := range result.Data {
		for _, domain := range cert.DomainNames {
			if strings.HasSuffix(domain, e.target) && e.isValidSubdomain(domain) {
				subdomainSet[domain] = true
			}
		}
	}

	var subdomains []string
	for subdomain := range subdomainSet {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

func (e *Enum) enumBuiltWith(ctx context.Context, client *http.Client) ([]string, error) {
	apiKey := e.config.APIKeys["builtwith"]
	if apiKey == "" {
		return nil, fmt.Errorf("builtwith API key required")
	}

	url := fmt.Sprintf(builtwithAPI, apiKey, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "builtwith")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Results []struct {
			Result struct {
				Domains []struct {
					Domain string `json:"Domain"`
				} `json:"SubDomains"`
			} `json:"Result"`
		} `json:"Results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, domainResult := range result.Results {
		for _, domain := range domainResult.Result.Domains {
			if e.isValidSubdomain(domain.Domain) {
				subdomains = append(subdomains, domain.Domain)
			}
		}
	}

	return subdomains, nil
}

func (e *Enum) enumHudsonRock(ctx context.Context, client *http.Client) ([]string, error) {
	url := fmt.Sprintf(hudsonrockAPI, e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "hudsonrock")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Subdomains, nil
}

func (e *Enum) enumDigitorus(ctx context.Context, client *http.Client) ([]string, error) {

	url := fmt.Sprintf("https://api.digitorus.com/passive-dns/%s", e.target)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.makeRequest(ctx, client, req, "digitorus")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var results []struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, result := range results {
		if strings.HasSuffix(result.Name, e.target) && e.isValidSubdomain(result.Name) {
			subdomains = append(subdomains, result.Name)
		}
	}

	return subdomains, nil
}

func GetAllSourceNames() []string {

	sourceInfo := GetSourcesInfo()
	allSources := make([]string, 0, len(sourceInfo))

	for name := range sourceInfo {
		allSources = append(allSources, name)
	}

	return allSources
}

func IsSourcePremium(sourceName string) bool {
	sourceInfo := GetSourcesInfo()
	if info, exists := sourceInfo[strings.ToLower(sourceName)]; exists {
		return info.RequiresKey
	}
	return false
}

func ValidateSources(sources []string) ([]string, []string) {
	validSources := []string{}
	invalidSources := []string{}

	allSources := GetAllSourceNames()
	allSourcesLower := make(map[string]string)

	for _, s := range allSources {
		allSourcesLower[strings.ToLower(s)] = s
	}

	for _, s := range sources {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		if correctCase, exists := allSourcesLower[strings.ToLower(s)]; exists {
			validSources = append(validSources, correctCase)
		} else {
			invalidSources = append(invalidSources, s)
		}
	}

	return validSources, invalidSources
}

func CountSourceTypes(sources []string) (int, int) {
	freeCount := 0
	premiumCount := 0

	for _, source := range sources {
		if IsSourcePremium(source) {
			premiumCount++
		} else {
			freeCount++
		}
	}

	return freeCount, premiumCount
}

// GetAvailableSources returns a list of all free sources plus premium sources with valid API keys
func GetAvailableSources(config config.SubdomainConfig) []string {
	sourceInfo := GetSourcesInfo()
	availableSources := make([]string, 0, len(sourceInfo))

	for name, info := range sourceInfo {
		if !info.RequiresKey {
			availableSources = append(availableSources, name)
		}
	}

	validKeys := make(map[string]bool)

	if config.SecurityTrailsAPIKey != "" {
		validKeys["securitytrails"] = true
	}
	if config.ShodanAPIKey != "" {
		validKeys["shodan"] = true
	}
	if config.CensysAPIKey != "" && config.CensysAPISecret != "" {
		validKeys["censys"] = true
	}
	if config.VirusTotalAPIKey != "" {
		validKeys["virustotal"] = true
	}
	if config.BinaryEdgeAPIKey != "" {
		validKeys["binaryedge"] = true
	}
	if config.FullHuntAPIKey != "" {
		validKeys["fullhunt"] = true
	}
	if config.SpyseAPIKey != "" {
		validKeys["spyse"] = true
	}
	if config.NetlasAPIKey != "" {
		validKeys["netlas"] = true
	}
	if config.LeakixAPIKey != "" {
		validKeys["leakix"] = true
	}
	if config.ThreatBookAPIKey != "" {
		validKeys["threatbook"] = true
	}

	for key, value := range config.APIKeys {
		key = strings.ToLower(key)
		if value != "" && !strings.Contains(value, "YOUR_") {
			validKeys[key] = true
		}
	}

	for name, info := range sourceInfo {
		if info.RequiresKey {
			name = strings.ToLower(name)
			if validKeys[name] {
				availableSources = append(availableSources, name)
			}
		}
	}

	return availableSources
}
