package dnsenum

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/miekg/dns"
	"github.com/zarni99/bbrecon/pkg/output"
)

type Config struct {
	RecordTypes		[]string
	ResolverIPs		[]string
	Timeout			int
	IncludeWildcards	bool
	VerifyResults		bool
	CheckTakeover		bool
	ResolvePTR		bool
	Debug			bool
	AllRecords		bool
}

type DNSRecord struct {
	Domain		string
	RecordType	string
	Value		string
	TTL		uint32
	Priority	uint16
	IssueFound	bool
	IssueType	string
}

type DNSResult struct {
	Domain	string
	Results	[]output.Finding
	Error	error
}

type SecurityIssue struct {
	Domain		string
	RecordType	string
	Description	string
	Severity	string
}

type Enumerator struct {
	domain		string
	config		Config
	timeout		time.Duration
	resolvers	[]string
	records		[]DNSRecord
	securityIssues	[]SecurityIssue
	recordsMux	sync.Mutex
	issuesMux	sync.Mutex
	debug		bool
}

var DefaultResolvers = []string{
	"8.8.8.8:53",
	"8.8.4.4:53",
	"1.1.1.1:53",
	"9.9.9.9:53",
	"208.67.222.222:53",
}

var AllRecordTypes = []string{
	"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA",
	"SRV", "CAA", "PTR", "DNSKEY", "DS", "NAPTR", "NSEC",
	"NSEC3", "RRSIG", "SPF", "SSHFP",
}

var CommonRecordTypes = []string{
	"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA",
}

func NewEnumerator(domain string, config Config, timeout int) *Enumerator {

	resolvers := config.ResolverIPs
	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}

	if len(config.RecordTypes) == 0 {
		if config.AllRecords {
			config.RecordTypes = AllRecordTypes
		} else {
			config.RecordTypes = CommonRecordTypes
		}
	}

	return &Enumerator{
		domain:		domain,
		config:		config,
		timeout:	time.Duration(timeout) * time.Second,
		resolvers:	resolvers,
		debug:		config.Debug,
	}
}

func (e *Enumerator) Run() ([]output.Finding, error) {
	var wg sync.WaitGroup

	if e.debug {
		fmt.Printf("%s Querying DNS records for %s\n", color.HiCyanString("DNS:"), color.HiWhiteString(e.domain))
		fmt.Printf("%s Using %d record types and %d resolvers\n",
			color.HiCyanString("DNS:"),
			len(e.config.RecordTypes),
			len(e.resolvers))
	}

	for _, recordType := range e.config.RecordTypes {
		wg.Add(1)
		go func(rt string) {
			defer wg.Done()
			e.queryRecordType(rt)
		}(recordType)
	}

	wg.Wait()

	e.analyzeSecurityIssues()

	return e.convertToFindings(), nil
}

func (e *Enumerator) queryRecordType(recordType string) {
	var results []DNSRecord

	c := new(dns.Client)
	c.Timeout = e.timeout

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(e.domain), dnsTypeFromString(recordType))
	m.RecursionDesired = true

	var resp *dns.Msg
	var err error
	for _, resolver := range e.resolvers {
		resp, _, err = c.Exchange(m, resolver)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			break
		}
	}

	if err != nil || resp == nil {
		if e.debug {
			fmt.Printf("%s Error querying %s records: %v\n",
				color.HiRedString("DNS ERROR:"),
				recordType,
				err)
		}
		return
	}

	for _, answer := range resp.Answer {
		record := e.parseAnswer(answer)
		if record != nil {
			results = append(results, *record)
		}
	}

	if len(results) > 0 {
		e.recordsMux.Lock()
		e.records = append(e.records, results...)
		e.recordsMux.Unlock()

		if e.debug {
			fmt.Printf("%s Found %d %s records\n",
				color.HiGreenString("DNS:"),
				len(results),
				recordType)
		}
	}
}

func (e *Enumerator) parseAnswer(answer dns.RR) *DNSRecord {
	var record DNSRecord
	record.Domain = e.domain

	switch rr := answer.(type) {
	case *dns.A:
		record.RecordType = "A"
		record.Value = rr.A.String()
		record.TTL = rr.Hdr.Ttl

	case *dns.AAAA:
		record.RecordType = "AAAA"
		record.Value = rr.AAAA.String()
		record.TTL = rr.Hdr.Ttl

	case *dns.CNAME:
		record.RecordType = "CNAME"
		record.Value = rr.Target
		record.TTL = rr.Hdr.Ttl

	case *dns.MX:
		record.RecordType = "MX"
		record.Value = fmt.Sprintf("%d %s", rr.Preference, rr.Mx)
		record.TTL = rr.Hdr.Ttl
		record.Priority = rr.Preference

	case *dns.NS:
		record.RecordType = "NS"
		record.Value = rr.Ns
		record.TTL = rr.Hdr.Ttl

	case *dns.TXT:
		record.RecordType = "TXT"
		record.Value = strings.Join(rr.Txt, " ")
		record.TTL = rr.Hdr.Ttl

	case *dns.SOA:
		record.RecordType = "SOA"
		record.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
			rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)
		record.TTL = rr.Hdr.Ttl

	case *dns.SRV:
		record.RecordType = "SRV"
		record.Value = fmt.Sprintf("%d %d %d %s",
			rr.Priority, rr.Weight, rr.Port, rr.Target)
		record.TTL = rr.Hdr.Ttl
		record.Priority = rr.Priority

	case *dns.CAA:
		record.RecordType = "CAA"
		record.Value = fmt.Sprintf("%d %s \"%s\"", rr.Flag, rr.Tag, rr.Value)
		record.TTL = rr.Hdr.Ttl

	case *dns.PTR:
		record.RecordType = "PTR"
		record.Value = rr.Ptr
		record.TTL = rr.Hdr.Ttl

	default:
		return nil
	}

	return &record
}

func (e *Enumerator) analyzeSecurityIssues() {
	e.checkSPFRecords()
	e.checkDMARCRecords()
	e.checkCAARecords()
	e.checkNameservers()
	e.checkSubdomainTakeover()
}

func (e *Enumerator) checkSPFRecords() {
	var spfRecords []DNSRecord

	e.recordsMux.Lock()
	for _, record := range e.records {
		if record.RecordType == "TXT" && strings.HasPrefix(record.Value, "v=spf1") {
			spfRecords = append(spfRecords, record)
		}
	}
	e.recordsMux.Unlock()

	if len(spfRecords) == 0 {

		e.addSecurityIssue(SecurityIssue{
			Domain:		e.domain,
			RecordType:	"SPF",
			Description:	"No SPF record found. This allows email spoofing.",
			Severity:	"medium",
		})
		return
	}

	if len(spfRecords) > 1 {

		e.addSecurityIssue(SecurityIssue{
			Domain:		e.domain,
			RecordType:	"SPF",
			Description:	fmt.Sprintf("Multiple SPF records found (%d). This is invalid per RFC and may cause inconsistent behavior.", len(spfRecords)),
			Severity:	"medium",
		})
	}

	for _, record := range spfRecords {
		value := record.Value

		if strings.Contains(value, " ~all") {
			e.addSecurityIssue(SecurityIssue{
				Domain:		e.domain,
				RecordType:	"SPF",
				Description:	"SPF record uses soft fail (~all) instead of hard fail (-all).",
				Severity:	"low",
			})
		}

		if strings.Contains(value, " ?all") || strings.Contains(value, " +all") {
			e.addSecurityIssue(SecurityIssue{
				Domain:		e.domain,
				RecordType:	"SPF",
				Description:	"SPF record uses neutral (?all) or allow all (+all), allowing email spoofing.",
				Severity:	"high",
			})
		}

		lookupCount := 0
		lookupCount += strings.Count(value, " include:")
		lookupCount += strings.Count(value, " a:")
		lookupCount += strings.Count(value, " mx:")
		lookupCount += strings.Count(value, " redirect=")
		lookupCount += strings.Count(value, " exists:")

		if lookupCount > 10 {
			e.addSecurityIssue(SecurityIssue{
				Domain:		e.domain,
				RecordType:	"SPF",
				Description:	fmt.Sprintf("SPF record has %d DNS lookups (RFC maximum is 10).", lookupCount),
				Severity:	"medium",
			})
		}
	}
}

func (e *Enumerator) checkDMARCRecords() {
	var dmarcRecords []DNSRecord

	dmarcDomain := "_dmarc." + e.domain
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dmarcDomain), dns.TypeTXT)
	m.RecursionDesired = true

	var resp *dns.Msg
	var err error
	for _, resolver := range e.resolvers {
		resp, _, err = c.Exchange(m, resolver)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			break
		}
	}

	if err != nil || resp == nil {

		e.addSecurityIssue(SecurityIssue{
			Domain:		e.domain,
			RecordType:	"DMARC",
			Description:	"No DMARC record found. This reduces email security and allows spoofing.",
			Severity:	"medium",
		})
		return
	}

	for _, answer := range resp.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			value := strings.Join(txt.Txt, "")
			if strings.HasPrefix(value, "v=DMARC1") {
				dmarcRecords = append(dmarcRecords, DNSRecord{
					Domain:		dmarcDomain,
					RecordType:	"DMARC",
					Value:		value,
					TTL:		txt.Hdr.Ttl,
				})
			}
		}
	}

	if len(dmarcRecords) == 0 {

		e.addSecurityIssue(SecurityIssue{
			Domain:		e.domain,
			RecordType:	"DMARC",
			Description:	"No valid DMARC record found with prefix 'v=DMARC1'.",
			Severity:	"medium",
		})
		return
	}

	for _, record := range dmarcRecords {
		value := record.Value

		if strings.Contains(value, "p=none") {
			e.addSecurityIssue(SecurityIssue{
				Domain:		e.domain,
				RecordType:	"DMARC",
				Description:	"DMARC policy set to 'none', which only monitors but doesn't prevent email spoofing.",
				Severity:	"medium",
			})
		}

		if !strings.Contains(value, "rua=") && !strings.Contains(value, "ruf=") {
			e.addSecurityIssue(SecurityIssue{
				Domain:		e.domain,
				RecordType:	"DMARC",
				Description:	"DMARC record doesn't include reporting addresses (rua/ruf).",
				Severity:	"low",
			})
		}

		e.recordsMux.Lock()
		e.records = append(e.records, record)
		e.recordsMux.Unlock()
	}
}

func (e *Enumerator) checkCAARecords() {
	var caaRecords []DNSRecord

	e.recordsMux.Lock()
	for _, record := range e.records {
		if record.RecordType == "CAA" {
			caaRecords = append(caaRecords, record)
		}
	}
	e.recordsMux.Unlock()

	if len(caaRecords) == 0 {
		e.addSecurityIssue(SecurityIssue{
			Domain:		e.domain,
			RecordType:	"CAA",
			Description:	"No CAA records found. CAA records help control which CAs can issue certificates for your domain.",
			Severity:	"low",
		})
	}
}

func (e *Enumerator) checkNameservers() {
	var nsRecords []DNSRecord

	e.recordsMux.Lock()
	for _, record := range e.records {
		if record.RecordType == "NS" {
			nsRecords = append(nsRecords, record)
		}
	}
	e.recordsMux.Unlock()

	if len(nsRecords) < 2 {
		e.addSecurityIssue(SecurityIssue{
			Domain:		e.domain,
			RecordType:	"NS",
			Description:	fmt.Sprintf("Only %d nameserver(s) found. Best practice recommends at least 2 nameservers.", len(nsRecords)),
			Severity:	"medium",
		})
	}

}

func (e *Enumerator) checkSubdomainTakeover() {
	if !e.config.CheckTakeover {
		return
	}

	vulnerableServices := []struct {
		Domain		string	// The CNAME pattern to match
		Service		string	// The service name
		Fingerprint	string	// Text pattern that confirms takeover possibility
		StatusCode	int	// Expected HTTP status code for vulnerable service
		Severity	string	// high, medium, low
		Remediation	string	// Instructions to fix
	}{
		{
			Domain:		"s3.amazonaws.com",
			Service:	"Amazon S3",
			Fingerprint:	"The specified bucket does not exist",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create the S3 bucket or remove the CNAME record",
		},
		{
			Domain:		"github.io",
			Service:	"GitHub Pages",
			Fingerprint:	"There isn't a GitHub Pages site here",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create a GitHub Pages repository for this domain or remove the CNAME record",
		},
		{
			Domain:		"azure-api.net",
			Service:	"Azure API Management",
			Fingerprint:	"not found",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create the Azure API instance or remove the CNAME record",
		},
		{
			Domain:		"azurewebsites.net",
			Service:	"Azure Web Apps",
			Fingerprint:	"404 Web Site not found",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create the Azure Web App or remove the CNAME record",
		},
		{
			Domain:		"cloudapp.net",
			Service:	"Azure Cloud Apps",
			Fingerprint:	"404 Not Found",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create the Azure Cloud App or remove the CNAME record",
		},
		{
			Domain:		"cloudfront.net",
			Service:	"AWS CloudFront",
			Fingerprint:	"The request could not be satisfied",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create a CloudFront distribution or remove the CNAME record",
		},
		{
			Domain:		"herokuapp.com",
			Service:	"Heroku",
			Fingerprint:	"No such app",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create the Heroku app or remove the CNAME record",
		},
		{
			Domain:		"zendesk.com",
			Service:	"Zendesk",
			Fingerprint:	"Help Center Closed",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the Zendesk Help Center or remove the CNAME record",
		},
		{
			Domain:		"statuspage.io",
			Service:	"Statuspage",
			Fingerprint:	"This page is not available",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the Statuspage or remove the CNAME record",
		},
		{
			Domain:		"cargocollective.com",
			Service:	"Cargo Collective",
			Fingerprint:	"404 Not Found",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the Cargo Collective site or remove the CNAME record",
		},
		{
			Domain:		"cloudapp.azure.com",
			Service:	"Azure Cloud Apps",
			Fingerprint:	"404 Not Found",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create the Azure Cloud App or remove the CNAME record",
		},
		{
			Domain:		"azureedge.net",
			Service:	"Azure CDN",
			Fingerprint:	"404 Not Found",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create the Azure CDN endpoint or remove the CNAME record",
		},
		{
			Domain:		"shopify.com",
			Service:	"Shopify",
			Fingerprint:	"Sorry, this shop is currently unavailable",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create the Shopify store or remove the CNAME record",
		},
		{
			Domain:		"squarespace.com",
			Service:	"Squarespace",
			Fingerprint:	"Domain Not Claimed",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the Squarespace site or remove the CNAME record",
		},
		{
			Domain:		"unbounce.com",
			Service:	"Unbounce",
			Fingerprint:	"The requested URL was not found",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the Unbounce page or remove the CNAME record",
		},
		{
			Domain:		"uservoice.com",
			Service:	"UserVoice",
			Fingerprint:	"This UserVoice subdomain is currently available",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the UserVoice account or remove the CNAME record",
		},
		{
			Domain:		"wpengine.com",
			Service:	"WP Engine",
			Fingerprint:	"not found",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the WP Engine site or remove the CNAME record",
		},
		{
			Domain:		"fastly.net",
			Service:	"Fastly",
			Fingerprint:	"Fastly error: unknown domain",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Configure Fastly properly for this service or remove the CNAME record",
		},
		{
			Domain:		"pantheonsite.io",
			Service:	"Pantheon",
			Fingerprint:	"404 - Page Not Found",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the Pantheon site or remove the CNAME record",
		},
		{
			Domain:		"firebaseapp.com",
			Service:	"Firebase",
			Fingerprint:	"Site Not Found",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create the Firebase app or remove the CNAME record",
		},
		{
			Domain:		"netlify.app",
			Service:	"Netlify",
			Fingerprint:	"Not Found",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create the Netlify site or remove the CNAME record",
		},
		{
			Domain:		"ghost.io",
			Service:	"Ghost",
			Fingerprint:	"Domain Not Found",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the Ghost blog or remove the CNAME record",
		},
		{
			Domain:		"intercom.io",
			Service:	"Intercom",
			Fingerprint:	"This page is reserved",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the Intercom messenger or remove the CNAME record",
		},
		{
			Domain:		"webflow.io",
			Service:	"Webflow",
			Fingerprint:	"The domain has not been claimed",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the Webflow site or remove the CNAME record",
		},
		{
			Domain:		"mailchimp.com",
			Service:	"Mailchimp",
			Fingerprint:	"domain isn't connected to a landing page",
			StatusCode:	404,
			Severity:	"medium",
			Remediation:	"Create the Mailchimp landing page or remove the CNAME record",
		},
		{
			Domain:		"vercel.app",
			Service:	"Vercel",
			Fingerprint:	"404: Not Found",
			StatusCode:	404,
			Severity:	"high",
			Remediation:	"Create the Vercel deployment or remove the CNAME record",
		},
	}

	client := &http.Client{
		Timeout:	e.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	var foundVulnerabilities []struct {
		Domain		string
		CnameTarget	string
		Service		string
		Verified	bool
		Severity	string
		Remediation	string
	}

	e.recordsMux.Lock()
	defer e.recordsMux.Unlock()

	for _, record := range e.records {
		if record.RecordType != "CNAME" {
			continue
		}

		for _, service := range vulnerableServices {
			if strings.Contains(record.Value, service.Domain) {

				vulnerability := struct {
					Domain		string
					CnameTarget	string
					Service		string
					Verified	bool
					Severity	string
					Remediation	string
				}{
					Domain:		e.domain,
					CnameTarget:	record.Value,
					Service:	service.Service,
					Verified:	false,
					Severity:	service.Severity,
					Remediation:	service.Remediation,
				}

				url := fmt.Sprintf("https://%s", e.domain)
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {

					url = fmt.Sprintf("http://%s", e.domain)
					req, err = http.NewRequest("GET", url, nil)
					if err != nil {

						foundVulnerabilities = append(foundVulnerabilities, vulnerability)
						continue
					}
				}

				resp, err := client.Do(req)
				if err != nil {

					foundVulnerabilities = append(foundVulnerabilities, vulnerability)
					continue
				}

				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {

					foundVulnerabilities = append(foundVulnerabilities, vulnerability)
					continue
				}

				if resp.StatusCode == service.StatusCode {

					if service.Fingerprint != "" && strings.Contains(string(body), service.Fingerprint) {
						vulnerability.Verified = true
					}
				}

				foundVulnerabilities = append(foundVulnerabilities, vulnerability)
			}
		}
	}

	for _, vuln := range foundVulnerabilities {
		description := fmt.Sprintf("Subdomain takeover possible via %s. CNAME points to %s.",
			vuln.Service, vuln.CnameTarget)

		if vuln.Verified {
			description = fmt.Sprintf("VERIFIED subdomain takeover via %s. CNAME points to %s.",
				vuln.Service, vuln.CnameTarget)
		}

		description += fmt.Sprintf(" Remediation: %s", vuln.Remediation)

		e.addSecurityIssue(SecurityIssue{
			Domain:		e.domain,
			RecordType:	"CNAME",
			Description:	description,
			Severity:	vuln.Severity,
		})
	}
}

func (e *Enumerator) addSecurityIssue(issue SecurityIssue) {
	e.issuesMux.Lock()
	defer e.issuesMux.Unlock()
	e.securityIssues = append(e.securityIssues, issue)

	if e.debug {
		var severityColor func(format string, a ...interface{}) string
		switch issue.Severity {
		case "high":
			severityColor = color.HiRedString
		case "medium":
			severityColor = color.HiYellowString
		default:
			severityColor = color.HiCyanString
		}

		fmt.Printf("%s [%s] %s\n",
			color.HiMagentaString("DNS ISSUE:"),
			severityColor(strings.ToUpper(issue.Severity)),
			issue.Description)
	}
}

func (e *Enumerator) FormatResults() string {
	var sb strings.Builder

	typeMap := make(map[string][]DNSRecord)
	e.recordsMux.Lock()
	for _, record := range e.records {
		typeMap[record.RecordType] = append(typeMap[record.RecordType], record)
	}
	e.recordsMux.Unlock()

	sb.WriteString(fmt.Sprintf("DNS Enumeration Results for %s\n\n", e.domain))

	for recordType, records := range typeMap {
		sb.WriteString(fmt.Sprintf("=== %s Records ===\n", recordType))
		for _, r := range records {
			sb.WriteString(fmt.Sprintf("%s\n", r.Value))
		}
		sb.WriteString("\n")
	}

	if len(e.securityIssues) > 0 {
		sb.WriteString("\n=== Security Issues ===\n")
		for _, issue := range e.securityIssues {
			sb.WriteString(fmt.Sprintf("[%s] %s: %s\n",
				strings.ToUpper(issue.Severity),
				issue.RecordType,
				issue.Description))
		}
	}

	return sb.String()
}

func (e *Enumerator) convertToFindings() []output.Finding {
	var findings []output.Finding

	e.recordsMux.Lock()
	for _, record := range e.records {
		severity := "info"

		finding := output.Finding{
			Target:		e.domain,
			Type:		"dns_record",
			Severity:	severity,
			Description:	fmt.Sprintf("DNS %s record", record.RecordType),
			Data: map[string]interface{}{
				"record_type":	record.RecordType,
				"value":	record.Value,
				"ttl":		record.TTL,
			},
		}

		if record.RecordType == "MX" || record.RecordType == "SRV" {
			finding.Data["priority"] = record.Priority
		}

		findings = append(findings, finding)
	}
	e.recordsMux.Unlock()

	e.issuesMux.Lock()
	for _, issue := range e.securityIssues {
		finding := output.Finding{
			Target:		e.domain,
			Type:		"dns_security_issue",
			Severity:	issue.Severity,
			Description:	issue.Description,
			Data: map[string]interface{}{
				"record_type":	issue.RecordType,
				"issue_type":	issue.Description,
			},
		}
		findings = append(findings, finding)
	}
	e.issuesMux.Unlock()

	return findings
}

func dnsTypeFromString(recordType string) uint16 {
	switch strings.ToUpper(recordType) {
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	case "CNAME":
		return dns.TypeCNAME
	case "MX":
		return dns.TypeMX
	case "NS":
		return dns.TypeNS
	case "TXT":
		return dns.TypeTXT
	case "SOA":
		return dns.TypeSOA
	case "SRV":
		return dns.TypeSRV
	case "CAA":
		return dns.TypeCAA
	case "PTR":
		return dns.TypePTR
	case "DNSKEY":
		return dns.TypeDNSKEY
	case "DS":
		return dns.TypeDS
	case "NAPTR":
		return dns.TypeNAPTR
	case "NSEC":
		return dns.TypeNSEC
	case "NSEC3":
		return dns.TypeNSEC3
	case "RRSIG":
		return dns.TypeRRSIG
	case "SPF":
		return dns.TypeSPF
	case "SSHFP":
		return dns.TypeSSHFP
	default:
		return dns.TypeA
	}
}
