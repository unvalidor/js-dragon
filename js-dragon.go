package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/fatih/color"
)

type Finding struct {
	Category string
	Match    string
	Context  string
	Line     int
	File     string
	Severity string
}

type Scanner struct {
	patterns map[string][]*regexp.Regexp
	client   *http.Client
}

var dragonBanner = "" +
	"                              ______________\n" +
	"                        ,===:'.,            `-._\n" +
	"                             `:.`---.__         `-._\n" +
	"                                `:.     `--.         `.\n" +
	"                                   \\.        `.         `.\n" +
	"                           (,,(,    \\.         `.   ____,-`.,\n" +
	"                        (,'     `/   \\.   ,--.___`.'\n" +
	"                    ,  ,'  ,--.  `,   \\.;'         `\n" +
	"                     `{D, {    \\  :    \\;\n" +
	"                       V,,'    /  /    //\n" +
	"                       j;;    /  ,' ,-//.    ,---.      ,\n" +
	"                       \\;'   /  ,' /  _  \\  /  _  \\   ,'/\n" +
	"                             \\   `'  / \\  `'  / \\  `.' /\n" +
	"                              `.___,'   `.__,'   `.__,'  JS-Dragon-Unvalidor\n"

var (
	red     = color.New(color.FgRed, color.Bold).SprintFunc()
	yellow  = color.New(color.FgYellow, color.Bold).SprintFunc()
	green   = color.New(color.FgGreen, color.Bold).SprintFunc()
	cyan    = color.New(color.FgCyan).SprintFunc()
	white   = color.New(color.FgWhite).SprintFunc()
	magenta = color.New(color.FgMagenta, color.Bold).SprintFunc()
	blue    = color.New(color.FgBlue, color.Bold).SprintFunc()
)

func printBanner() {
	fmt.Println(cyan(dragonBanner))
	fmt.Println(magenta("                  github.com/unvalidor"))
	fmt.Println()
}

func NewScanner() *Scanner {
	s := &Scanner{
		patterns: make(map[string][]*regexp.Regexp),
		client: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
	s.compilePatterns()
	return s
}

func (s *Scanner) compilePatterns() {
	apiKeys := []string{
		`(?i)(api[_-]?key|apikey)["'\s:=]{1,5}["']([a-zA-Z0-9_\-]{16,})["']`,
		`(?i)(secret[_-]?key|secretkey)["'\s:=]{1,5}["']([a-zA-Z0-9_\-]{16,})["']`,
		`(?i)(access[_-]?key|accesskey)["'\s:=]{1,5}["']([a-zA-Z0-9_\-]{16,})["']`,
		`(?i)(private[_-]?key|privatekey)["'\s:=]{1,5}["']([a-zA-Z0-9_\-]{16,})["']`,
		`AIza[0-9A-Za-z\-_]{35}`,
		`AKIA[0-9A-Z]{16}`,
		`(?i)sk_live_[0-9a-zA-Z]{24,}`,
		`(?i)pk_live_[0-9a-zA-Z]{24,}`,
		`(?i)sk_test_[0-9a-zA-Z]{24,}`,
		`(?i)xox[baprs]-[0-9a-zA-Z\-]{10,}`,
		`ghp_[0-9a-zA-Z]{36}`,
		`gho_[0-9a-zA-Z]{36}`,
		`ghu_[0-9a-zA-Z]{36}`,
		`ghs_[0-9a-zA-Z]{36}`,
		`ghr_[0-9a-zA-Z]{36}`,
		`(?i)bearer\s+[a-zA-Z0-9\-_\.=]{20,}`,
		`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`,
	}
	s.patterns["API_KEY"] = compileList(apiKeys)

	credentials := []string{
		`(?i)(password|passwd|pwd)["'\s:=]{1,5}["']([^"']{4,})["']`,
		`(?i)(username|user|login)["'\s:=]{1,5}["']([^"']{3,})["']`,
		`(?i)(db_pass|db_password|database_password)["'\s:=]{1,5}["']([^"']{4,})["']`,
		`(?i)(aws_secret|aws_secret_access_key)["'\s:=]{1,5}["']([A-Za-z0-9/+=]{40})["']`,
		`(?i)(client_secret)["'\s:=]{1,5}["']([a-zA-Z0-9_\-]{16,})["']`,
		`(?i)Authorization\s*:\s*["']?[Bb]asic\s+[A-Za-z0-9+/=]{8,}`,
		`(?i)mongodb(\+srv)?://[^"'\s]+:[^"'\s]+@[^"'\s]+`,
		`(?i)mysql://[^"'\s]+:[^"'\s]+@[^"'\s]+`,
		`(?i)postgres(ql)?://[^"'\s]+:[^"'\s]+@[^"'\s]+`,
		`(?i)redis://[^"'\s]+:[^"'\s]+@[^"'\s]+`,
	}
	s.patterns["CREDENTIAL"] = compileList(credentials)

	tokens := []string{
		`(?i)token["'\s:=]{1,5}["']([a-zA-Z0-9_\-\.]{20,})["']`,
		`(?i)csrf[_-]?token["'\s:=]{1,5}["']([a-zA-Z0-9_\-]{16,})["']`,
		`(?i)auth[_-]?token["'\s:=]{1,5}["']([a-zA-Z0-9_\-\.]{20,})["']`,
		`(?i)session[_-]?id["'\s:=]{1,5}["']([a-zA-Z0-9_\-]{16,})["']`,
		`(?i)jwt["'\s:=]{1,5}["']([a-zA-Z0-9_\-\.]{20,})["']`,
	}
	s.patterns["TOKEN"] = compileList(tokens)

	endpoints := []string{
		`["'](https?://[a-zA-Z0-9\-\._~:/?#\[\]@!\$&'\(\)\*\+,;=%]+)["']`,
		`["'](/[a-zA-Z0-9\-_/]+(/[a-zA-Z0-9\-_]+)+)["']`,
		`["'](wss?://[a-zA-Z0-9\-\._~:/?#\[\]@!\$&'\(\)\*\+,;=%]+)["']`,
		`(?i)fetch\s*\(\s*["']([^"']+)["']`,
		`(?i)axios\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`,
		`(?i)\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']`,
		`(?i)\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["']([^"']+)["']`,
	}
	s.patterns["ENDPOINT"] = compileList(endpoints)

	sinks := []string{
		`(?i)innerHTML\s*=`,
		`(?i)outerHTML\s*=`,
		`(?i)document\.write\s*\(`,
		`(?i)eval\s*\(`,
		`(?i)Function\s*\(`,
		`(?i)setTimeout\s*\(\s*["']`,
		`(?i)setInterval\s*\(\s*["']`,
		`(?i)execScript\s*\(`,
		`(?i)\.insertAdjacentHTML\s*\(`,
		`(?i)dangerouslySetInnerHTML`,
		`(?i)location\s*=\s*`,
		`(?i)location\.href\s*=`,
		`(?i)location\.replace\s*\(`,
		`(?i)location\.assign\s*\(`,
		`(?i)postMessage\s*\(`,
		`(?i)\.src\s*=\s*["']javascript:`,
	}
	s.patterns["SINK"] = compileList(sinks)

	sources := []string{
		`(?i)location\.hash`,
		`(?i)location\.search`,
		`(?i)location\.href`,
		`(?i)document\.URL`,
		`(?i)document\.documentURI`,
		`(?i)document\.referrer`,
		`(?i)window\.name`,
		`(?i)postMessage`,
		`(?i)localStorage\.`,
		`(?i)sessionStorage\.`,
		`(?i)document\.cookie`,
		`(?i)URLSearchParams`,
		`(?i)\.value\b`,
	}
	s.patterns["SOURCE"] = compileList(sources)

	vuln := []string{
		`(?i)new\s+Function\s*\(`,
		`(?i)document\.write\s*\([^)]*\+`,
		`(?i)\.innerHTML\s*=\s*[^"']*\+`,
		`(?i)\.html\s*\(\s*[^"']*\+`,
		`(?i)\$\([^)]*\)\.html\s*\(`,
		`(?i)child_process`,
		`(?i)require\s*\(\s*["']child_process["']`,
		`(?i)exec\s*\(\s*[^"']*\+`,
		`(?i)spawn\s*\(\s*[^"']*\+`,
		`(?i)deserialize`,
		`(?i)unserialize`,
		`(?i)Math\.random\s*\(\s*\)`,
	}
	s.patterns["VULNERABLE"] = compileList(vuln)
}

func compileList(list []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(list))
	for _, p := range list {
		re, err := regexp.Compile(p)
		if err == nil {
			out = append(out, re)
		}
	}
	return out
}

func (s *Scanner) severityFor(cat string) string {
	switch cat {
	case "API_KEY", "CREDENTIAL", "TOKEN":
		return "HIGH"
	case "VULNERABLE", "SINK":
		return "MEDIUM"
	case "SOURCE", "ENDPOINT":
		return "LOW"
	default:
		return "INFO"
	}
}

func (s *Scanner) analyzeContent(content, filename string) []Finding {
	findings := []Finding{}
	lines := strings.Split(content, "\n")
	seen := make(map[string]bool)

	for cat, patterns := range s.patterns {
		for _, re := range patterns {
			for i, line := range lines {
				matches := re.FindAllStringSubmatch(line, -1)
				for _, m := range matches {
					var matchStr string
					if len(m) > 2 {
						matchStr = m[2]
					} else if len(m) > 1 {
						matchStr = m[1]
					} else {
						matchStr = m[0]
					}
					key := cat + "|" + matchStr + "|" + filename
					if seen[key] {
						continue
					}
					seen[key] = true
					ctx := strings.TrimSpace(line)
					if len(ctx) > 200 {
						ctx = ctx[:200] + "..."
					}
					findings = append(findings, Finding{
						Category: cat,
						Match:    matchStr,
						Context:  ctx,
						Line:     i + 1,
						File:     filename,
						Severity: s.severityFor(cat),
					})
				}
			}
		}
	}
	return findings
}

func (s *Scanner) scanFile(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return s.analyzeContent(string(data), path), nil
}

func (s *Scanner) scanDir(dir string) []Finding {
	var all []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".js" && ext != ".mjs" && ext != ".cjs" && ext != ".jsx" && ext != ".ts" {
			return nil
		}
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			f, err := s.scanFile(p)
			if err != nil {
				return
			}
			mu.Lock()
			all = append(all, f...)
			mu.Unlock()
		}(path)
		return nil
	})
	wg.Wait()
	return all
}

func (s *Scanner) fetchURL(u string) (string, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (s *Scanner) scanURL(u string) []Finding {
	content, err := s.fetchURL(u)
	if err != nil {
		fmt.Println(red("[!] failed to fetch: " + u + " - " + err.Error()))
		return nil
	}
	return s.analyzeContent(content, u)
}

func (s *Scanner) extractJSFromPage(pageURL string) []string {
	var urls []string
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return urls
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := s.client.Do(req)
	if err != nil {
		return urls
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return urls
	}

	base, _ := url.Parse(pageURL)
	seen := make(map[string]bool)

	doc.Find("script[src]").Each(func(i int, sel *goquery.Selection) {
		src, ok := sel.Attr("src")
		if !ok || src == "" {
			return
		}
		abs := resolveURL(base, src)
		if abs == "" || seen[abs] {
			return
		}
		seen[abs] = true
		urls = append(urls, abs)
	})

	re := regexp.MustCompile(`["']([^"']+\.js(\?[^"']*)?)["']`)
	body, _ := doc.Html()
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		abs := resolveURL(base, m[1])
		if abs == "" || seen[abs] {
			continue
		}
		seen[abs] = true
		urls = append(urls, abs)
	}

	return urls
}

func resolveURL(base *url.URL, ref string) string {
	if strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "javascript:") {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func (s *Scanner) crawlSite(siteURL string) []Finding {
	fmt.Println(cyan("[*] crawling: " + siteURL))
	jsURLs := s.extractJSFromPage(siteURL)
	fmt.Println(cyan(fmt.Sprintf("[*] found %d js files", len(jsURLs))))

	var all []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, u := range jsURLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			fmt.Println(white("[+] scanning: " + u))
			f := s.scanURL(u)
			mu.Lock()
			all = append(all, f...)
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	return all
}

func severityColor(sev string) string {
	switch sev {
	case "HIGH":
		return red(sev)
	case "MEDIUM":
		return yellow(sev)
	case "LOW":
		return green(sev)
	default:
		return blue(sev)
	}
}

func categoryColor(cat string) string {
	switch cat {
	case "API_KEY":
		return magenta(cat)
	case "CREDENTIAL":
		return red(cat)
	case "TOKEN":
		return yellow(cat)
	case "ENDPOINT":
		return cyan(cat)
	case "SINK":
		return yellow(cat)
	case "SOURCE":
		return blue(cat)
	case "VULNERABLE":
		return red(cat)
	default:
		return white(cat)
	}
}

func printFindings(findings []Finding) {
	if len(findings) == 0 {
		fmt.Println(yellow("[!] no findings"))
		return
	}

	byCat := make(map[string][]Finding)
	for _, f := range findings {
		byCat[f.Category] = append(byCat[f.Category], f)
	}

	fmt.Println()
	fmt.Println(green("========================================================"))
	fmt.Println(green("                    SCAN RESULTS                        "))
	fmt.Println(green("========================================================"))
	fmt.Println()

	for _, cat := range []string{"API_KEY", "CREDENTIAL", "TOKEN", "VULNERABLE", "SINK", "SOURCE", "ENDPOINT"} {
		items, ok := byCat[cat]
		if !ok || len(items) == 0 {
			continue
		}
		fmt.Printf("%s [%d]\n", categoryColor(cat), len(items))
		for _, f := range items {
			fmt.Printf("  %s %s:%d\n", severityColor("["+f.Severity+"]"), cyan(f.File), f.Line)
			fmt.Printf("      %s\n", yellow(f.Match))
			fmt.Printf("      %s\n", white(f.Context))
		}
		fmt.Println()
	}

	fmt.Println(green("========================================================"))
	fmt.Printf("%s total findings: %d\n", green("[*]"), len(findings))
	fmt.Println(green("========================================================"))
}

func saveReport(findings []Finding, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()

	fmt.Fprintln(w, "JS Analyzer Report")
	fmt.Fprintln(w, "==================")
	fmt.Fprintln(w)
	for _, f := range findings {
		fmt.Fprintf(w, "[%s] %s\n", f.Severity, f.Category)
		fmt.Fprintf(w, "  File: %s\n", f.File)
		fmt.Fprintf(w, "  Line: %d\n", f.Line)
		fmt.Fprintf(w, "  Match: %s\n", f.Match)
		fmt.Fprintf(w, "  Context: %s\n\n", f.Context)
	}
	fmt.Fprintf(w, "Total: %d\n", len(findings))
	return nil
}

func main() {
	printBanner()

	var (
		fileFlag   = flag.String("f", "", "scan a single local js file")
		dirFlag    = flag.String("d", "", "scan all js files in a directory")
		urlFlag    = flag.String("u", "", "scan a remote js file by url")
		siteFlag   = flag.String("s", "", "crawl a website and scan its js files")
		outputFlag = flag.String("o", "", "save report to a file")
	)
	flag.Parse()

	s := NewScanner()
	var findings []Finding

	switch {
	case *fileFlag != "":
		fmt.Println(cyan("[*] scanning file: " + *fileFlag))
		f, err := s.scanFile(*fileFlag)
		if err != nil {
			fmt.Println(red("[!] error: " + err.Error()))
			os.Exit(1)
		}
		findings = f
	case *dirFlag != "":
		fmt.Println(cyan("[*] scanning directory: " + *dirFlag))
		findings = s.scanDir(*dirFlag)
	case *urlFlag != "":
		fmt.Println(cyan("[*] scanning url: " + *urlFlag))
		findings = s.scanURL(*urlFlag)
	case *siteFlag != "":
		findings = s.crawlSite(*siteFlag)
	default:
		fmt.Println(yellow("[!] no target specified"))
		fmt.Println(white("usage:"))
		fmt.Println(white("  -f <file>     scan a single local js file"))
		fmt.Println(white("  -d <dir>      scan all js files in a directory"))
		fmt.Println(white("  -u <url>      scan a remote js file by url"))
		fmt.Println(white("  -s <site>     crawl a website and scan js files"))
		fmt.Println(white("  -o <file>     save report to a file"))
		os.Exit(1)
	}

	printFindings(findings)

	if *outputFlag != "" {
		if err := saveReport(findings, *outputFlag); err != nil {
			fmt.Println(red("[!] failed to save report: " + err.Error()))
		} else {
			fmt.Println(green("[+] report saved: " + *outputFlag))
		}
	}
}