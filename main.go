package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

var (
	outputFile = "output.txt"
	mu         sync.Mutex
	proxies    = []string{
		"http://127.0.0.1:8080", // Example proxy (replace with real list)
	}
)

func main() {
	for {
		printMainMenu()
		choice := getInput("Select an option:")

		switch choice {
		case "1":
			hostScannerMenu()
		case "2":
			ipLookupMenu()
		case "3":
			portScannerMenu()
		case "4":
			dnsLookupMenu()
		case "5":
			subfinderMenu()
		case "6":
			color.Yellow("File Toolkit (placeholder)")
		case "7":
			hostInfoMenu()
		case "8":
			color.Yellow("Help: Use this tool to scan hosts.")
		case "9":
			color.Yellow("Update: (placeholder)")
		case "0":
			color.Green("Exiting. Bye!")
			return
		default:
			color.Red("Invalid choice. Try again.")
		}
	}
}

func printMainMenu() {
	color.Cyan("\n🚀 MAIN MENU")
	fmt.Println("[1] HOST SCANNER")
	fmt.Println("[2] IP LOOKUP")
	fmt.Println("[3] PORT SCANNER")
	fmt.Println("[4] DNS RECORD")
	fmt.Println("[5] SUBFINDER")
	fmt.Println("[6] FILE TOOLKIT")
	fmt.Println("[7] HOST INFO")
	fmt.Println("[8] HELP")
	fmt.Println("[9] UPDATE")
	fmt.Println("[0] EXIT")
}

func inputOptions() []string {
	color.Cyan("\nINPUT OPTIONS")
	fmt.Println("[1] Single domain")
	fmt.Println("[2] Bulk via txt file")
	fmt.Println("[3] Multiple via line input")

	opt := getInput("Choose input option:")
	var domains []string

	switch opt {
	case "1":
		d := getInput("Enter domain:")
		domains = []string{d}
	case "2":
		f := getInput("Enter file path:")
		domains = readFileLines(f)
	case "3":
		l := getInput("Enter comma-separated domains:")
		for _, d := range strings.Split(l, ",") {
			domains = append(domains, strings.TrimSpace(d))
		}
	default:
		color.Red("Invalid input option.")
	}
	return domains
}

// HOST SCANNER
func hostScannerMenu() {
	color.Cyan("\nHOST SCANNER MODES")
	fmt.Println("[1] Direct")
	fmt.Println("[2] DirectNon302")
	fmt.Println("[3] ProxyTest")
	fmt.Println("[4] ProxyRoute")
	fmt.Println("[5] Ping")
	fmt.Println("[6] SSL")

	scanMode := getInput("Select scan mode:")
	domains := inputOptions()

	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			switch scanMode {
			case "1":
				directScan(d)
			case "2":
				directNon302Scan(d)
			case "3":
				proxyScan(d, proxies[0])
			case "4":
				rotateProxyScan(d)
			case "5":
				pingScan(d)
			case "6":
				sslScan(d)
			default:
				color.Red("Invalid scan mode")
			}
		}(domain)
	}
	wg.Wait()
	color.Green("Host scan complete. Results saved to %s", outputFile)
}

// INDIVIDUAL SCANS
func directScan(domain string) {
	url := "http://" + domain
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		writeError("Direct", domain, err)
		return
	}
	defer resp.Body.Close()
	writeSuccess("Direct", domain, fmt.Sprintf("%d %s", resp.StatusCode, resp.Status))
}

func directNon302Scan(domain string) {
	url := "http://" + domain
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		writeError("DirectNon302", domain, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 302 {
		writeWarning("DirectNon302", domain, "302 Found - Skipped")
	} else {
		writeSuccess("DirectNon302", domain, fmt.Sprintf("%d %s", resp.StatusCode, resp.Status))
	}
}

func proxyScan(domain, proxyURL string) {
	proxyFunc := http.ProxyURL(parseURL(proxyURL))
	transport := &http.Transport{Proxy: proxyFunc}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	url := "http://" + domain
	resp, err := client.Get(url)
	if err != nil {
		writeError("ProxyTest", domain, err)
		return
	}
	defer resp.Body.Close()
	writeSuccess("ProxyTest", domain, fmt.Sprintf("%d %s", resp.StatusCode, resp.Status))
}

func rotateProxyScan(domain string) {
	for _, proxyURL := range proxies {
		proxyScan(domain, proxyURL)
	}
}

func pingScan(domain string) {
	ip, err := net.ResolveIPAddr("ip", domain)
	if err != nil {
		writeError("Ping", domain, err)
		return
	}
	conn, err := net.DialTimeout("ip4:icmp", ip.String(), 3*time.Second)
	if err != nil {
		writeError("Ping", domain, err)
		return
	}
	defer conn.Close()
	writeSuccess("Ping", domain, fmt.Sprintf("Reachable (%s)", ip.String()))
}

func sslScan(domain string) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{})
	if err != nil {
		writeError("SSL", domain, err)
		return
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		writeSuccess("SSL", domain, fmt.Sprintf("CN: %s", certs[0].Subject.CommonName))
	}
}

// PORT SCANNER
func portScannerMenu() {
	ports := []int{80, 443, 8080, 8443, 21, 22}
	domains := inputOptions()

	var wg sync.WaitGroup
	for _, domain := range domains {
		for _, port := range ports {
			wg.Add(1)
			go func(d string, p int) {
				defer wg.Done()
				address := fmt.Sprintf("%s:%d", d, p)
				conn, err := net.DialTimeout("tcp", address, 3*time.Second)
				if err != nil {
					writeWarning("PortScan", address, "Closed/Filtered")
					return
				}
				conn.Close()
				writeSuccess("PortScan", address, "Open")
			}(domain, port)
		}
	}
	wg.Wait()
	color.Green("Port scan complete.")
}

// DNS LOOKUP
func dnsLookupMenu() {
	domains := inputOptions()
	for _, d := range domains {
		ips, _ := net.LookupHost(d)
		mxs, _ := net.LookupMX(d)
		cnames, _ := net.LookupCNAME(d)
		writeSuccess("DNS", d, fmt.Sprintf("A: %v", ips))
		writeSuccess("DNS", d, fmt.Sprintf("MX: %v", mxs))
		writeSuccess("DNS", d, fmt.Sprintf("CNAME: %v", cnames))
	}
}

// IP LOOKUP
func ipLookupMenu() {
	domains := inputOptions()
	for _, d := range domains {
		ips, err := net.LookupIP(d)
		if err != nil {
			writeError("IPLookup", d, err)
			continue
		}
		writeSuccess("IPLookup", d, fmt.Sprintf("%v", ips))
	}
}

// SUBFINDER
func subfinderMenu() {
	domains := inputOptions()
	prefixes := []string{"www", "mail", "ftp", "dev"}
	for _, d := range domains {
		for _, p := range prefixes {
			sub := p + "." + d
			ips, err := net.LookupHost(sub)
			if err == nil {
				writeSuccess("Subfinder", sub, fmt.Sprintf("%v", ips))
			}
		}
	}
}

// HOST INFO
func hostInfoMenu() {
	domains := inputOptions()
	for _, d := range domains {
		directScan(d)
		pingScan(d)
		sslScan(d)
		dnsLookupMenu()
		portScannerMenu()
	}
}

// HELPERS
func getInput(prompt string) string {
	fmt.Print(prompt + " ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func readFileLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		color.Red("Failed to open file: %v", err)
		return nil
	}
	defer file.Close()
	var lines []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func writeSuccess(tag, target, msg string) {
	color.Green("%s [%s] -> %s", tag, target, msg)
	writeOutput(fmt.Sprintf("%s [%s] -> %s\n", tag, target, msg))
}

func writeWarning(tag, target, msg string) {
	color.Yellow("%s [%s] -> %s", tag, target, msg)
	writeOutput(fmt.Sprintf("%s [%s] -> %s\n", tag, target, msg))
}

func writeError(tag, target string, err error) {
	color.Red("%s [%s] -> Error: %v", tag, target, err)
	writeOutput(fmt.Sprintf("%s [%s] -> Error: %v\n", tag, target, err))
}

func writeOutput(line string) {
	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		color.Red("Write failed: %v", err)
		return
	}
	defer f.Close()
	f.WriteString(line)
}

func parseURL(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}
