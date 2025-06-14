package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

var (
	outputFile string
	mu         sync.Mutex
)

func main() {
	showBanner()

	// Set output file with timestamp
	outputFile = fmt.Sprintf("output_%d.txt", time.Now().Unix())

	// Handle Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		color.Yellow("\nInterrupted. Exiting gracefully.")
		os.Exit(1)
	}()

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
			tlsHandshakeMenu()
		case "7":
			httpHeaderMenu()
		case "8":
			color.Yellow("Help: Multi-tool scanner for bug hunting.")
		case "9":
			color.Yellow("Update: (placeholder)")
		case "0":
			color.Green("Exiting.")
			return
		default:
			color.Red("Invalid choice.")
		}
	}
}

func showBanner() {
	color.Cyan(`
██╗  ██╗ ██████╗ ███████╗████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████║██║   ██║███████╗   ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██║██║   ██║╚════██║   ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝███████║   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
`)
	color.Magenta("HOST HUNTER by TS HACKER | Telegram: @teamsatved71\n")
}

func printMainMenu() {
	color.Cyan("\n🚀 MAIN MENU")
	fmt.Println("[1] HOST SCANNER")
	fmt.Println("[2] IP LOOKUP")
	fmt.Println("[3] PORT SCANNER")
	fmt.Println("[4] DNS RECORD")
	fmt.Println("[5] SUBFINDER")
	fmt.Println("[6] SSL/TLS HANDSHAKE CHECK")
	fmt.Println("[7] HTTP HEADER CHECK")
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
		domains = []string{getInput("Enter domain:")}
	case "2":
		path := getInput("File path:")
		domains = readFileLines(path)
	case "3":
		line := getInput("Enter comma-separated domains:")
		for _, d := range strings.Split(line, ",") {
			domains = append(domains, strings.TrimSpace(d))
		}
	default:
		color.Red("Invalid input option.")
	}
	return domains
}

func hostScannerMenu() {
	color.Cyan("\nHOST SCANNER MODES")
	fmt.Println("[1] Direct")
	fmt.Println("[2] DirectNon302")
	fmt.Println("[3] Ping")

	mode := getInput("Select scan mode:")
	domains := inputOptions()

	var wg sync.WaitGroup
	var done int32 = 0
	total := int32(len(domains))

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			switch mode {
			case "1":
				directScan(d)
			case "2":
				directNon302Scan(d)
			case "3":
				pingScan(d)
			default:
				color.Red("Invalid scan mode")
			}
			atomic.AddInt32(&done, 1)
			fmt.Printf("\rProgress: %.2f%%", (float64(done)/float64(total))*100)
		}(domain)
	}
	wg.Wait()
	fmt.Println("\nScan complete.")
}

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

func pingScan(domain string) {
	cmd := exec.Command("ping", "-c", "1", domain)
	out, err := cmd.CombinedOutput()
	if err != nil {
		writeError("Ping", domain, fmt.Errorf("%v: %s", err, string(out)))
		return
	}
	writeSuccess("Ping", domain, "Reachable")
}

func tlsHandshakeMenu() {
	domains := inputOptions()
	for _, domain := range domains {
		addr := domain + ":443"
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			writeError("TLS", domain, err)
			continue
		}
		state := conn.ConnectionState()
		writeSuccess("TLS", domain, fmt.Sprintf("Handshake Success. Version: %x, Cipher: %x", state.Version, state.CipherSuite))
		for i, cert := range state.PeerCertificates {
			writeSuccess("TLS", domain, fmt.Sprintf("Cert[%d]: CN=%s, Expiry=%s", i, cert.Subject.CommonName, cert.NotAfter))
		}
		conn.Close()
	}
}

func httpHeaderMenu() {
	domains := inputOptions()
	client := http.Client{Timeout: 10 * time.Second}
	for _, domain := range domains {
		url := "http://" + domain
		resp, err := client.Get(url)
		if err != nil {
			writeError("HTTPHeader", domain, err)
			continue
		}
		writeSuccess("HTTPHeader", domain, fmt.Sprintf("Status: %d %s", resp.StatusCode, resp.Status))
		for k, v := range resp.Header {
			writeSuccess("HTTPHeader", domain, fmt.Sprintf("%s: %s", k, strings.Join(v, ", ")))
		}
		resp.Body.Close()
	}
}

func portScannerMenu() {
	ports := []int{80, 443, 8080, 8443}
	domains := inputOptions()

	var wg sync.WaitGroup
	for _, domain := range domains {
		for _, port := range ports {
			wg.Add(1)
			go func(d string, p int) {
				defer wg.Done()
				addr := fmt.Sprintf("%s:%d", d, p)
				conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil {
					writeWarning("PortScan", addr, "Closed/Filtered")
					return
				}
				conn.Close()
				writeSuccess("PortScan", addr, "Open")
			}(domain, port)
		}
	}
	wg.Wait()
	color.Green("Port scan complete.")
}

func dnsLookupMenu() {
	domains := inputOptions()
	for _, d := range domains {
		ips, err := net.LookupHost(d)
		if err != nil {
			writeError("DNS", d, err)
			continue
		}
		writeSuccess("DNS", d, fmt.Sprintf("A: %v", ips))
	}
}

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

func subfinderMenu() {
	domains := inputOptions()
	words := []string{"www", "mail", "ftp", "dev", "test", "portal"}
	var wg sync.WaitGroup
	for _, domain := range domains {
		for _, word := range words {
			wg.Add(1)
			go func(sub string) {
				defer wg.Done()
				ips, err := net.LookupHost(sub)
				if err == nil {
					writeSuccess("Subfinder", sub, fmt.Sprintf("%v", ips))
				}
			}(word + "." + domain)
		}
	}
	wg.Wait()
	color.Green("Subfinder scan complete.")
}

func getInput(prompt string) string {
	fmt.Print(prompt + " ")
	sc := bufio.NewScanner(os.Stdin)
	sc.Scan()
	return strings.TrimSpace(sc.Text())
}

func readFileLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		color.Red("File read error: %v", err)
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" {
			lines = append(lines, l)
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
		color.Red("Output file write error: %v", err)
		return
	}
	defer f.Close()
	f.WriteString(line)
}
