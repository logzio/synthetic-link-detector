package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	envToken        = "LOGZIO_LOG_SHIPPING_TOKEN"
	envUrl          = "URL"
	envListener     = "LOGZIO_LISTENER"
	envLogzioType   = "LOGZIO_TYPE"
	envCustomFields = "LOGZIO_FIELDS"

	defaultListener = "https://listener.logz.io:8071"
	defaultLogType  = "synthetic-links-detector"
)

var (
	logger       *log.Logger
	token        string
	listener     string
	fullListener string
	urlToInspect string
	logType      string
	httpClient   *http.Client
	wg           sync.WaitGroup
	uuid         string
)

func main() {
	//lambda.Start(HandleRequest)
	// Scheduled invocation
	err := getParameters()
	if err != nil {
		//return "lambda encountered error", err
		return
	}

	generateUuid()
	logger = log.New(os.Stdout, uuid, log.Ldate|log.Ltime|log.Lshortfile)
	linksInPage := getLinksInPage(urlToInspect)
	logger.Printf("detected %d links in %s\n", len(linksInPage), urlToInspect)
	wg.Add(len(linksInPage))
	setupHttpClient()
	for _, link := range linksInPage {
		go detectAndSend(link, urlToInspect)
	}

	wg.Wait()
	logger.Printf("finished run\n")
}

//func HandleRequest(ctx context.Context, event map[string]interface{}) (string, error) {
//	if _, ok := event["RequestId"]; ok {
//		// First invocation
//	} else {
//		// Scheduled invocation
//		token, listener, urlToInspect, err := getParameters()
//		if err != nil {
//			return "lambda encountered error", err
//		}
//		linksInPage := getLinksInPage(urlToInspect)
//		for _, link := range linksInPage {
//			go detectAndSend(link)
//		}
//	}
//
//}

func generateUuid() {
	var err error
	uuidBytes, err := exec.Command("uuidgen").Output()
	if err != nil {
		logger.Fatalf("could not generate uuid: %s\n", err)
	}

	uuid = string(uuidBytes)
}

func setupHttpClient() {
	tlsConfig := &tls.Config{}
	transport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}

	// in case server side is sleeping - wait 10s instead of waiting for him to wake up
	httpClient = &http.Client{
		Transport: transport,
		Timeout:   time.Second * 10,
	}
}

func detectAndSend(link, mainUrl string) {
	defer wg.Done()
	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		logger.Printf("unable to create request: %v\n", err)
		return
	}

	var t0, t1, t2, t3, t4, t5, t6 time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { t0 = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { t1 = time.Now() },
		ConnectStart: func(_, _ string) {
			if t1.IsZero() {
				// connecting to IP
				t1 = time.Now()
			}
		},
		ConnectDone: func(net, addr string, err error) {
			if err != nil {
				logger.Printf("unable to connect to host %v: %v\n", addr, err)
				return
			}
			t2 = time.Now()

		},
		GotConn:              func(_ httptrace.GotConnInfo) { t3 = time.Now() },
		GotFirstResponseByte: func() { t4 = time.Now() },
		TLSHandshakeStart:    func() { t5 = time.Now() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { t6 = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	l, err := url.Parse(link)
	if err != nil {
		logger.Printf("could not parse link %s: %s\n", link, err.Error())
		return
	}

	if l.Scheme == "https" {
		host, _, err := net.SplitHostPort(req.Host)
		if err != nil {
			host = req.Host
		}

		tr.TLSClientConfig = &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// always refuse to follow redirects, visit does that
			// manually if required.
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("failed to read response: %v\n", err)
		return
	}

	w := io.Discard
	if _, err := io.Copy(w, resp.Body); err != nil && w != io.Discard {
		logger.Printf("failed to read response body: %v\n", err)
		return
	}

	resp.Body.Close()

	t7 := time.Now() // after read body
	if t0.IsZero() {
		// we skipped DNS
		t0 = t1
	}

	data := make(map[string]string, 0)
	data["link"] = link
	data["main_url"] = mainUrl
	data["status_code"] = strconv.Itoa(resp.StatusCode)
	switch l.Scheme {
	case "https":
		data["dns_lookup"] = strconv.FormatInt(t1.Sub(t0).Milliseconds(), 10)
		data["tcp_connection"] = strconv.FormatInt(t2.Sub(t1).Milliseconds(), 10)
		data["tls_handshake"] = strconv.FormatInt(t6.Sub(t5).Milliseconds(), 10)
		data["server_processing"] = strconv.FormatInt(t4.Sub(t3).Milliseconds(), 10)
		data["content_transfer"] = strconv.FormatInt(t7.Sub(t4).Milliseconds(), 10)
		data["name_lookup"] = strconv.FormatInt(t1.Sub(t0).Milliseconds(), 10)
		data["connect"] = strconv.FormatInt(t2.Sub(t0).Milliseconds(), 10)
		data["pre_transfer"] = strconv.FormatInt(t3.Sub(t0).Milliseconds(), 10)
		data["start_transfer"] = strconv.FormatInt(t4.Sub(t0).Milliseconds(), 10)
		data["total"] = strconv.FormatInt(t7.Sub(t0).Milliseconds(), 10)
	case "http":
		data["dns_lookup"] = strconv.FormatInt(t1.Sub(t0).Milliseconds(), 10)
		data["tcp_connection"] = strconv.FormatInt(t3.Sub(t1).Milliseconds(), 10)
		data["server_processing"] = strconv.FormatInt(t4.Sub(t3).Milliseconds(), 10)
		data["content_transfer"] = strconv.FormatInt(t7.Sub(t4).Milliseconds(), 10)
		data["name_lookup"] = strconv.FormatInt(t1.Sub(t0).Milliseconds(), 10)
		data["connect"] = strconv.FormatInt(t3.Sub(t0).Milliseconds(), 10)
		data["start_transfer"] = strconv.FormatInt(t4.Sub(t0).Milliseconds(), 10)
		data["total"] = strconv.FormatInt(t7.Sub(t0).Milliseconds(), 10)
	}

	processAndSendLog(data)
}

func processAndSendLog(data map[string]string) {
	addLogzioFields(data)
	addCustomFields(data)
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		logger.Printf("unable to marshal data for %v: %s\n", data, err)
		return
	}

	sendToLogzio(jsonBytes)
}

func sendToLogzio(log []byte) {
	maxRetries := 4
	req, err := http.NewRequest(http.MethodPost, fullListener, bytes.NewBuffer(log))
	if err != nil {
		logger.Printf("could not create new http request: %s\n", err.Error())
		return
	}

	req.Header.Add("Content-Type", "application/json")

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err := httpClient.Do(req)
		if err != nil {
			logger.Printf("error sending logs to logzio %s\n", err)
			return
		}

		defer resp.Body.Close()
		statusCode := resp.StatusCode
		switch statusCode {
		case http.StatusOK:
			return
		case http.StatusBadRequest:
			logger.Printf("bad request for %s\n", string(log))
			return
		case http.StatusUnauthorized:
			logger.Printf("got 401 from logz.io. please check your token\n")
			return
		default:
			logger.Printf("attempt %d/%d\n", attempt, maxRetries)
			if attempt < maxRetries {
				logger.Printf("will retry to send log...\n")
			}
		}
	}
}

func addLogzioFields(data map[string]string) {
	data["type"] = logType
	data["run_id"] = uuid
}

func addCustomFields(data map[string]string) {
	input := os.Getenv(envCustomFields)
	if input == "" {
		return
	}

	keyValPairs := strings.Split(input, ",")
	for _, pair := range keyValPairs {
		field := strings.Split(pair, "=")
		data[field[0]] = field[1]
	}
}

func getLinksInPage(url string) []string {
	links := make([]string, 0)
	res, err := http.Get(url)
	if err != nil {
		logger.Fatal(err)
	}

	content, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		logger.Fatal(err)
	}

	doc, err := html.Parse(strings.NewReader(string(content)))
	if err != nil {
		logger.Fatal(err)
	}
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" {
					link := a.Val
					matched, _ := regexp.MatchString("^http(s?)://", link)
					if !matched {
						link = url + link
					}
					if !contains(links, link) {
						links = append(links, link)
					}
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}

	f(doc)
	return links
}

func getParameters() (err error) {
	err = validateRequired()
	if err != nil {
		return
	}

	listener = os.Getenv(envListener)
	if listener == "" {
		listener = defaultListener
	}

	fullListener = fmt.Sprintf("%s?token=%s", listener, token)

	logType = os.Getenv(envLogzioType)
	if logType == "" {
		logType = defaultLogType
	}

	return
}

func validateRequired() (err error) {
	token, err = validate(envToken, "logzio shipping token")
	if err != nil {
		return
	}

	urlToInspect, err = validate(envUrl, "urlToInspect to investigate")
	if err != nil {
		return
	}

	return
}

func validate(envName, errorParameter string) (string, error) {
	param := os.Getenv(envName)
	if param == "" {
		return "", fmt.Errorf("missing required %s", errorParameter)
	}

	return param, nil
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}

	return false
}
