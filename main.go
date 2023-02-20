package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/google/uuid"
	"golang.org/x/net/html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
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
	envAwsRegion    = "AWS_REGION" // reserved env

	defaultListener = "https://listener.logz.io:8071"
	defaultLogType  = "synthetic-links-detector"

	maxRedirects = 2
)

var (
	logger                 *log.Logger
	token                  string
	listener               string
	fullListener           string
	urlToInspect           string
	logType                string
	httpClientLogzioSender *http.Client
	wg                     sync.WaitGroup
	runUuid                string
	zeroDialer             net.Dialer
	regionToGeoLocation    = map[string][]float64{
		"us-east-1":      {-78.024902, 37.926868},  // N. Virginia
		"us-east-2":      {-82.996216, 40.367474},  // Ohio
		"us-west-1":      {-119.417931, 36.778259}, // N. California
		"us-west-2":      {-120.500000, 44.000000}, // Oregon
		"ap-south-1":     {72.877426, 19.076090},   // Mumbai
		"ap-northeast-3": {135.484802, 34.672314},  // Osaka
		"ap-northeast-2": {127.024612, 37.532600},  // Seoul
		"ap-southeast-1": {103.851959, 1.290270},   // Singapore
		"ap-southeast-2": {151.209900, -33.865143}, // Sydney
		"ap-northeast-1": {139.839478, 35.652832},  // Tokyo
		"ca-central-1":   {-73.561668, 45.508888},  // Canada Central
		"eu-central-1":   {8.682127, 50.110924},    // Frankfurt
		"eu-west-1":      {-6.266155, 53.350140},   // Ireland
		"eu-west-2":      {-0.118092, 51.509865},   // London
		"eu-west-3":      {2.349014, 48.864716},    // Paris
		"eu-north-1":     {18.063240, 59.334591},   // Stockholm
		"sa-east-1":      {-46.625290, -23.533773}, // Sao Paulo
	}
	location  []float64
	awsRegion string
)

func main() {
	lambda.Start(HandleRequest)
}

func HandleRequest(ctx context.Context, event map[string]interface{}) (string, error) {
	if _, ok := event["RequestId"]; ok {
		// First invocation
		if event["RequestType"].(string) == "Create" {
			lambda.Start(cfn.LambdaWrap(customResourceRun))
		} else {
			lambda.Start(cfn.LambdaWrap(customResourceRunDoNothing))
		}
	} else {
		// Scheduled invocation
		return run()
	}

	return "lambda finished", nil
}

// Wrapper for first invocation from cloud formation custom resource
func customResourceRun(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	_, err = run()
	return
}

func customResourceRunDoNothing(ctx context.Context, event cfn.Event) (physicalResourceID string, data map[string]interface{}, err error) {
	return
}

func run() (string, error) {
	err := getParameters()
	if err != nil {
		return "lambda encountered error while getting parameters", err
	}

	err = generateUuid()
	if err != nil {
		return "lambda encountered error while generating run_uuid", err
	}

	logger = log.New(os.Stdout, runUuid, log.Ldate|log.Ltime|log.Lshortfile)
	linksInPage := getLinksInPage(urlToInspect)
	logger.Printf("detected %d links in %s\n", len(linksInPage), urlToInspect)
	wg.Add(len(linksInPage))
	setupHttpClientLogzioSender()
	for _, link := range linksInPage {
		go detectAndSend(link, urlToInspect)
	}

	wg.Wait()
	logger.Printf("finished run\n")
	return "finished run", nil
}

func generateUuid() error {
	id := uuid.New()

	runUuid = id.String()
	return nil
}

func setupHttpClientLogzioSender() {
	tlsConfig := &tls.Config{}
	transport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}

	// in case server side is sleeping - wait 10s instead of waiting for him to wake up
	httpClientLogzioSender = &http.Client{
		Transport: transport,
		Timeout:   time.Second * 10,
	}
}

func detectAndSend(link, mainUrl string) {
	currentRedirect := 0
	linkToInspect := link
	for {
		resp := createSendData(linkToInspect, mainUrl)
		if resp != nil {
			if resp.StatusCode > 299 && resp.StatusCode < 400 && currentRedirect < maxRedirects {
				linkToInspectUrlObj, err := resp.Location()
				if err != nil {
					logger.Printf("Error on redirect: %s", err.Error())
					break
				}
				linkToInspect = linkToInspectUrlObj.String()
				currentRedirect++
			} else {
				break
			}
		} else {
			break
		}
	}
}

func createSendData(link, mainUrl string) *http.Response {
	defer wg.Done()
	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		logger.Printf("unable to create request: %v\n", err)
		return nil
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
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return zeroDialer.DialContext(ctx, "tcp4", addr)
		},
	}

	l, err := url.Parse(link)
	if err != nil {
		logger.Printf("could not parse link %s: %s\n", link, err.Error())
		return nil
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
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("failed to read response: %v\n", err)
		return nil
	}

	w := io.Discard
	if _, err := io.Copy(w, resp.Body); err != nil && w != io.Discard {
		logger.Printf("failed to read response body: %v\n", err)
		return nil
	}

	resp.Body.Close()

	t7 := time.Now() // after read body
	if t0.IsZero() {
		// we skipped DNS
		t0 = t1
	}

	data := make(map[string]interface{}, 0)
	data["link"] = link
	data["main_url"] = mainUrl
	data["status_code"] = strconv.Itoa(resp.StatusCode)
	switch l.Scheme {
	case "https":
		data["dns_lookup"] = t1.Sub(t0).Milliseconds()
		data["tcp_connection"] = t2.Sub(t1).Milliseconds()
		data["tls_handshake"] = t6.Sub(t5).Milliseconds()
		data["server_processing"] = t4.Sub(t3).Milliseconds()
		data["content_transfer"] = t7.Sub(t4).Milliseconds()
		data["name_lookup"] = t1.Sub(t0).Milliseconds()
		data["connect"] = t2.Sub(t0).Milliseconds()
		data["pre_transfer"] = t3.Sub(t0).Milliseconds()
		data["start_transfer"] = t4.Sub(t0).Milliseconds()
		data["total"] = t7.Sub(t0).Milliseconds()
	case "http":
		data["dns_lookup"] = t1.Sub(t0).Milliseconds()
		data["tcp_connection"] = t3.Sub(t1).Milliseconds()
		data["server_processing"] = t4.Sub(t3).Milliseconds()
		data["content_transfer"] = t7.Sub(t4).Milliseconds()
		data["name_lookup"] = t1.Sub(t0).Milliseconds()
		data["connect"] = t3.Sub(t0).Milliseconds()
		data["start_transfer"] = t4.Sub(t0).Milliseconds()
		data["total"] = t7.Sub(t0).Milliseconds()
	}

	processAndSendLog(data)
	return resp
}

func processAndSendLog(data map[string]interface{}) {
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
		resp, err := httpClientLogzioSender.Do(req)
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

func addLogzioFields(data map[string]interface{}) {
	data["type"] = logType
	data["run_id"] = runUuid
	data["geoip"] = map[string][]float64{
		"location": location,
	}
	data["aws_region"] = awsRegion
}

func addCustomFields(data map[string]interface{}) {
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
						tmpUrl := url
						tmpLink := link
						prefix, _ := regexp.Compile("^/+")
						suffix, _ := regexp.Compile("/+$")
						prefixIndex := prefix.FindStringIndex(link)
						if len(prefixIndex) > 0 {
							tmpLink = link[prefixIndex[1]:len(link)]
						}
						suffixIndex := suffix.FindStringIndex(url)
						if len(suffixIndex) > 0 {
							tmpUrl = url[:suffixIndex[0]]
						}

						link = fmt.Sprintf("%s/%s", tmpUrl, tmpLink)
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

	awsRegion = os.Getenv(envAwsRegion)
	if awsRegion == "" {
		logger.Print("Could not get aws region. geolocation will not be added\nֿ")
	} else {
		if val, ok := regionToGeoLocation[awsRegion]; ok {
			location = val
		} else {
			logger.Printf("region %s is not mapped. geolocation will not be added\n")
		}
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
