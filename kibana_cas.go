/*
TODO:
1. session encrypt
2. session expire time
*/
package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	CookieExpireTime = 48 // 2 days
)

var (
	localHost = flag.String("localhost", "0.0.0.0", "local address")
	localPort = flag.Int("localport", 8888, "local port")
	dstHost   = flag.String("dsthost", "", "kibana address")
	dstPort   = flag.Int("dstport", 80, "kibana port")
	domain    = flag.String("domain", "log.mi.com", "log domain url")
	casUrl    = flag.String("casurl", "", "cas url, eg: https://cas.mi.com")
	logFile   = flag.String("logfile", "./access.log", "logfile")
)

var logger *log.Logger

type handle struct {
	host string
	port int
}

func (this *handle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user_cookie, err := r.Cookie("kibana_user")
	if err != nil {
		logger.Printf("ERROR: get cookie err: %s\n", err)
		http.Redirect(w, r, "/login", 301)
		return
	} else {
		if time.Now().Sub(user_cookie.Expires) <= 0 {
			logger.Println("ERROR: cookie expire")
			http.Redirect(w, r, "/logout", 301)
			return
		}
	}
	username := user_cookie.Value
	logger.Printf("INFO: %s %s - %s\n", username, r.Method, r.RequestURI)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	remote, err := url.Parse(fmt.Sprintf("http://%s:%d", *dstHost, *dstPort))
	if err != nil {
		logger.Printf("ERROR: parse url err: %s\n", err)
		os.Exit(1)
	}
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.ServeHTTP(w, r)
}

func init() {
	flag.Parse()
	if *dstHost == "" {
		fmt.Println("-h to get help message")
		os.Exit(1)
	}
	if *casUrl == "" || strings.HasPrefix(*casUrl, "/") {
		fmt.Println("cas url is need, and can't not be end with /")
		os.Exit(1)
	}
	logfile, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("open or write log file err: %s\n", err)
		os.Exit(1)
	}
	logger = log.New(logfile, "logger: ", log.Ldate|log.Ltime|log.Llongfile)
}

func main() {

	// login handle
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("INFO: - %s - %s\n", r.Method, r.RequestURI)
		if strings.Contains(r.RequestURI, "?ticket=") {
			queryurl := strings.Split(r.RequestURI, "?")
			values, err := url.ParseQuery(queryurl[1])
			if err != nil {
				logger.Printf("ERROR: url parse query %s err: %s\n", queryurl[1], err)
				return
			}
			ticket := values.Get("ticket")
			data, err := ValidateTicket(ticket)
			if err != nil {
				logger.Printf("ERROR: validate ticket err: %s\n", err)
				return
			}
			results := strings.Split(data, "\n")
			if results[0] != "yes" {
				http.Redirect(w, r, "/logout", 301)
				return
			} else {
				// cookie := &http.Cookie{Name: "kibana_user", Value: EncodeCookie(results[1]), Expires: time.Now().Add(CookieExpireTime * time.Hour)}
				cookie := &http.Cookie{Name: "kibana_user", Value: results[1], Expires: time.Now().Add(CookieExpireTime * time.Hour)}
				http.SetCookie(w, cookie)
				http.Redirect(w, r, "/", 301)
				return
			}
		} else {
			cas_login_url := fmt.Sprintf("%s/login?service=%s", *casUrl, url.QueryEscape(fmt.Sprintf("http://%s/login", *domain)))
			http.Redirect(w, r, cas_login_url, 301)
			return
		}
	})

	// logout handle
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("INFO: - %s - %s\n", r.Method, r.RequestURI)
		cas_logout_url := fmt.Sprintf("%s/logout", *casUrl)
		cookie := &http.Cookie{Name: "kibana_user", MaxAge: -1}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, cas_logout_url, 301)
	})

	// proxy handle
	proxyhandle := &handle{host: *dstHost, port: *dstPort}
	http.Handle("/", proxyhandle)

	// listen
	localaddr := fmt.Sprintf("%s:%d", *localHost, *localPort)
	err := http.ListenAndServe(localaddr, nil)
	if err != nil {
		logger.Printf("ERROR: listen port 8888 err: %s\n", err)
		return
	}
}

func ValidateTicket(ticket string) (string, error) {
	if ticket != "" {
		cas_valid_url := fmt.Sprintf("%s/validate?service=%s&ticket=%s", *casUrl, url.QueryEscape(fmt.Sprintf("http://%s/login", *domain)), ticket)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		resp, err := client.Get(cas_valid_url)
		if err != nil {
			logger.Printf("ERROR: validate ticket err: %s\n", err)
			return "", err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logger.Printf("ERROR: validate ticket read body err: %s\n", err)
			return "", err
		}
		return string(body), nil
	} else {
		return "", errors.New("unknown ticket")
	}
}

func EncodeCookie(src string) string {
	return base64.StdEncoding.EncodeToString([]byte(src))
}

func DecodeCookie(src string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return "", err
	} else {
		return string(data), nil
	}
}
