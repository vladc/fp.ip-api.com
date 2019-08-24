package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

var (
	socket *string
)

type query struct {
	magic     uint32
	addr_type uint8
	addr      [16]uint8
}

type response struct {
	Magic       uint32    /* Must be P0F_RESP_MAGIC             */
	Status      uint32    /* P0F_STATUS_*                       */
	First_seen  uint32    /* First seen (unix time)             */
	Last_seen   uint32    /* Last seen (unix time)              */
	Total_conn  uint32    /* Total connections seen             */
	Uptime_min  uint32    /* Last uptime (minutes)              */
	Up_mod_days uint32    /* Uptime modulo (days)               */
	Last_nat    uint32    /* NAT / LB last detected (unix time) */
	Last_chg    uint32    /* OS chg last detected (unix time)   */
	Distance    int16     /* System distance                    */
	Bad_sw      uint8     /* Host is lying about U-A / Server   */
	Os_match_q  uint8     /* Match quality                      */
	Os_name     [32]uint8 /* Name of detected OS                */
	Os_flavor   [32]uint8 /* Flavor of detected OS              */
	Http_name   [32]uint8 /* Name of detected HTTP app          */
	Http_flavor [32]uint8 /* Flavor of detected HTTP app        */
	Link_mtu    uint16    /* Link MTU value                     */
	Link_type   [32]uint8 /* Link type                          */
	Language    [32]uint8 /* Language                           */
}

func main() {
	setLog("/var/log/fingerprint/access.log")
	socket = flag.String("socket", "/opt/p0f_socket", "p0f socket")
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU())

	log.Printf("Starting with p0f_socket=%s", string(*socket))

	mux := http.NewServeMux()
	mux.HandleFunc("/", dispatcher())

	go func() {
		s := http.Server{
			Addr:         "0.0.0.0:80",
			Handler:      mux,
			ReadTimeout:  8 * time.Second,
			WriteTimeout: 8 * time.Second,
		}
		log.Printf("Starting HTTP server")
		log.Fatal(s.ListenAndServe())
	}()
	select {}
}

func handleError(message string, query string) map[string]interface{} {
	ret := make(map[string]interface{})
	ret["status"] = "fail"
	ret["message"] = message
	ret["query"] = query
	return ret
}

func Lookup(r *http.Request) map[string]interface{} {
	var ip net.IP
	if sIP, _, err := net.SplitHostPort(r.RemoteAddr); err != nil {
		ip = net.ParseIP(r.RemoteAddr)
	} else {
		ip = net.ParseIP(sIP)
	}
	if ip == nil {
		return handleError("internal error [0]", ip.String())
	}
	_, err := ip2int(ip)
	if err != nil {
		return handleError("invalid IPv4", ip.String())
	}
	c, err := net.Dial("unix", *socket)
	if err != nil {
		return handleError("internal error [1]", ip.String())
	}
	defer c.Close()
	q := &query{0x50304601, 0x04, [16]uint8{ip[12], ip[13], ip[14], ip[15]}}
	if err := binary.Write(c, binary.LittleEndian, q); err != nil {
		return handleError("internal error [2]", ip.String())
	}
	var resp response
	rerr := binary.Read(c, binary.LittleEndian, &resp)
	if rerr != nil {
		return handleError("internal error [3]", ip.String())
	}
	if resp.Magic != 0x50304602 {
		return handleError("internal error [4]", ip.String())
	}
	if resp.Status != 0x10 {
		return handleError(fmt.Sprintf("internal error [%04x]", resp.Status), ip.String())
	}
	ret := make(map[string]interface{})
	ret["status"] = "success"
	ret["query"] = ip.String()
	ret["first_seen"] = resp.First_seen
	ret["last_seen"] = resp.Last_seen
	ret["total_conn"] = resp.Total_conn
	ret["uptime_min"] = resp.Uptime_min
	ret["up_mod_days"] = resp.Up_mod_days
	ret["last_nat"] = resp.Last_nat
	ret["last_chg"] = resp.Last_chg
	ret["distance"] = resp.Distance
	ret["bad_sw"] = resp.Bad_sw
	ret["os_match_q"] = resp.Os_match_q
	ret["os_name"] = toStr(resp.Os_name)
	ret["os_flavor"] = toStr(resp.Os_flavor)
	ret["http_name"] = toStr(resp.Http_name)
	ret["http_flavor"] = toStr(resp.Http_flavor)
	ret["link_type"] = toStr(resp.Link_type)
	ret["link_mtu"] = resp.Link_mtu
	ret["language"] = toStr(resp.Language)
	ret["user_agent"] = r.UserAgent()
	return ret
}

func toStr(c [32]uint8) string {
	n := -1
	for i, b := range c {
		if b == 0 {
			break
		}
		n = i
	}
	return string(c[:n+1])
}

func QueryHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/favicon.ico" {
		http.Error(w, http.StatusText(404), 404)
		return
	}
	if path == "/json" || path == "/json/" {
		w.Header().Set("Connection", "close")
		time.Sleep(25 * time.Millisecond)
		o := Lookup(r)
		jsonBytes, _ := json.MarshalIndent(o, "", "	")
		if cb := r.FormValue("callback"); len(cb) > 0 {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			fmt.Fprintf(w, "%s(%s);", html.EscapeString(cb), jsonBytes)
		} else {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			fmt.Fprintf(w, "%s", jsonBytes)
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "ip-api.com fingerprint API at /json/ (JSONP via 'callback' parameter)\r\nBased on p0f - see https://github.com/ValdikSS/p0f-mtu for documentation.")
}

func dispatcher() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		w.Header().Set("Access-Control-Allow-Origin", "*")
		switch r.Method {
		case "OPTIONS":
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "1728000")
			w.WriteHeader(200)
		case "GET", "POST", "HEAD":
			QueryHandler(w, r)
		default:
			w.Header().Set("Allow", "GET, POST, HEAD, OPTIONS")
			http.Error(w, http.StatusText(405), 405)
		}
		log.Printf("%s %q %q %s %s", r.Method, r.URL, r.Referer(), r.RemoteAddr, time.Since(now))
	}
}

func setLog(filename string) {
	f := openLog(filename)
	log.SetOutput(f)
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP)
	go func() {
		var fb *os.File
		for {
			<-sigc
			fb = f
			f = openLog(filename)
			log.SetOutput(f)
			fb.Close()
		}
	}()
}

func openLog(filename string) *os.File {
	f, err := os.OpenFile(
		filename,
		os.O_WRONLY|os.O_CREATE|os.O_APPEND,
		0644,
	)
	if err != nil {
		log.SetOutput(os.Stderr)
		log.Fatal(err)
	}
	return f
}

func ip2int(ip net.IP) (uint32, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("IP %s is not IPv4", ip.String())
	}
	return binary.BigEndian.Uint32(ipv4), nil
}
