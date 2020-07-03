package logger

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"io/ioutil"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Headers
const (
	HeaderXRequestID = "X-Request-ID"
)

// Config defines the config for logger middleware
type Config struct {
	Logger *zerolog.Logger
	// UTC a boolean stating whether to use UTC time zone or local.
	UTC                    bool
	SkipPath               []string
	SkipPathRegexp         *regexp.Regexp
	Format                 string
	Output                 io.Writer
	SkipLoggedPathResponse []string
}

var (
	// DefaultLoggerConfig is the default Logger middleware config.
	DefaultLoggerConfig = Config{
		UTC: true,
		Format: `{"time":"${time_rfc3339_nano}","id":"${id}","remote_ip":"${remote_ip}",` +
			`"host":"${host}","method":"${method}","uri":"${uri}","user_agent":"${user_agent}",` +
			`"status":${status},"error":"${error}","latency":${latency},"latency_human":"${latency_human}"` +
			`,"bytes_in":${bytes_in},"bytes_out":${bytes_out}}` + "\n",
		Output: os.Stdout,
	}
)

type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// SetLogger initializes the logging middleware.
func SetLogger(config ...Config) gin.HandlerFunc {

	flag.Parse()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if gin.IsDebugging() {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	var newConfig Config
	if len(config) > 0 {
		newConfig = config[0]
	}
	var skip map[string]struct{}
	if length := len(newConfig.SkipPath); length > 0 {
		skip = make(map[string]struct{}, length)
		for _, path := range newConfig.SkipPath {
			skip[path] = struct{}{}
		}
	}

	var skipLoggedPathResponse map[string]struct{}
	if length := len(newConfig.SkipLoggedPathResponse); length > 0 {
		skipLoggedPathResponse = make(map[string]struct{}, length)
		for _, path := range newConfig.SkipLoggedPathResponse {
			skipLoggedPathResponse[path] = struct{}{}
		}
	}

	// log.Logger = log.Output(
	// 	zerolog.ConsoleWriter{
	// 		Out:     os.Stdout,
	// 		NoColor: false,
	// 	},
	// )

	if newConfig.Format == "" {
		newConfig.Format = DefaultLoggerConfig.Format
	}

	if newConfig.Output == nil {
		newConfig.Output = DefaultLoggerConfig.Output
	}

	newConfig.UTC = DefaultLoggerConfig.UTC

	var sublog zerolog.Logger
	if newConfig.Logger == nil {
		sublog = log.Logger
	} else {
		sublog = *newConfig.Logger
	}

	return func(c *gin.Context) {

		timestamp := strconv.Itoa(int(time.Now().Unix()))
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		if raw != "" {
			path = path + "?" + raw
		}

		track := true

		if _, ok := skip[path]; ok {
			track = false
		}

		if track &&
			newConfig.SkipPathRegexp != nil &&
			newConfig.SkipPathRegexp.MatchString(path) {
			track = false
		}

		if track {
			var responseBody bytes.Buffer

			// Take req body and add again to request context
			// Because can only read json once
			body, _ := c.GetRawData()

			blw := &bodyLogWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
			c.Writer = blw

			rdr := ioutil.NopCloser(bytes.NewBuffer(body))
			c.Request.Body = rdr

			c.Next()

			hostname, err := os.Hostname()
			if err != nil {
				hostname = "unknown"
			}

			end := time.Now()
			latency := end.Sub(start)
			if newConfig.UTC {
				end = end.UTC()
			}

			msg := "Request"
			if len(c.Errors) > 0 {
				msg = c.Errors.String()
			}

			// Create new json body with removed unnecesarry character
			// eg: \n \r etc
			bodyBuffer := new(bytes.Buffer)
			if len(body) > 0 {
				if err := json.Compact(bodyBuffer, body); err != nil {
					msg = c.Errors.String()
				}
			}

			compactBody := bodyBuffer.Bytes()
			if len(compactBody) == 0 {
				compactBody = []byte("null")
			}

			if _, ok := skipLoggedPathResponse[path]; !ok || c.Writer.Status() >= http.StatusBadRequest {
				responseBody = *blw.body
			}

			reqID := CxtRequestID(c)
			reqMethod := c.Request.Method
			reqURI := c.Request.RequestURI
			statusCode := c.Writer.Status()
			clientIP := c.ClientIP()
			clientUserAgent := c.Request.UserAgent()
			referer := c.Request.Referer()
			dataLength := c.Writer.Size()
			if dataLength < 0 {
				dataLength = 0
			}

			dumplogger := sublog.With().
				Str("timestamp", timestamp).
				Str("requestID", reqID).
				Str("host", hostname).
				Str("header", GetAllHeaders(c)).
				Str("uri", reqURI).
				Int("status", statusCode).
				Str("method", reqMethod).
				Str("path", path).
				Str("ip", clientIP).
				Dur("latency", latency).
				Str("user-agent", clientUserAgent).
				Str("referer", referer).
				RawJSON("body", compactBody).
				RawJSON("responseBody", responseBody.Bytes()).
				Logger()

			switch {
			case c.Writer.Status() >= http.StatusBadRequest && c.Writer.Status() < http.StatusInternalServerError:
				{
					dumplogger.Warn().
						Msg(msg)
				}
			case c.Writer.Status() >= http.StatusInternalServerError:
				{
					dumplogger.Error().
						Msg(msg)
				}
			default:
				dumplogger.Info().
					Msg(msg)
			}
		}

	}
}

func CxtRequestID(c *gin.Context) string {

	// already setup, so we're done
	if id, found := c.Get(HeaderXRequestID); found == true {
		return id.(string)
	}

	return ""

}

func GetAllHeaders(c *gin.Context) string {
	var headers string
	if reqHeadersBytes, err := json.Marshal(c.Request.Header); err == nil {
		headers = string(reqHeadersBytes)
	}

	return headers
}
