package logger

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
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
	UTC            bool
	SkipPath       []string
	SkipPathRegexp *regexp.Regexp
	Format         string
	Output         io.Writer
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

// SetLogger initializes the logging middleware.
func SetLogger(config ...Config) gin.HandlerFunc {
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

	if newConfig.Format == "" {
		newConfig.Format = DefaultLoggerConfig.Format
	}

	if newConfig.Output == nil {
		newConfig.Output = DefaultLoggerConfig.Output
	}

	var sublog zerolog.Logger
	if newConfig.Logger == nil {
		sublog = log.Logger
	} else {
		sublog = *newConfig.Logger
	}

	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery
		if raw != "" {
			path = path + "?" + raw
		}

		c.Next()
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
			reqID := CxtRequestID(c)
			reqMethod := c.Request.Method
			reqURI := c.Request.RequestURI
			statusCode := c.Writer.Status()
			clientIP := c.ClientIP()
			clientUserAgent := c.Request.UserAgent()
			postParams, _ := ioutil.ReadAll(c.Request.Body)
			referer := c.Request.Referer()
			dataLength := c.Writer.Size()
			if dataLength < 0 {
				dataLength = 0
			}
			c.Request.Body = ioutil.NopCloser(bytes.NewReader(postParams))

			dumplogger := sublog.With().
				Str("requestID", reqID).
				Str("host", hostname).
				Str("header", GetAllHeaders(c)).
				Str("uri", reqURI).
				Int("status", statusCode).
				Str("method", reqMethod).
				Str("post-param", string(postParams)).
				Str("path", path).
				Str("ip", clientIP).
				Str("post-param", string(postParams)).
				Dur("latency", latency).
				Str("user-agent", clientUserAgent).
				Str("referer", referer).
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
