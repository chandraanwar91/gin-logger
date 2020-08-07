# logger

Gin middleware/handler to logger url path using [rs/zerolog](https://github.com/rs/zerolog).

## Example:

```go
package main

import (
	"github.com/chandraanwar91/logger"
	"github.com/gin-gonic/gin"
)

func main() {
	//setting confing
	config := logger.Config{
		SkipPath:               []string{"/application/health"}, // if we want to skip log
		SkipLoggedPathResponse: []string{"/application/get-credential"}, //if we don't want to log body response
	}

	r := gin.New()

	// Add a logger middleware, which:
	//   - Logs all requests, like a combined access and error log.
	//   - Logs to stdout.
	r.Use(logger.SetLogger(config))

	// Listen and Server in 0.0.0.0:8080
	r.Run(":8080")
}
```
