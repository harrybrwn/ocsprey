package log

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type loggerContextKey string

const loggerKey = loggerContextKey("_logger")

func Stash(ctx context.Context, logger logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func ContextLogger(ctx context.Context) logrus.FieldLogger {
	res := ctx.Value(loggerKey)
	if res == nil {
		l := logrus.New()
		l.Warn("couldn't find logger in context")
		return l
	}
	return res.(logrus.FieldLogger)
}

func HTTPRequests(wrap http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := ContextLogger(ctx).WithFields(logrus.Fields{
			"method":      r.Method,
			"uri":         r.RequestURI,
			"host":        r.Host,
			"remote_addr": r.RemoteAddr,
		})
		l.Trace("request")
		wrap.ServeHTTP(w, r.WithContext(Stash(ctx, l)))
	}
}
