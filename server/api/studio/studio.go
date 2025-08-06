package main

import (
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"net/http"
	"strings"

	"github.com/vesoft-inc/go-pkg/middleware"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/internal/config"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/internal/handler"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/internal/svc"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/pkg/auth"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/pkg/client"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/pkg/llm"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/pkg/logging"
	studioMiddleware "github.com/vesoft-inc/nebula-studio/server/api/studio/pkg/middleware"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/pkg/server"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/pkg/utils"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/pkg/ws"
	wsUtils "github.com/vesoft-inc/nebula-studio/server/api/studio/pkg/ws/utils"
	"github.com/zeromicro/go-zero/core/conf"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/core/proc"
	"github.com/zeromicro/go-zero/rest"
	"github.com/zeromicro/go-zero/rest/httpx"
	"go.uber.org/zap"
)

var (
	//go:embed assets/*
	embedAssets embed.FS
	configFile  = flag.String("f", "etc/studio-api.yaml", "the config file")
)

func main() {
	flag.Parse()

	var c config.Config
	conf.MustLoad(*configFile, &c, conf.UseEnv())

	logx.MustSetup(c.Log)
	defer logx.Close()

	// init logger
	loggingOptions := logging.NewOptions()
	if err := loggingOptions.InitGlobals(); err != nil {
		panic(err)
	}

	if err := c.InitConfig(); err != nil {
		zap.L().Fatal("init config failed", zap.Error(err))
	}
	server.InitDB(&c, nil)

	svcCtx := svc.NewServiceContext(c)
	opts := []rest.RunOption{
		rest.WithNotFoundHandler(studioMiddleware.AssetsMiddlewareWithCtx(svcCtx, embedAssets, c.EnableSecurityHeader)),
	}
	if len(c.CorsOrigins) > 0 {
		opts = append(opts, rest.WithCors(c.CorsOrigins...))
	}

	if c.EnableSecurityHeader && c.RestConf.CertFile != "" && c.RestConf.KeyFile != "" {
		fmt.Println("Disable TLS 1.0/1.1 and enforce secure cipher suites")
		customTLS := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			},
		}
		opts = append(opts, rest.WithTLSConfig(customTLS))
	}

	server := rest.MustNewServer(c.RestConf, opts...)

	defer server.Stop()
	waitForCalled := proc.AddWrapUpListener(func() {
		client.ClearClients()
	})
	defer waitForCalled()

	// global middleware
	if c.EnableSecurityHeader {
		fmt.Println("Enable security header")
		xFrameOptionsMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Frame-Options", "SAMEORIGIN")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("X-XSS-Protection", "1; mode=block")

				if strings.HasSuffix(r.URL.Path, ".map") {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}

				w.Header().Set("Content-Security-Policy",
					"default-src 'self'; "+
						"script-src 'self' 'unsafe-inline' 'unsafe-eval'; "+
						"style-src 'self' 'unsafe-inline' 'unsafe-eval'; "+
						"img-src 'self' data:; "+
						"connect-src 'self'; "+
						"font-src 'self'; "+
						"frame-ancestors 'none'; "+
						"base-uri 'self'; "+
						"form-action 'self'")

				next(w, r)
			}
		}
		server.Use(xFrameOptionsMiddleware)
	}

	server.Use(auth.AuthMiddlewareWithCtx(svcCtx))
	server.Use(rest.ToMiddleware(middleware.ReserveRequest(middleware.ReserveRequestConfig{
		Skipper: func(r *http.Request) bool {
			return !utils.PathHasPrefix(r.URL.Path, utils.ReserveRequestRoutes)
		},
	})))
	server.Use(rest.ToMiddleware(middleware.ReserveResponseWriter(middleware.ReserveResponseWriterConfig{
		Skipper: func(r *http.Request) bool {
			return !utils.PathHasPrefix(r.URL.Path, utils.ReserveResponseRoutes)
		},
	})))

	// api handlers
	handler.RegisterHandlers(server, svcCtx)

	// websocket
	hub := wsUtils.NewHub()
	go hub.Run()
	server.AddRoute(rest.Route{
		Method: http.MethodGet,
		Path:   "/nebula_ws",
		Handler: func(w http.ResponseWriter, r *http.Request) {
			clientInfo := &auth.AuthData{}
			tokenCookie, err := r.Cookie(svcCtx.Config.Auth.TokenName)
			if err == nil {
				clientInfo, _ = auth.Decode(tokenCookie.Value, svcCtx.Config.Auth.AccessSecret)
			}
			ws.ServeWebSocket(hub, w, r, clientInfo)
		},
	})

	httpx.SetErrorHandler(func(err error) (int, interface{}) {
		return svcCtx.ResponseHandler.GetStatusBody(nil, nil, err)
	})
	go llm.InitSchedule()
	fmt.Printf("Starting server at %s:%d...\n", c.Host, c.Port)
	server.Start()
}
