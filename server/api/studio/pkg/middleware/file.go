package utils

import (
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/vesoft-inc/go-pkg/middleware"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/internal/svc"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/pkg/ecode"
	"github.com/vesoft-inc/nebula-studio/server/api/studio/pkg/utils"
)

func AssetsMiddlewareWithCtx(svcCtx *svc.ServiceContext, embedAssets fs.FS, enableSecurityHeader bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if filepath.Ext(r.URL.Path) == "" {
			tpl, err := template.ParseFS(embedAssets, "assets/index.html")
			withErrorMessage := utils.ErrMsgWithLogger(r.Context())
			if err != nil {
				svcCtx.ResponseHandler.Handle(w, r, nil, withErrorMessage(ecode.ErrInternalServer, err))
				return
			}

			w.Header().Set("Content-Type", "text/html")

			if enableSecurityHeader {
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
			}

			w.WriteHeader(http.StatusOK)
			tpl.Execute(w, map[string]any{"appInstance": svcCtx.Config.AppInstance})
			return
		}

		handler := middleware.NewAssetsHandler(middleware.AssetsConfig{
			Root:       "assets",
			Filesystem: http.FS(embedAssets),
			SPA:        true,
		})
		// if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && !strings.Contains(r.Header.Get("Accept"), "image/") {
		// 	w.Header().Set("Content-Encoding", "gzip")
		// }

		if enableSecurityHeader {
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
		}

		handler.ServeHTTP(w, r)
	})
}
