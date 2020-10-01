package proxy

// type authorizeResponse struct {
// 	authorized bool
// 	statusCode int32
// }

// func (p *Proxy) isAuthorized(w http.ResponseWriter, r *http.Request) (*authorizeResponse, error) {
// 	res, err := p.authorizeCheck(r)
// 	if err != nil {
// 		return nil, httputil.NewError(http.StatusInternalServerError, err)
// 	}

// 	ar := &authorizeResponse{}
// 	switch res.HttpResponse.(type) {
// 	case *envoy_service_auth_v2.CheckResponse_OkResponse:
// 		for _, hdr := range res.GetOkResponse().GetHeaders() {
// 			w.Header().Set(hdr.GetHeader().GetKey(), hdr.GetHeader().GetValue())
// 		}
// 		ar.authorized = true
// 		ar.statusCode = res.GetStatus().Code
// 	case *envoy_service_auth_v2.CheckResponse_DeniedResponse:
// 		ar.statusCode = int32(res.GetDeniedResponse().GetStatus().Code)
// 	default:
// 		ar.statusCode = http.StatusInternalServerError
// 	}
// 	return ar, nil
// }

// func (p *Proxy) authorizeCheck(r *http.Request) (*envoy_service_auth_v2.CheckResponse, error) {
// 	state := p.state.Load()

// 	tm, err := ptypes.TimestampProto(time.Now())
// 	if err != nil {
// 		return nil, httputil.NewError(http.StatusInternalServerError, fmt.Errorf("error creating protobuf timestamp from current time: %w", err))
// 	}

// 	httpAttrs := &envoy_service_auth_v2.AttributeContext_HttpRequest{
// 		Method:   "GET",
// 		Headers:  map[string]string{},
// 		Path:     r.URL.Path,
// 		Host:     r.Host,
// 		Scheme:   r.URL.Scheme,
// 		Fragment: r.URL.Fragment,
// 	}
// 	for k := range r.Header {
// 		httpAttrs.Headers[k] = r.Header.Get(k)
// 	}
// 	if r.URL.RawQuery != "" {
// 		// envoy expects the query string in the path
// 		httpAttrs.Path += "?" + r.URL.RawQuery
// 	}

// 	return state.authzClient.Check(r.Context(), &envoy_service_auth_v2.CheckRequest{
// 		Attributes: &envoy_service_auth_v2.AttributeContext{
// 			Request: &envoy_service_auth_v2.AttributeContext_Request{
// 				Time: tm,
// 				Http: httpAttrs,
// 			},
// 		},
// 	})
// }

// // jwtClaimMiddleware logs and propagates JWT claim information via request headers
// //
// // if returnJWTInfo is set to true, it will also return JWT claim information in the response
// func (p *Proxy) jwtClaimMiddleware(returnJWTInfo bool) mux.MiddlewareFunc {
// 	return func(next http.Handler) http.Handler {
// 		return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
// 			defer next.ServeHTTP(w, r)

// 			state := p.state.Load()

// 			jwt, err := sessions.FromContext(r.Context())
// 			if err != nil {
// 				log.Error().Err(err).Msg("proxy: could not locate session from context")
// 				return nil // best effort decoding
// 			}

// 			formattedJWTClaims, err := p.getFormatedJWTClaims([]byte(jwt))
// 			if err != nil {
// 				log.Error().Err(err).Msg("proxy: failed to format jwt claims")
// 				return nil // best effort formatting
// 			}

// 			// log group, email, user claims
// 			l := log.Ctx(r.Context())
// 			for _, claimName := range []string{"groups", "email", "user"} {

// 				l.UpdateContext(func(c zerolog.Context) zerolog.Context {
// 					return c.Str(claimName, fmt.Sprintf("%v", formattedJWTClaims[claimName]))
// 				})

// 			}

// 			// set headers for any claims specified by config
// 			for _, claimName := range state.jwtClaimHeaders {
// 				if _, ok := formattedJWTClaims[claimName]; ok {

// 					headerName := fmt.Sprintf("x-pomerium-claim-%s", claimName)
// 					r.Header.Set(headerName, formattedJWTClaims[claimName])
// 					if returnJWTInfo {
// 						w.Header().Add(headerName, formattedJWTClaims[claimName])
// 					}
// 				}
// 			}

// 			return nil
// 		})
// 	}
// }

// // getFormatJWTClaims reformats jwtClaims into something resembling map[string]string
// func (p *Proxy) getFormatedJWTClaims(jwt []byte) (map[string]string, error) {
// 	state := p.state.Load()

// 	formattedJWTClaims := make(map[string]string)

// 	var jwtClaims map[string]interface{}
// 	if err := state.encoder.Unmarshal(jwt, &jwtClaims); err != nil {
// 		return formattedJWTClaims, err
// 	}

// 	for claim, value := range jwtClaims {
// 		var formattedClaim string
// 		if cv, ok := value.([]interface{}); ok {
// 			elements := make([]string, len(cv))

// 			for i, v := range cv {
// 				elements[i] = fmt.Sprintf("%v", v)
// 			}
// 			formattedClaim = strings.Join(elements, ",")
// 		} else {
// 			formattedClaim = fmt.Sprintf("%v", value)
// 		}
// 		formattedJWTClaims[claim] = formattedClaim
// 	}

// 	return formattedJWTClaims, nil
// }
