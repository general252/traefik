package anonymize

import (
	"flag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	traefiktls "github.com/traefik/traefik/v2/pkg/tls"
	"github.com/traefik/traefik/v2/pkg/types"
	"os"
	"strings"
	"testing"
)

var updateExpected = flag.Bool("update_expected", false, "Update expected files in fixtures")

func TestDo_dynamicConfiguration(t *testing.T) {
	config := &dynamic.Configuration{}
	config.HTTP = &dynamic.HTTPConfiguration{
		Routers: map[string]*dynamic.Router{
			"foo": {
				EntryPoints: []string{"foo"},
				Middlewares: []string{"foo"},
				Service:     "foo",
				Rule:        "foo",
				Priority:    42,
				TLS: &dynamic.RouterTLSConfig{
					Options:      "foo",
					CertResolver: "foo",
					Domains: []types.Domain{
						{
							Main: "foo",
							SANs: []string{"foo"},
						},
					},
				},
			},
		},
		Services: map[string]*dynamic.Service{
			"foo": {
				LoadBalancer: &dynamic.ServersLoadBalancer{
					Sticky: &dynamic.Sticky{
						Cookie: &dynamic.Cookie{
							Name:     "foo",
							Secure:   true,
							HTTPOnly: true,
							SameSite: "foo",
						},
					},
					HealthCheck: &dynamic.ServerHealthCheck{
						Scheme:          "foo",
						Path:            "foo",
						Port:            42,
						Interval:        "foo",
						Timeout:         "foo",
						Hostname:        "foo",
						FollowRedirects: boolPtr(true),
						Headers: map[string]string{
							"foo": "bar",
						},
					},
					PassHostHeader: boolPtr(true),
					ResponseForwarding: &dynamic.ResponseForwarding{
						FlushInterval: "foo",
					},
					ServersTransport: "foo",
					Servers: []dynamic.Server{
						{
							URL: "http://127.0.0.1:8080",
						},
					},
				},
			},
			"bar": {
				Weighted: &dynamic.WeightedRoundRobin{
					Services: []dynamic.WRRService{
						{
							Name:   "foo",
							Weight: intPtr(42),
						},
					},
					Sticky: &dynamic.Sticky{
						Cookie: &dynamic.Cookie{
							Name:     "foo",
							Secure:   true,
							HTTPOnly: true,
							SameSite: "foo",
						},
					},
				},
			},
			"baz": {
				Mirroring: &dynamic.Mirroring{
					Service:     "foo",
					MaxBodySize: int64Ptr(42),
					Mirrors: []dynamic.MirrorService{
						{
							Name:    "foo",
							Percent: 42,
						},
					},
				},
			},
		},
		ServersTransports: map[string]*dynamic.ServersTransport{
			"foo": {
				ServerName:         "foo",
				InsecureSkipVerify: true,
				RootCAs:            []traefiktls.FileOrContent{"rootca.pem"},
				Certificates: []traefiktls.Certificate{
					{
						CertFile: "cert.pem",
						KeyFile:  "key.pem",
					},
				},
				MaxIdleConnsPerHost: 42,
				ForwardingTimeouts: &dynamic.ForwardingTimeouts{
					DialTimeout:           42,
					ResponseHeaderTimeout: 42,
					IdleConnTimeout:       42,
				},
			},
		},
		Models: map[string]*dynamic.Model{
			"foo": {
				Middlewares: []string{"foo"},
				TLS: &dynamic.RouterTLSConfig{
					Options:      "foo",
					CertResolver: "foo",
					Domains: []types.Domain{
						{
							Main: "foo",
							SANs: []string{"foo"},
						},
					},
				},
			},
		},
		Middlewares: map[string]*dynamic.Middleware{
			"foo": {
				AddPrefix: &dynamic.AddPrefix{
					Prefix: "foo",
				},
				StripPrefix: &dynamic.StripPrefix{
					Prefixes:   []string{"foo"},
					ForceSlash: true,
				},
				StripPrefixRegex: &dynamic.StripPrefixRegex{
					Regex: []string{"foo"},
				},
				ReplacePath: &dynamic.ReplacePath{
					Path: "foo",
				},
				ReplacePathRegex: &dynamic.ReplacePathRegex{
					Regex:       "foo",
					Replacement: "foo",
				},
				Chain: &dynamic.Chain{
					Middlewares: []string{"foo"},
				},
				IPWhiteList: &dynamic.IPWhiteList{
					SourceRange: []string{"foo"},
					IPStrategy: &dynamic.IPStrategy{
						Depth:       42,
						ExcludedIPs: []string{"127.0.0.1"},
					},
				},
				Headers: &dynamic.Headers{
					CustomRequestHeaders:              map[string]string{"foo": "bar"},
					CustomResponseHeaders:             map[string]string{"foo": "bar"},
					AccessControlAllowCredentials:     true,
					AccessControlAllowHeaders:         []string{"foo"},
					AccessControlAllowMethods:         []string{"foo"},
					AccessControlAllowOriginList:      []string{"foo"},
					AccessControlAllowOriginListRegex: []string{"foo"},
					AccessControlExposeHeaders:        []string{"foo"},
					AccessControlMaxAge:               42,
					AddVaryHeader:                     true,
					AllowedHosts:                      []string{"foo"},
					HostsProxyHeaders:                 []string{"foo"},
					SSLRedirect:                       true,
					SSLTemporaryRedirect:              true,
					SSLHost:                           "foo",
					SSLProxyHeaders:                   map[string]string{"foo": "bar"},
					SSLForceHost:                      true,
					STSSeconds:                        42,
					STSIncludeSubdomains:              true,
					STSPreload:                        true,
					ForceSTSHeader:                    true,
					FrameDeny:                         true,
					CustomFrameOptionsValue:           "foo",
					ContentTypeNosniff:                true,
					BrowserXSSFilter:                  true,
					CustomBrowserXSSValue:             "foo",
					ContentSecurityPolicy:             "foo",
					PublicKey:                         "foo",
					ReferrerPolicy:                    "foo",
					FeaturePolicy:                     "foo",
					PermissionsPolicy:                 "foo",
					IsDevelopment:                     true,
				},
				Errors: &dynamic.ErrorPage{
					Status:  []string{"foo"},
					Service: "foo",
					Query:   "foo",
				},
				RateLimit: &dynamic.RateLimit{
					Average: 42,
					Period:  42,
					Burst:   42,
					SourceCriterion: &dynamic.SourceCriterion{
						IPStrategy: &dynamic.IPStrategy{
							Depth:       42,
							ExcludedIPs: []string{"foo"},
						},
						RequestHeaderName: "foo",
						RequestHost:       true,
					},
				},
				RedirectRegex: &dynamic.RedirectRegex{
					Regex:       "foo",
					Replacement: "foo",
					Permanent:   true,
				},
				RedirectScheme: &dynamic.RedirectScheme{
					Scheme:    "foo",
					Port:      "foo",
					Permanent: true,
				},
				BasicAuth: &dynamic.BasicAuth{
					Users:        []string{"foo"},
					UsersFile:    "foo",
					Realm:        "foo",
					RemoveHeader: true,
					HeaderField:  "foo",
				},
				DigestAuth: &dynamic.DigestAuth{
					Users:        []string{"foo"},
					UsersFile:    "foo",
					RemoveHeader: true,
					Realm:        "foo",
					HeaderField:  "foo",
				},
				ForwardAuth: &dynamic.ForwardAuth{
					Address: "127.0.0.1",
					TLS: &types.ClientTLS{
						CA:                 "ca.pem",
						CAOptional:         true,
						Cert:               "cert.pem",
						Key:                "cert.pem",
						InsecureSkipVerify: true,
					},
					TrustForwardHeader:       true,
					AuthResponseHeaders:      []string{"foo"},
					AuthResponseHeadersRegex: "foo",
					AuthRequestHeaders:       []string{"foo"},
				},
				InFlightReq: &dynamic.InFlightReq{
					Amount: 42,
					SourceCriterion: &dynamic.SourceCriterion{
						IPStrategy: &dynamic.IPStrategy{
							Depth:       42,
							ExcludedIPs: []string{"foo"},
						},
						RequestHeaderName: "foo",
						RequestHost:       true,
					},
				},
				Buffering: &dynamic.Buffering{
					MaxRequestBodyBytes:  42,
					MemRequestBodyBytes:  42,
					MaxResponseBodyBytes: 42,
					MemResponseBodyBytes: 42,
					RetryExpression:      "foo",
				},
				CircuitBreaker: &dynamic.CircuitBreaker{
					Expression: "foo",
				},
				Compress: &dynamic.Compress{
					ExcludedContentTypes: []string{"foo"},
				},
				PassTLSClientCert: &dynamic.PassTLSClientCert{
					PEM: true,
					Info: &dynamic.TLSClientCertificateInfo{
						NotAfter:  true,
						NotBefore: true,
						Sans:      true,
						Subject: &dynamic.TLSClientCertificateDNInfo{
							Country:         true,
							Province:        true,
							Locality:        true,
							Organization:    true,
							CommonName:      true,
							SerialNumber:    true,
							DomainComponent: true,
						},
						Issuer: &dynamic.TLSClientCertificateDNInfo{
							Country:         true,
							Province:        true,
							Locality:        true,
							Organization:    true,
							CommonName:      true,
							SerialNumber:    true,
							DomainComponent: true,
						},
						SerialNumber: true,
					},
				},
				Retry: &dynamic.Retry{
					Attempts:        42,
					InitialInterval: 42,
				},
				ContentType: &dynamic.ContentType{
					AutoDetect: true,
				},
				Plugin: map[string]dynamic.PluginConf{
					"foo": {
						"answer": struct{ Answer int }{
							Answer: 42,
						},
					},
				},
			},
		},
	}
	config.TCP = &dynamic.TCPConfiguration{
		Routers: map[string]*dynamic.TCPRouter{
			"foo": {
				EntryPoints: []string{"foo"},
				Service:     "foo",
				Rule:        "foo",
				TLS: &dynamic.RouterTCPTLSConfig{
					Passthrough:  true,
					Options:      "foo",
					CertResolver: "foo",
					Domains: []types.Domain{
						{
							Main: "foo",
							SANs: []string{"foo"},
						},
					},
				},
			},
		},
		Services: map[string]*dynamic.TCPService{
			"foo": {
				LoadBalancer: &dynamic.TCPServersLoadBalancer{
					TerminationDelay: intPtr(42),
					ProxyProtocol: &dynamic.ProxyProtocol{
						Version: 42,
					},
					Servers: []dynamic.TCPServer{
						{
							Address: "127.0.0.1:8080",
						},
					},
				},
			},
			"bar": {
				Weighted: &dynamic.TCPWeightedRoundRobin{
					Services: []dynamic.TCPWRRService{
						{
							Name:   "foo",
							Weight: intPtr(42),
						},
					},
				},
			},
		},
	}
	config.UDP = &dynamic.UDPConfiguration{
		Routers: map[string]*dynamic.UDPRouter{
			"foo": {
				EntryPoints: []string{"foo"},
				Service:     "foo",
			},
		},
		Services: map[string]*dynamic.UDPService{
			"foo": {
				LoadBalancer: &dynamic.UDPServersLoadBalancer{
					Servers: []dynamic.UDPServer{
						{
							Address: "127.0.0.1:8080",
						},
					},
				},
			},
			"bar": {
				Weighted: &dynamic.UDPWeightedRoundRobin{
					Services: []dynamic.UDPWRRService{
						{
							Name:   "foo",
							Weight: intPtr(42),
						},
					},
				},
			},
		},
	}
	config.TLS = &dynamic.TLSConfiguration{
		Options: map[string]traefiktls.Options{
			"foo": {
				MinVersion:       "foo",
				MaxVersion:       "foo",
				CipherSuites:     []string{"foo"},
				CurvePreferences: []string{"foo"},
				ClientAuth: traefiktls.ClientAuth{
					CAFiles:        []traefiktls.FileOrContent{"ca.pem"},
					ClientAuthType: "RequireAndVerifyClientCert",
				},
				SniStrict:                true,
				PreferServerCipherSuites: true,
			},
		},
		Certificates: []*traefiktls.CertAndStores{
			{
				Certificate: traefiktls.Certificate{
					CertFile: "cert.pem",
					KeyFile:  "key.pem",
				},
				Stores: []string{"foo"},
			},
		},
		Stores: map[string]traefiktls.Store{
			"foo": {
				DefaultCertificate: &traefiktls.Certificate{
					CertFile: "cert.pem",
					KeyFile:  "key.pem",
				},
			},
		},
	}

	expectedConfiguration, err := os.ReadFile("./testdata/anonymized-dynamic-config.json")
	require.NoError(t, err)

	cleanJSON, err := Do(config, true)
	require.NoError(t, err)

	if *updateExpected {
		require.NoError(t, os.WriteFile("testdata/anonymized-dynamic-config.json", []byte(cleanJSON), 0o666))
	}

	expected := strings.TrimSuffix(string(expectedConfiguration), "\n")
	assert.Equal(t, expected, cleanJSON)
}

func boolPtr(value bool) *bool {
	return &value
}

func intPtr(value int) *int {
	return &value
}

func int64Ptr(value int64) *int64 {
	return &value
}
