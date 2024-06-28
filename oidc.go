package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type openIDHandler struct {
	log     *slog.Logger
	service *openIDService
}

func newOpenIDHandler(log *slog.Logger, service *openIDService) *openIDHandler {
	return &openIDHandler{
		log:     log,
		service: service,
	}
}

func (h openIDHandler) printConfig(w http.ResponseWriter, _ *http.Request) {
	config, err := h.service.getConfig()
	if err != nil {
		h.log.Error("Failed to get OIDC config", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	jsonBytes, err := json.Marshal(config)
	if err != nil {
		h.log.Error("Failed to marshal OIDC config JSON", slog.Any("error", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Write(jsonBytes)
}

type openIDService struct {
	log          *slog.Logger
	configURL    string
	cachedConfig *openIDConfig
	lastFetch    time.Time
}

func newOpenIDService(log *slog.Logger, configURL string) *openIDService {
	return &openIDService{
		log:       log,
		configURL: configURL,
	}
}

func (s openIDService) getConfig() (*openIDConfig, error) {
	if time.Now().Sub(s.lastFetch) < 10*time.Minute && s.cachedConfig != nil {
		return s.cachedConfig, nil
	}

	resp, err := http.Get(s.configURL)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 reponse code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var config openIDConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	s.cachedConfig = &config
	s.lastFetch = time.Now()
	return &config, nil
}

type openIDConfig struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint,omitempty"`
	JwksUri                                    string   `json:"jwks_uri"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                        []string `json:"grant_types_supported,omitempty"`
	AcrValuesSupported                         []string `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	IdTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IdTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported       []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported       []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported                     []string `json:"display_values_supported,omitempty"`
	ClaimTypesSupported                        []string `json:"claim_types_supported,omitempty"`
	ClaimsSupported                            []string `json:"claims_supported,omitempty"`
	ServiceDocumentation                       string   `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported                     []string `json:"claims_locales_supported,omitempty"`
	UILocalesSupported                         []string `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported,omitempty"`
	RequestUriParameterSupported               bool     `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestUriRegistration              bool     `json:"require_request_uri_registration,omitempty"`
	OpPolicyUri                                string   `json:"op_policy_uri,omitempty"`
	OpTosUri                                   string   `json:"op_tos_uri,omitempty"`
}
