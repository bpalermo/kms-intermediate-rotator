// Package config loads and validates the rotator's configuration: inline
// JSON from ROTATOR_CONFIG, or the value of the SSM parameter named by
// ROTATOR_CONFIG_PARAMETER. Exactly one of the two must be set.
package config

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/bpalermo/kms-intermediate-rotator/pkg/intermediate"
	"github.com/bpalermo/kms-intermediate-rotator/pkg/secretformat"
)

// The environment variables the configuration comes from.
const (
	EnvConfig          = "ROTATOR_CONFIG"
	EnvConfigParameter = "ROTATOR_CONFIG_PARAMETER"
)

// Defaults for the per-secret settings.
const (
	DefaultValidity   = 2160 * time.Hour
	DefaultMaxPathLen = 1
)

// ParameterGetter is the part of the SSM API Load uses.
type ParameterGetter interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// Config is the rotator's configuration.
type Config struct {
	// KMSKeyID is the root's KMS key: an ID, ARN, alias name or alias ARN.
	KMSKeyID string `json:"kms_key_id"`
	// RootCertificate is the root's certificate, PEM: exactly one.
	RootCertificate string `json:"root_certificate"`
	// SigningAlgorithm is a KMS signing algorithm; empty derives it from
	// the key spec.
	SigningAlgorithm string `json:"signing_algorithm"`
	// Secrets is what to issue for each secret, by secret ARN.
	Secrets map[string]*Secret `json:"secrets"`

	// Root is RootCertificate, parsed.
	Root *x509.Certificate `json:"-"`
}

// Secret is the configuration of the intermediate kept in one secret.
type Secret struct {
	Subject         Subject         `json:"subject"`
	KeyType         string          `json:"key_type"`
	Validity        Duration        `json:"validity"`
	MaxPathLen      *int            `json:"max_path_len"`
	NameConstraints NameConstraints `json:"name_constraints"`
	// MinRemaining is the least validity a pending intermediate must have
	// left for testSecret to promote it; default half of Validity.
	MinRemaining Duration `json:"min_remaining"`
}

// Subject is the intermediate's subject name.
type Subject struct {
	CommonName         string   `json:"common_name"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Country            []string `json:"country"`
	Province           []string `json:"province"`
	Locality           []string `json:"locality"`
}

// NameConstraints are the intermediate's name constraints.
type NameConstraints struct {
	PermittedURIDomains []string `json:"permitted_uri_domains"`
	ExcludedURIDomains  []string `json:"excluded_uri_domains"`
	PermittedDNSDomains []string `json:"permitted_dns_domains"`
	ExcludedDNSDomains  []string `json:"excluded_dns_domains"`
}

// Duration is a time.Duration written as a Go duration string ("2160h").
type Duration time.Duration

// UnmarshalJSON parses a duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string such as \"2160h\": %w", err)
	}
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	if v <= 0 {
		return fmt.Errorf("duration %q is not positive", s)
	}
	*d = Duration(v)
	return nil
}

// Load reads the configuration from the environment (getenv) and, for the
// parameter form, from SSM, once.
func Load(ctx context.Context, getenv func(string) string, params ParameterGetter) (*Config, error) {
	inline, name := getenv(EnvConfig), getenv(EnvConfigParameter)
	switch {
	case inline != "" && name != "":
		return nil, fmt.Errorf("both %s and %s are set; set exactly one", EnvConfig, EnvConfigParameter)
	case inline != "":
		return Parse([]byte(inline))
	case name != "":
		if params == nil {
			return nil, errors.New("no SSM client for " + EnvConfigParameter)
		}
		out, err := params.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(name), WithDecryption: aws.Bool(true)})
		if err != nil {
			return nil, fmt.Errorf("read SSM parameter %s: %w", name, err)
		}
		if out.Parameter == nil || aws.ToString(out.Parameter.Value) == "" {
			return nil, fmt.Errorf("SSM parameter %s is empty", name)
		}
		return Parse([]byte(aws.ToString(out.Parameter.Value)))
	}
	return nil, fmt.Errorf("neither %s nor %s is set; set exactly one", EnvConfig, EnvConfigParameter)
}

// Parse decodes and validates a configuration and fills in the defaults.
// Unknown fields are errors, so that a misspelt setting is not ignored.
func Parse(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if dec.More() {
		return nil, errors.New("config: trailing data after the JSON object")
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	if strings.TrimSpace(c.KMSKeyID) == "" {
		return errors.New("kms_key_id is required")
	}
	root, err := secretformat.ParseOneCertificate(c.RootCertificate)
	if err != nil {
		return fmt.Errorf("root_certificate: %w", err)
	}
	if err := checkRoot(root); err != nil {
		return fmt.Errorf("root_certificate: %w", err)
	}
	c.Root = root
	if len(c.Secrets) == 0 {
		return errors.New("secrets: at least one secret is required")
	}
	for arn, s := range c.Secrets {
		if !isSecretARN(arn) {
			return fmt.Errorf("secrets: %q is not a Secrets Manager secret ARN", arn)
		}
		if s == nil {
			return fmt.Errorf("secrets[%s]: empty", arn)
		}
		if err := s.validate(root); err != nil {
			return fmt.Errorf("secrets[%s]: %w", arn, err)
		}
	}
	return nil
}

// checkRoot refuses a root that cannot issue the intermediate.
func checkRoot(root *x509.Certificate) error {
	if !root.BasicConstraintsValid || !root.IsCA {
		return errors.New("not a CA certificate")
	}
	if root.KeyUsage != 0 && root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("its key usage does not include keyCertSign")
	}
	if root.MaxPathLenZero || root.MaxPathLen == 0 {
		return errors.New("its path length is 0: it can issue no intermediate CA")
	}
	return nil
}

// rootPathLen is the path length constraint of root, or -1 when it has none.
func rootPathLen(root *x509.Certificate) int {
	if root.MaxPathLen > 0 {
		return root.MaxPathLen
	}
	return -1
}

func (s *Secret) validate(root *x509.Certificate) error {
	if strings.TrimSpace(s.Subject.CommonName) == "" {
		return errors.New("subject.common_name is required")
	}
	if s.KeyType == "" {
		s.KeyType = string(intermediate.DefaultKeyType)
	}
	if !intermediate.KeyType(s.KeyType).Valid() {
		return fmt.Errorf("unknown key_type %q (want ec-p256, ec-p384, rsa-2048 or rsa-4096)", s.KeyType)
	}
	if s.Validity == 0 {
		s.Validity = Duration(DefaultValidity)
	}
	if s.MaxPathLen == nil {
		n := DefaultMaxPathLen
		s.MaxPathLen = &n
	}
	if *s.MaxPathLen < 0 {
		return fmt.Errorf("max_path_len %d is negative", *s.MaxPathLen)
	}
	// The intermediate is one CA below the root; its own path length must
	// fit in what is left.
	if n := rootPathLen(root); n >= 0 && *s.MaxPathLen > n-1 {
		return fmt.Errorf("max_path_len %d does not fit under the root's path length %d (at most %d)", *s.MaxPathLen, n, n-1)
	}
	if s.MinRemaining == 0 {
		s.MinRemaining = s.Validity / 2
	}
	if s.MinRemaining > s.Validity {
		return fmt.Errorf("min_remaining %s is longer than validity %s", time.Duration(s.MinRemaining), time.Duration(s.Validity))
	}
	return s.NameConstraints.validate()
}

func (n NameConstraints) validate() error {
	lists := map[string][]string{
		"permitted_uri_domains": n.PermittedURIDomains,
		"excluded_uri_domains":  n.ExcludedURIDomains,
		"permitted_dns_domains": n.PermittedDNSDomains,
		"excluded_dns_domains":  n.ExcludedDNSDomains,
	}
	for field, list := range lists {
		for _, d := range list {
			if d == "" || strings.ContainsAny(d, " \t/:@*") {
				return fmt.Errorf("name_constraints.%s: %q is not a domain", field, d)
			}
		}
	}
	return nil
}

// Profile is the intermediate.Profile of s. s must have been validated.
func (s *Secret) Profile() intermediate.Profile {
	return intermediate.Profile{
		Subject: pkix.Name{
			CommonName:         s.Subject.CommonName,
			Organization:       s.Subject.Organization,
			OrganizationalUnit: s.Subject.OrganizationalUnit,
			Country:            s.Subject.Country,
			Province:           s.Subject.Province,
			Locality:           s.Subject.Locality,
		},
		KeyType:      intermediate.KeyType(s.KeyType),
		Validity:     time.Duration(s.Validity),
		MaxPathLen:   *s.MaxPathLen,
		MinRemaining: time.Duration(s.MinRemaining),
		NameConstraints: intermediate.NameConstraints{
			PermittedURIDomains: s.NameConstraints.PermittedURIDomains,
			ExcludedURIDomains:  s.NameConstraints.ExcludedURIDomains,
			PermittedDNSDomains: s.NameConstraints.PermittedDNSDomains,
			ExcludedDNSDomains:  s.NameConstraints.ExcludedDNSDomains,
		},
	}
}

// Lookup returns the configuration for the secret with ARN arn, and the
// configured key it was found under. A configured key matches when it is
// arn, or arn without the six random characters (and their dash) Secrets
// Manager appends to a secret's name in its ARN.
func (c *Config) Lookup(arn string) (string, *Secret, bool) {
	if s, ok := c.Secrets[arn]; ok {
		return arn, s, true
	}
	if partial, ok := strings.CutSuffix(arn, arnSuffix(arn)); ok && partial != arn {
		if s, ok := c.Secrets[partial]; ok {
			return partial, s, true
		}
	}
	return "", nil, false
}

// arnSuffix is the "-XXXXXX" Secrets Manager appends to a secret ARN, or "".
func arnSuffix(arn string) string {
	i := strings.LastIndexByte(arn, '-')
	if i < 0 || len(arn)-i != 7 || !isSecretARN(arn) {
		return ""
	}
	return arn[i:]
}

// isSecretARN reports whether s has the shape
// arn:PARTITION:secretsmanager:REGION:ACCOUNT:secret:NAME.
func isSecretARN(s string) bool {
	parts := strings.SplitN(s, ":", 7)
	return len(parts) == 7 && parts[0] == "arn" && parts[1] != "" &&
		parts[2] == "secretsmanager" && parts[3] != "" && parts[4] != "" &&
		parts[5] == "secret" && parts[6] != ""
}

// IsARN reports whether a SecretId is an ARN rather than a name.
func IsARN(secretID string) bool { return strings.HasPrefix(secretID, "arn:") }
