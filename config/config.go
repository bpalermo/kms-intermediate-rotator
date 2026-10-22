// Package config loads and validates the rotator's configuration: inline
// JSON from ROTATOR_CONFIG, or the value of the SSM parameter named by
// ROTATOR_CONFIG_PARAMETER. Exactly one of the two must be set.
//
// The configuration is the protobuf JSON of configv1.Config
// (config/v1/config.proto). Parse decodes it strictly (an unknown field is
// an error), checks it against the schema's protovalidate rules, then checks
// what the schema cannot: the root certificate, and each secret's path
// length against it.
package config

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"google.golang.org/protobuf/encoding/protojson"

	configv1 "github.com/bpalermo/kms-intermediate-rotator/config/v1"
	"github.com/bpalermo/kms-intermediate-rotator/intermediate"
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

// Config is the rotator's configuration, validated, with the defaults filled
// in.
type Config struct {
	// KMSKeyID is the root's KMS key: an ID, ARN, alias name or alias ARN.
	KMSKeyID string
	// SigningAlgorithm is a KMS signing algorithm; empty derives it from
	// the key spec.
	SigningAlgorithm string
	// Root is the root certificate, parsed.
	Root *x509.Certificate
	// Secrets is what to issue for each secret, by the configured ARN.
	Secrets map[string]*Secret
	// Raw is the configuration as decoded.
	Raw *configv1.Config
}

// Secret is the configuration of the intermediate kept in one secret.
type Secret struct {
	// Profile is what the rotator issues, with the defaults filled in.
	Profile intermediate.Profile
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
// Unknown fields are errors, so that a misspelt setting is not ignored. No
// error it returns contains the root certificate.
func Parse(data []byte) (*Config, error) {
	raw := &configv1.Config{}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(data, raw); err != nil {
		// protojson's message names the field and the JSON token it could not
		// take, and quotes no more of the input than that token; a string
		// token is quoted whole, though, and could be a certificate.
		if strings.Contains(err.Error(), "-----BEGIN") {
			return nil, errors.New("config: not a configuration document: a certificate where another value belongs")
		}
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := validate(raw); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c, err := build(raw)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return c, nil
}

var (
	validatorOnce sync.Once
	validator     protovalidate.Validator
	validatorErr  error
)

// validate checks raw against the rules of config.proto. The error lists
// each violation by field path, rule ID and the rule's message, none of
// which holds a field's value.
func validate(raw *configv1.Config) error {
	validatorOnce.Do(func() { validator, validatorErr = protovalidate.New() })
	if validatorErr != nil {
		return fmt.Errorf("building the validator: %w", validatorErr)
	}
	err := validator.Validate(raw)
	if err == nil {
		return nil
	}
	var verr *protovalidate.ValidationError
	if !errors.As(err, &verr) {
		// A rule that could not be evaluated, such as a duration too long
		// to represent.
		return fmt.Errorf("invalid: %w", err)
	}
	reasons := make([]string, 0, len(verr.Violations))
	for _, v := range verr.Violations {
		reasons = append(reasons, fmt.Sprintf("%s: %s [%s]",
			protovalidate.FieldPathString(v.Proto.GetField()), v.Proto.GetMessage(), v.Proto.GetRuleId()))
	}
	return fmt.Errorf("invalid: %s", strings.Join(reasons, "; "))
}

// build makes the Config of a configuration that satisfies the schema.
func build(raw *configv1.Config) (*Config, error) {
	root, err := parseRoot(raw.GetRootCertificate())
	if err != nil {
		return nil, fmt.Errorf("root_certificate: %w", err)
	}
	if err := checkRoot(root); err != nil {
		return nil, fmt.Errorf("root_certificate: %w", err)
	}
	c := &Config{
		KMSKeyID:         raw.GetKmsKeyId(),
		SigningAlgorithm: raw.GetSigningAlgorithm(),
		Root:             root,
		Secrets:          make(map[string]*Secret, len(raw.GetSecrets())),
		Raw:              raw,
	}
	for arn, s := range raw.GetSecrets() {
		p, err := profile(s, root)
		if err != nil {
			return nil, fmt.Errorf("secrets[%s]: %w", arn, err)
		}
		c.Secrets[arn] = &Secret{Profile: p}
	}
	return c, nil
}

// parseRoot parses exactly one PEM certificate, and nothing else: no other
// block, no text after it (the schema refuses text before it).
func parseRoot(s string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(s))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("more than one PEM block, or text after it: want exactly one certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		// The parser's message describes the encoding, not the contents.
		return nil, fmt.Errorf("not an X.509 certificate: %w", err)
	}
	return root, nil
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

// profile is the intermediate.Profile of s, with the defaults, checked
// against root. s satisfies the schema.
func profile(s *configv1.SecretProfile, root *x509.Certificate) (intermediate.Profile, error) {
	p := intermediate.Profile{
		Subject:         subject(s.GetSubject()),
		KeyType:         intermediate.KeyType(s.GetKeyType()),
		Validity:        DefaultValidity,
		MaxPathLen:      DefaultMaxPathLen,
		NameConstraints: nameConstraints(s.GetNameConstraints()),
	}
	if p.KeyType == "" {
		p.KeyType = intermediate.DefaultKeyType
	}
	var err error
	if v := s.GetValidity(); v != "" {
		if p.Validity, err = time.ParseDuration(v); err != nil {
			return p, fmt.Errorf("validity: %w", err)
		}
	}
	p.MinRemaining = p.Validity / 2
	if v := s.GetMinRemaining(); v != "" {
		if p.MinRemaining, err = time.ParseDuration(v); err != nil {
			return p, fmt.Errorf("min_remaining: %w", err)
		}
	}
	// The schema compares the two when both are set; this also covers the
	// default validity.
	if p.MinRemaining > p.Validity {
		return p, fmt.Errorf("min_remaining %s is longer than validity %s", p.MinRemaining, p.Validity)
	}
	if s.MaxPathLen != nil {
		p.MaxPathLen = int(s.GetMaxPathLen())
	}
	// The intermediate is one CA below the root; its own path length must
	// fit in what is left.
	if n := rootPathLen(root); n >= 0 && p.MaxPathLen > n-1 {
		return p, fmt.Errorf("max_path_len %d does not fit under the root's path length %d (at most %d)", p.MaxPathLen, n, n-1)
	}
	return p, nil
}

func subject(s *configv1.Subject) pkix.Name {
	return pkix.Name{
		CommonName:         s.GetCommonName(),
		Organization:       s.GetOrganization(),
		OrganizationalUnit: s.GetOrganizationalUnit(),
		Country:            s.GetCountry(),
		Province:           s.GetProvince(),
		Locality:           s.GetLocality(),
	}
}

func nameConstraints(n *configv1.NameConstraints) intermediate.NameConstraints {
	return intermediate.NameConstraints{
		PermittedURIDomains: n.GetPermittedUriDomains(),
		ExcludedURIDomains:  n.GetExcludedUriDomains(),
		PermittedDNSDomains: n.GetPermittedDnsDomains(),
		ExcludedDNSDomains:  n.GetExcludedDnsDomains(),
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
