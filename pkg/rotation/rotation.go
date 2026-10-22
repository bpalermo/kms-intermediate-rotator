// Package rotation implements the four steps of an AWS Secrets Manager
// rotation for a secret holding an intermediate CA in the secret format v1:
// createSecret issues a new intermediate signed by the KMS root key,
// setSecret does nothing, testSecret checks the new version, and
// finishSecret makes it AWSCURRENT.
package rotation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/bpalermo/kms-intermediate-rotator/pkg/config"
	"github.com/bpalermo/kms-intermediate-rotator/pkg/intermediate"
	"github.com/bpalermo/kms-intermediate-rotator/pkg/kmssigner"
	"github.com/bpalermo/kms-intermediate-rotator/pkg/secretformat"
)

// The rotation steps.
const (
	StepCreate = "createSecret"
	StepSet    = "setSecret"
	StepTest   = "testSecret"
	StepFinish = "finishSecret"
)

// The staging labels.
const (
	StageCurrent = "AWSCURRENT"
	StagePending = "AWSPENDING"
)

// Event is the input Secrets Manager invokes a rotation function with.
type Event struct {
	SecretID           string `json:"SecretId"`
	ClientRequestToken string `json:"ClientRequestToken"`
	Step               string `json:"Step"`
	// RotationToken identifies the rotation when the function rotates
	// through an assumed role or across accounts; when set it is passed on
	// to PutSecretValue. It is sensitive and never logged.
	RotationToken string `json:"RotationToken,omitempty"`
}

// SecretsManager is the part of the Secrets Manager API the rotation uses.
type SecretsManager interface {
	DescribeSecret(ctx context.Context, in *secretsmanager.DescribeSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(ctx context.Context, in *secretsmanager.PutSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	UpdateSecretVersionStage(ctx context.Context, in *secretsmanager.UpdateSecretVersionStageInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretVersionStageOutput, error)
}

// Rotator runs the rotation steps.
type Rotator struct {
	SecretsManager SecretsManager
	Config         *config.Config
	// Signer is the root's KMS key.
	Signer *kmssigner.Signer
	Logger *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// target is the secret an event is for.
type target struct {
	arn           string
	token         string
	rotationToken string
	secret        *config.Secret
	profile       intermediate.Profile
	desc          *secretsmanager.DescribeSecretOutput
}

// Handle runs one rotation step. It applies the preconditions the AWS
// rotation templates apply to every step: the secret is configured here
// and has rotation enabled, the token is a version of it, a token that is
// already AWSCURRENT is a success with nothing to do, and a token that is
// not AWSPENDING is an error. The one exception: a testSecret for a token
// that is not a version is a configuration test, and succeeds.
func (r *Rotator) Handle(ctx context.Context, ev Event) error {
	if ev.SecretID == "" || ev.ClientRequestToken == "" {
		return errors.New("the event needs a SecretId and a ClientRequestToken")
	}
	if !slices.Contains([]string{StepCreate, StepSet, StepTest, StepFinish}, ev.Step) {
		return fmt.Errorf("unknown step %q", ev.Step)
	}
	if config.IsARN(ev.SecretID) {
		if _, _, ok := r.Config.Lookup(ev.SecretID); !ok {
			return fmt.Errorf("secret %s is not configured for rotation here", ev.SecretID)
		}
	}
	t, err := r.target(ctx, ev)
	if err != nil {
		return err
	}
	log := r.logger().With("secret_arn", t.arn, "step", ev.Step, "token", t.token)
	stages, isVersion := t.desc.VersionIdsToStages[t.token]
	if !isVersion {
		if ev.Step == StepTest {
			return r.configurationTest(log, "the token is not a version of the secret")
		}
		return fmt.Errorf("secret %s has no version %s", t.arn, t.token)
	}
	if slices.Contains(stages, StageCurrent) {
		log.Info("the version is already AWSCURRENT; nothing to do")
		return nil
	}
	if !slices.Contains(stages, StagePending) {
		return fmt.Errorf("version %s of secret %s is not AWSPENDING", t.token, t.arn)
	}
	switch ev.Step {
	case StepCreate:
		return r.createSecret(ctx, t, log)
	case StepTest:
		return r.testSecret(ctx, t, log)
	case StepFinish:
		return r.finishSecret(ctx, t, log)
	}
	return nil // setSecret: there is no service to configure.
}

func (r *Rotator) target(ctx context.Context, ev Event) (*target, error) {
	desc, err := r.SecretsManager.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(ev.SecretID)})
	if err != nil {
		return nil, fmt.Errorf("describe secret %s: %w", ev.SecretID, err)
	}
	arn := aws.ToString(desc.ARN)
	_, sc, ok := r.Config.Lookup(arn)
	if !ok {
		return nil, fmt.Errorf("secret %s is not configured for rotation here", arn)
	}
	if !aws.ToBool(desc.RotationEnabled) {
		return nil, fmt.Errorf("secret %s does not have rotation enabled", arn)
	}
	return &target{
		arn: arn, token: ev.ClientRequestToken, rotationToken: ev.RotationToken,
		secret: sc, profile: sc.Profile(), desc: desc,
	}, nil
}

// createSecret issues a new intermediate and stores it as the AWSPENDING
// version of the token, unless that version already has a value (a retry,
// or a concurrent invocation that got there first).
func (r *Rotator) createSecret(ctx context.Context, t *target, log *slog.Logger) error {
	if _, err := r.pending(ctx, t); err == nil {
		log.Info("the pending version already has a value; not issuing again")
		return nil
	} else if !isNotFound(err) {
		return fmt.Errorf("read the pending version: %w", err)
	}

	cert, value, err := r.issue(ctx, t)
	if err != nil {
		return err
	}
	in := &secretsmanager.PutSecretValueInput{
		SecretId:           aws.String(t.arn),
		ClientRequestToken: aws.String(t.token),
		SecretString:       aws.String(value),
		VersionStages:      []string{StagePending},
	}
	if t.rotationToken != "" {
		in.RotationToken = aws.String(t.rotationToken)
	}
	if _, err := r.SecretsManager.PutSecretValue(ctx, in); err != nil {
		var exists *types.ResourceExistsException
		if errors.As(err, &exists) {
			if _, err := r.pending(ctx, t); err == nil {
				log.Info("another invocation stored the pending version first; discarding this one")
				return nil
			}
		}
		return fmt.Errorf("put the pending version: %w", err)
	}
	log.Info("issued intermediate certificate",
		"serial", cert.SerialNumber.Text(16),
		"not_after", cert.NotAfter.UTC().Format(time.RFC3339),
		"public_key_sha256", PublicKeySHA256(cert),
	)
	return nil
}

// issue makes a new key and intermediate, checks them, and returns the
// certificate and the v1 secret value.
func (r *Rotator) issue(ctx context.Context, t *target) (*x509.Certificate, string, error) {
	key, err := intermediate.GenerateKey(t.profile.KeyType)
	if err != nil {
		return nil, "", err
	}
	signer := r.Signer.WithContext(ctx)
	root := r.Config.Root
	now := r.now()
	cert, err := intermediate.Issue(t.profile, key.Public(), root, signer, signer.SignatureAlgorithm(), now)
	if err != nil {
		return nil, "", err
	}
	b := &secretformat.Bundle{Cert: cert, Key: key, Root: root}
	if err := b.Verify(now); err != nil {
		return nil, "", fmt.Errorf("the new intermediate: %w", err)
	}
	if err := intermediate.VerifyDepth(cert, key, root, now); err != nil {
		return nil, "", fmt.Errorf("the new intermediate: %w", err)
	}
	value, err := secretformat.Encode(b)
	if err != nil {
		return nil, "", err
	}
	return cert, value, nil
}

// testSecret checks the AWSPENDING version: it is format v1, its key
// matches its cert, the cert verifies to the configured root (also through
// a chain as deep as its path length allows), it is what createSecret
// issues, and it has enough validity left.
//
// A token whose AWSPENDING version has no value is a configuration test
// (rotation set up without rotating immediately runs testSecret alone) and
// succeeds: the configuration and the KMS key were checked at start.
func (r *Rotator) testSecret(ctx context.Context, t *target, log *slog.Logger) error {
	out, err := r.pending(ctx, t)
	if isNotFound(err) {
		return r.configurationTest(log, "the pending version has no value")
	}
	if err != nil {
		return fmt.Errorf("read the pending version: %w", err)
	}
	if err := r.validatePending(aws.ToString(out.SecretString), t); err != nil {
		// A version cannot change: retrying will not help.
		return fmt.Errorf("pending version %s of %s: %w; it can never pass, so remove AWSPENDING from it "+
			"(aws secretsmanager update-secret-version-stage --secret-id %s --version-stage AWSPENDING --remove-from-version-id %s) "+
			"and rotate again", t.token, t.arn, err, t.arn, t.token)
	}
	log.Info("the pending version is valid")
	return nil
}

func (r *Rotator) validatePending(value string, t *target) error {
	now := r.now()
	b, err := secretformat.Decode(value, now)
	if err != nil {
		return err
	}
	root := r.Config.Root
	if !b.Root.Equal(root) {
		return errors.New("its root is not the configured root")
	}
	if err := intermediate.Check(b.Cert, t.profile); err != nil {
		return err
	}
	if err := intermediate.CheckLifetime(b.Cert, t.profile, root, now); err != nil {
		return err
	}
	return intermediate.VerifyDepth(b.Cert, b.Key, root, now)
}

// configurationTest is testSecret without a pending value to test.
func (r *Rotator) configurationTest(log *slog.Logger, why string) error {
	log.Info("configuration test: nothing to validate, the configuration and the KMS key were checked at start", "reason", why)
	return nil
}

// finishSecret moves AWSCURRENT to the token, off the version that has it.
// Secrets Manager then moves AWSPREVIOUS to that version.
func (r *Rotator) finishSecret(ctx context.Context, t *target, log *slog.Logger) error {
	in := &secretsmanager.UpdateSecretVersionStageInput{
		SecretId:        aws.String(t.arn),
		VersionStage:    aws.String(StageCurrent),
		MoveToVersionId: aws.String(t.token),
	}
	for id, stages := range t.desc.VersionIdsToStages {
		if slices.Contains(stages, StageCurrent) {
			in.RemoveFromVersionId = aws.String(id)
			break
		}
	}
	if _, err := r.SecretsManager.UpdateSecretVersionStage(ctx, in); err != nil {
		return fmt.Errorf("move AWSCURRENT to %s: %w", t.token, err)
	}
	log.Info("moved AWSCURRENT", "previous_version", aws.ToString(in.RemoveFromVersionId))
	return nil
}

func (r *Rotator) pending(ctx context.Context, t *target) (*secretsmanager.GetSecretValueOutput, error) {
	return r.SecretsManager.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(t.arn),
		VersionId:    aws.String(t.token),
		VersionStage: aws.String(StagePending),
	})
}

func (r *Rotator) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Rotator) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.Default()
}

func isNotFound(err error) bool {
	var nf *types.ResourceNotFoundException
	return errors.As(err, &nf)
}

// PublicKeySHA256 is the hex SHA-256 of cert's SubjectPublicKeyInfo DER,
// the public key's fingerprint as logged.
func PublicKeySHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
