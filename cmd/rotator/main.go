// Command rotator is the AWS Lambda that rotates, for AWS Secrets Manager, an
// intermediate CA signed by an AWS KMS key. It runs on the provided.al2023
// custom runtime, as the executable named bootstrap.
//
// At start (once per cold start) it loads its configuration
// (ROTATOR_CONFIG or ROTATOR_CONFIG_PARAMETER) and checks that the KMS key's
// public key is the configured root certificate's; it refuses to run if
// either fails. Then it serves rotation events (pkg/rotation).
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/bpalermo/kms-intermediate-rotator/internal/version"
	"github.com/bpalermo/kms-intermediate-rotator/pkg/config"
	"github.com/bpalermo/kms-intermediate-rotator/pkg/kmssigner"
	"github.com/bpalermo/kms-intermediate-rotator/pkg/rotation"
)

// initTimeout bounds the start-up calls (SSM GetParameter, KMS
// GetPublicKey), inside the 10 seconds of the Lambda init phase.
const initTimeout = 8 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv, startLambda))
}

// startLambda serves h as the Lambda handler; it never returns.
func startLambda(h func(context.Context, rotation.Event) error) { lambda.Start(h) }

func run(args []string, stdout, stderr io.Writer, getenv func(string) string, start func(func(context.Context, rotation.Event) error)) int {
	fs := flag.NewFlagSet("rotator", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "kms-intermediate-rotator %s\n", version.Version)
		return 0
	}

	// Structured JSON, one object per line, which CloudWatch Logs indexes.
	logger := slog.New(slog.NewJSONHandler(stdout, nil)).With("version", version.Version)
	slog.SetDefault(logger)
	ctx, cancel := context.WithTimeout(context.Background(), initTimeout)
	r, err := setup(ctx, getenv, logger)
	cancel()
	if err != nil {
		logger.Error("refusing to start", "error", err.Error())
		return 1
	}
	logger.Info("started", "secrets", len(r.Config.Secrets), "signing_algorithm", string(r.Signer.Algorithm()))
	start(r.Handle)
	return 0
}

// setup builds the rotator from the environment.
func setup(ctx context.Context, getenv func(string) string, logger *slog.Logger) (*rotation.Rotator, error) {
	// A missing or doubled configuration fails before anything touches AWS.
	if (getenv(config.EnvConfig) == "") == (getenv(config.EnvConfigParameter) == "") {
		return nil, fmt.Errorf("set exactly one of %s and %s", config.EnvConfig, config.EnvConfigParameter)
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	cfg, err := config.Load(ctx, getenv, ssm.NewFromConfig(awsCfg))
	if err != nil {
		return nil, err
	}
	signer, err := kmssigner.New(ctx, kms.NewFromConfig(awsCfg), cfg.KMSKeyID, cfg.SigningAlgorithm, cfg.Root.PublicKey)
	if err != nil {
		return nil, err
	}
	return &rotation.Rotator{
		SecretsManager: secretsmanager.NewFromConfig(awsCfg),
		Config:         cfg,
		Signer:         signer,
		Logger:         logger,
	}, nil
}
