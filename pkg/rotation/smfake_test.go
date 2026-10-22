package rotation_test

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// fakeSM is one secret in an in-process Secrets Manager: its versions, their
// values and their staging labels, with the behaviour the rotation relies
// on (label moves, AWSPREVIOUS, ResourceNotFound for a version without a
// value).
type fakeSM struct {
	mu       sync.Mutex
	arn      string
	name     string
	rotation bool
	values   map[string]*string  // version -> value (nil: no value yet)
	stages   map[string][]string // version -> labels

	puts    int
	lastPut *secretsmanager.PutSecretValueInput
	updates []secretsmanager.UpdateSecretVersionStageInput
	// beforePut, when set, runs at the start of PutSecretValue, outside the
	// lock: another writer racing this one.
	beforePut func()
}

func newFakeSM(arn, name string) *fakeSM {
	return &fakeSM{arn: arn, name: name, rotation: true, values: map[string]*string{}, stages: map[string][]string{}}
}

// version adds a version with labels; value nil is a version Secrets
// Manager made for a rotation and that has no value yet.
func (f *fakeSM) version(id string, value *string, labels ...string) {
	f.values[id] = value
	f.stages[id] = labels
}

func (f *fakeSM) check(id *string) error {
	if s := aws.ToString(id); s != f.arn && s != f.name {
		return &types.ResourceNotFoundException{Message: aws.String("no secret " + s)}
	}
	return nil
}

func (f *fakeSM) DescribeSecret(_ context.Context, in *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(in.SecretId); err != nil {
		return nil, err
	}
	stages := map[string][]string{}
	for id, l := range f.stages {
		if len(l) > 0 {
			stages[id] = slices.Clone(l)
		}
	}
	return &secretsmanager.DescribeSecretOutput{
		ARN:                aws.String(f.arn),
		Name:               aws.String(f.name),
		RotationEnabled:    aws.Bool(f.rotation),
		VersionIdsToStages: stages,
	}, nil
}

func (f *fakeSM) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(in.SecretId); err != nil {
		return nil, err
	}
	id := aws.ToString(in.VersionId)
	stage := aws.ToString(in.VersionStage)
	if id == "" {
		id = f.holder(stage)
	}
	v, ok := f.values[id]
	if !ok || v == nil || (stage != "" && !slices.Contains(f.stages[id], stage)) {
		return nil, &types.ResourceNotFoundException{Message: aws.String("no such version")}
	}
	return &secretsmanager.GetSecretValueOutput{ARN: aws.String(f.arn), VersionId: aws.String(id), SecretString: v, VersionStages: slices.Clone(f.stages[id])}, nil
}

func (f *fakeSM) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	if f.beforePut != nil {
		f.beforePut()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(in.SecretId); err != nil {
		return nil, err
	}
	f.lastPut = in
	id := aws.ToString(in.ClientRequestToken)
	if v := f.values[id]; v != nil {
		if *v != aws.ToString(in.SecretString) {
			return nil, &types.ResourceExistsException{Message: aws.String("version exists with another value")}
		}
		return &secretsmanager.PutSecretValueOutput{VersionId: aws.String(id)}, nil
	}
	for _, label := range in.VersionStages {
		f.detach(label)
	}
	f.values[id] = in.SecretString
	f.stages[id] = slices.Clone(in.VersionStages)
	f.puts++
	return &secretsmanager.PutSecretValueOutput{VersionId: aws.String(id), VersionStages: in.VersionStages}, nil
}

func (f *fakeSM) UpdateSecretVersionStage(_ context.Context, in *secretsmanager.UpdateSecretVersionStageInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.check(in.SecretId); err != nil {
		return nil, err
	}
	f.updates = append(f.updates, *in)
	label, to, from := aws.ToString(in.VersionStage), aws.ToString(in.MoveToVersionId), aws.ToString(in.RemoveFromVersionId)
	// Like Secrets Manager: a label attached elsewhere moves only when the
	// request names the version it is on.
	if holder := f.holder(label); holder != "" && holder != to && holder != from {
		return nil, &types.InvalidParameterException{Message: aws.String(fmt.Sprintf("%s is on %s, not %s", label, holder, from))}
	}
	if _, ok := f.stages[to]; !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("no version " + to)}
	}
	f.detach(label)
	f.stages[to] = append(f.stages[to], label)
	if label == "AWSCURRENT" && from != "" {
		f.detach("AWSPREVIOUS")
		f.stages[from] = append(f.stages[from], "AWSPREVIOUS")
	}
	return &secretsmanager.UpdateSecretVersionStageOutput{ARN: aws.String(f.arn)}, nil
}

func (f *fakeSM) holder(label string) string {
	for id, l := range f.stages {
		if slices.Contains(l, label) {
			return id
		}
	}
	return ""
}

func (f *fakeSM) detach(label string) {
	for id, l := range f.stages {
		f.stages[id] = slices.DeleteFunc(l, func(s string) bool { return s == label })
	}
}

func (f *fakeSM) value(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return aws.ToString(f.values[id])
}

func (f *fakeSM) labels(id string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.stages[id])
}
