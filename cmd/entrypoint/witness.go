package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/shlex"
	"github.com/testifysec/go-witness"
	"github.com/testifysec/go-witness/archivista"
	"github.com/testifysec/go-witness/attestation"
	"github.com/testifysec/go-witness/attestation/commandrun"
	"github.com/testifysec/go-witness/attestation/environment"
	"github.com/testifysec/go-witness/attestation/git"
	"github.com/testifysec/go-witness/attestation/material"
	"github.com/testifysec/go-witness/attestation/product"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/dsse"
	"github.com/testifysec/go-witness/log"
	"github.com/testifysec/go-witness/signer/fulcio"
	"github.com/testifysec/go-witness/timestamp"
)

const (
	DEFAULT_FULCIO_URL            = "https://v1.fulcio.sigstore.dev"
	DEFAULT_FULCIO_OIDC_ISSUER    = "https://oauth2.sigstore.dev/auth"
	DEFAULT_FULCIO_OIDC_CLIENT_ID = "sigstore"
	DEFAULT_TIMESTAMP_URL         = "https://freetsa.org/tsr"
	DEFAULT_ARCHIVISTA_URL        = "https://archivista.testifysec.io"
	DEFAULT_STEP_ENV              = "TEKTON_RESOURCE_NAME"
	DEFAULT_ENABLE_TRACING        = false
	DEFAULT_OUTFILE               = ""
	DEFAULT_ATTESTORS             = "environment,git"
)

func loadFulcioSigner(ctx context.Context) (cryptoutil.Signer, error) {
	FULCIO_URL := DEFAULT_FULCIO_URL
	if val, exists := os.LookupEnv("FULCIO_URL"); exists {
		FULCIO_URL = val
	}

	FULCIO_OIDC_ISSUER := DEFAULT_FULCIO_OIDC_ISSUER
	if val, exists := os.LookupEnv("FULCIO_OIDC_ISSUER"); exists {
		FULCIO_OIDC_ISSUER = val
	}

	FULCIO_OIDC_CLIENT_ID := DEFAULT_FULCIO_OIDC_CLIENT_ID
	if val, exists := os.LookupEnv("FULCIO_OIDC_CLIENT_ID"); exists {
		FULCIO_OIDC_CLIENT_ID = val
	}

	signer, err := fulcio.Signer(ctx, FULCIO_URL, FULCIO_OIDC_ISSUER, FULCIO_OIDC_CLIENT_ID, "")
	if err != nil {
		return nil, fmt.Errorf("failed to load fulcio signer: %w", err)
	}

	return signer, nil
}

func withWitness(ctx context.Context, args []string) error {

	signer, error := loadFulcioSigner(ctx)
	if error != nil {
		return fmt.Errorf("failed to load fulcio signer: %w", error)
	}

	TIMESTAMP_URL := DEFAULT_TIMESTAMP_URL
	if val, exists := os.LookupEnv("TIMESTAMP_URL"); exists {
		TIMESTAMP_URL = val
	}

	ARCHIVISTA_URL := DEFAULT_ARCHIVISTA_URL
	if val, exists := os.LookupEnv("ARCHIVISTA_URL"); exists {
		ARCHIVISTA_URL = val
	}

	STEP_ENV := DEFAULT_STEP_ENV
	if val, exists := os.LookupEnv("STEP_ENV"); exists {
		STEP_ENV = val
	}

	ATTESTORS := DEFAULT_ATTESTORS
	if val, exists := os.LookupEnv("ATTESTORS"); exists {
		ATTESTORS = val
	}

	OUT_FILE := DEFAULT_OUTFILE
	if val, exists := os.LookupEnv("OUT_FILE"); exists {
		OUT_FILE = val
	}

	timestampers := []dsse.Timestamper{}
	for _, url := range []string{TIMESTAMP_URL} {
		timestampers = append(timestampers, timestamp.NewTimestamper(timestamp.TimestampWithUrl(url)))
	}

	joinedArgs := strings.Join(args, " ")

	attestors, err := getAttestorsFromEnv(ctx, joinedArgs, ATTESTORS)
	if err != nil {
		return fmt.Errorf("failed to get attestors: %w", err)
	}

	stepName := os.Getenv(STEP_ENV)
	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	result, err := witness.Run(
		stepName,
		signer,
		witness.RunWithAttestors(attestors),
		witness.RunWithAttestationOpts(attestation.WithWorkingDir(workDir)),
		witness.RunWithTimestampers(timestampers...),
	)

	if err != nil {
		return err
	}

	//upload to archivista
	archivistaClient := archivista.New(ARCHIVISTA_URL)
	if gitoid, err := archivistaClient.Store(ctx, result.SignedEnvelope); err != nil {
		return fmt.Errorf("failed to store artifact in archivist: %w", err)
	} else {
		log.Infof("Stored in archivist as %v\n", gitoid)
	}

	//write to file
	signedBytes, err := json.Marshal(&result.SignedEnvelope)
	if err != nil {
		return fmt.Errorf("failed to marshal envelope: %w", err)
	}

	if OUT_FILE != "" {
		if err := ioutil.WriteFile(OUT_FILE, signedBytes, 0644); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	} else {
		fmt.Println(string(signedBytes))
	}

	return nil
}

func getAttestorsFromEnv(ctx context.Context, args string, attestors string) ([]attestation.Attestor, error) {
	attestorList := []attestation.Attestor{product.New(), material.New()}

	parsedArgs, err := shlex.Split(args)
	if err != nil {
		return nil, fmt.Errorf("failed to parse args: %w", err)
	}

	ENABLE_TRACING := DEFAULT_ENABLE_TRACING
	if val, exists := os.LookupEnv("ENABLE_TRACING"); exists {
		if strings.ToLower(val) == "true" {
			ENABLE_TRACING = true
		}
	}

	if len(args) > 0 {
		attestorList = append(attestorList, commandrun.New(commandrun.WithCommand(parsedArgs), commandrun.WithTracing(ENABLE_TRACING)))
	}

	for _, attestor := range strings.Split(attestors, ",") {
		switch attestor {
		case "environment":
			attestorList = append(attestorList, environment.New())
		case "git":
			attestorList = append(attestorList, git.New())
		default:
			return nil, fmt.Errorf("unsupported attestor: %s", attestor)
		}
	}
	return attestorList, nil
}

//Witness Logger

type StdoutStderrLogger struct{}

func (l StdoutStderrLogger) Errorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func (l StdoutStderrLogger) Error(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
}

func (l StdoutStderrLogger) Warnf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

func (l StdoutStderrLogger) Warn(args ...interface{}) {
	fmt.Fprintln(os.Stdout, args...)
}

func (l StdoutStderrLogger) Debugf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

func (l StdoutStderrLogger) Debug(args ...interface{}) {
	fmt.Fprintln(os.Stdout, args...)
}

func (l StdoutStderrLogger) Infof(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

func (l StdoutStderrLogger) Info(args ...interface{}) {
	fmt.Fprintln(os.Stdout, args...)
}
