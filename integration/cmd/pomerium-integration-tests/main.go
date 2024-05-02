// Package main contains the pomerium integration tests
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/google/go-jsonnet"
	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/rs/zerolog/log"
	"sigs.k8s.io/yaml"
)

func main() {
	generateCmd := &ffcli.Command{
		Name: "generate-configuration",
		Exec: func(ctx context.Context, _ []string) error {
			return runGenerateConfiguration(ctx)
		},
	}
	rootCmd := &ffcli.Command{
		Subcommands: []*ffcli.Command{generateCmd},
		Exec: func(_ context.Context, _ []string) error {
			return flag.ErrHelp
		},
	}
	err := rootCmd.ParseAndRun(context.Background(), os.Args[1:])
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal().Err(err).Send()
	}
}

func runGenerateConfiguration(_ context.Context) error {
	log.Info().Msg("generating configuration")

	root := filepath.Join(".", "integration")
	if _, err := os.Stat(root); err != nil {
		return fmt.Errorf("expected integration subfolder in cwd")
	}
	tplRoot := filepath.Join(root, "tpl")

	var allSrcPaths []string
	err := filepath.WalkDir(tplRoot, func(srcPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		allSrcPaths = append(allSrcPaths, srcPath)

		return err
	})
	if err != nil {
		return err
	}
	sort.Strings(allSrcPaths)

	vm := jsonnet.MakeVM()
	vm.Importer(&jsonnet.FileImporter{JPaths: allSrcPaths})
	for _, srcPath := range allSrcPaths {
		if filepath.Ext(srcPath) != ".jsonnet" {
			continue
		}

		dstPath := filepath.Join(root, srcPath[len(tplRoot)+1:])
		dstPath = dstPath[:len(dstPath)-len(filepath.Ext(dstPath))]

		contents, err := vm.EvaluateFile(srcPath)
		if err != nil {
			return fmt.Errorf("error evaluating jsonnet (path=%s): %w", srcPath, err)
		}
		asYAML, _ := yaml.JSONToYAML([]byte(contents))

		err = os.MkdirAll(filepath.Dir(dstPath), 0o755)
		if err != nil {
			return fmt.Errorf("error creating directory (path=%s): %w", dstPath, err)
		}

		err = os.WriteFile(dstPath, asYAML, 0o600)
		if err != nil {
			return fmt.Errorf("error writing file (path=%s): %w", dstPath, err)
		}
	}

	return nil
}
