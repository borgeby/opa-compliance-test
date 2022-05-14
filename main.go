package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/open-policy-agent/opa/util"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/open-policy-agent/opa/compile"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/test/cases"
	"github.com/open-policy-agent/opa/topdown"
)

type ResultMap map[string]interface{}

type ExtendedTestCase struct {
	cases.TestCase
	EntryPoints    []string    `json:"entrypoints"`
	Plan           interface{} `json:"plan"`
	WantPlanResult interface{} `json:"want_plan_result"`
}

type Test struct {
	filename string
	Cases    []*ExtendedTestCase `json:"cases"`
}

func main() {
	args := os.Args
	var srcPath, dstPath string

	switch len(args) {
	case 2:
		srcPath = "opa/test/cases/testdata"
		dstPath = args[1]
	case 3:
		srcPath = args[1]
		dstPath = args[2]
	default:
		panic(fmt.Sprintf("Usage: %s [SRC] DST", args[0]))
	}

	generate(srcPath, dstPath)
}

func generate(srcPath string, dstPath string) {
	fmt.Println("Generating compliance tests")

	successCount, failureCount := 0, 0

	for _, t := range loadTests(srcPath) {
		for _, tc := range t.Cases {
			modules := map[string]string{}
			for i, mod := range tc.Modules {
				modules[fmt.Sprintf("mod_%d", i)] = mod
			}
			modFiles := getModuleFiles(modules, false)

			var entryPoints []string
			for _, modFile := range modFiles {
				entryPoints = append(entryPoints, strings.TrimPrefix(strings.ReplaceAll(modFile.Parsed.Package.Path.String(), ".", "/"), "data/"))
			}
			tc.EntryPoints = entryPoints

			b := bundle.Bundle{Modules: modFiles}

			compiler := compile.New().
				WithTarget("plan").
				WithEntrypoints(entryPoints...).
				WithBundle(&b)
			if err := compiler.Build(context.Background()); err != nil {
				fmt.Printf("Skipping %s: %v\n", tc.Note, err)
				failureCount++
				continue
			}

			if len(b.PlanModules) != 1 {
				fmt.Printf("Unexpected plan count: %d\n", len(b.PlanModules))
				failureCount++
				continue
			}

			if tc.WantError == nil {
				expectedResultSet, err := eval(entryPoints, tc)
				if err != nil {
					fmt.Printf("Skipping %s: %v\n", tc.Note, err)
					failureCount++
					continue
				}

				if len(expectedResultSet) != 1 {
					fmt.Printf("Unexpected result count: %d\n", len(expectedResultSet))
					failureCount++
					continue
				}

				tc.WantPlanResult = expectedResultSet[0]
			}

			var plan interface{}
			if err := json.Unmarshal(b.PlanModules[0].Raw, &plan); err != nil {
				fmt.Printf("Failed to unmarshal plan: %s\n", err.Error())
				failureCount++
				continue
			}
			tc.Plan = plan

			successCount++
		}

		if tcJson, err := json.MarshalIndent(t, "", "\t"); err != nil {
			fmt.Printf("Failed to marchal tc to json: %s\n", err.Error())
			failureCount++
			continue
		} else {
			tPath := strings.Split(t.filename, "/")
			folderPath := fmt.Sprintf("%s/%s", dstPath, tPath[len(tPath)-2])
			tcFileName := strings.ReplaceAll(tPath[len(tPath)-1], ".yaml", ".json")

			if err := os.MkdirAll(folderPath, 0755); err != nil {
				panic(err)
			}

			if err := writeWile(folderPath, tcFileName, tcJson); err != nil {
				fmt.Printf("Failed to write tc: %s\n", err.Error())
				failureCount++
				continue
			}
		}
	}

	fmt.Printf("Tests generated: %d; successes: %d; failures: %d\n", successCount+failureCount, successCount, failureCount)
}

func loadTests(dirpath string) []Test {

	var result []Test

	err := filepath.Walk(dirpath, func(path string, info os.FileInfo, err error) error {

		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		bs, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		var x Test
		if err := util.Unmarshal(bs, &x); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		for i := range x.Cases {
			x.Cases[i].Filename = path
			x.filename = path
		}

		result = append(result, x)
		return nil
	})

	if err != nil {
		panic(err)
	}

	return result
}

func writeWile(folderPath string, name string, data []byte) error {
	return os.WriteFile(fmt.Sprintf("%s/%s", folderPath, name), data, 0644)
}

func getModuleFiles(src map[string]string, includeRaw bool) []bundle.ModuleFile {

	var keys []string

	for k := range src {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	var modules []bundle.ModuleFile

	for _, k := range keys {
		module, err := ast.ParseModule(k, src[k])
		if err != nil {
			panic(err)
		}
		modules = append(modules, bundle.ModuleFile{
			Parsed: module,
			Path:   k,
			URL:    k,
		})
		if includeRaw {
			modules[len(modules)-1].Raw = []byte(src[k])
		}
	}

	return modules
}

func createQuery(entryPoints []string) ast.Body {
	q := ast.Body{}
	for _, entryPoint := range entryPoints {
		expr := ast.MustParseExpr(fmt.Sprintf("%s = data.%s", entryPoint, entryPoint))
		q = append(q, expr)
	}

	return q
}

func eval(entryPoints []string, tc *ExtendedTestCase) ([]ResultMap, error) {
	ctx := context.Background()

	q := createQuery(entryPoints)

	modules := map[string]string{}
	for i, module := range tc.Modules {
		modules[fmt.Sprintf("test-%d.rego", i)] = module
	}

	compiler := ast.MustCompileModules(modules)
	query, err := compiler.QueryCompiler().Compile(q)

	if err != nil {
		return nil, err
	}

	var store storage.Store

	if tc.Data != nil {
		store = inmem.NewFromObject(*tc.Data)
	} else {
		store = inmem.New()
	}

	txn := storage.NewTransactionOrDie(ctx, store)

	var input *ast.Term

	if tc.InputTerm != nil {
		input = ast.MustParseTerm(*tc.InputTerm)
	} else if tc.Input != nil {
		input = ast.NewTerm(ast.MustInterfaceToValue(*tc.Input))
	}

	qrs, err := topdown.NewQuery(query).
		WithCompiler(compiler).
		WithStore(store).
		WithTransaction(txn).
		WithInput(input).
		WithStrictBuiltinErrors(tc.StrictError).
		Run(ctx)

	if err != nil && tc.WantErrorCode == nil && tc.WantError == nil {
		return nil, err
	}

	if len(qrs) > 1 {
		return nil, fmt.Errorf("ResultSet contains more than one entry")
	}

	resultSet := make([]ResultMap, 0, len(qrs))
	for _, qr := range qrs {
		result := make(ResultMap)
		for k, term := range qr {
			v, err := ast.JSON(term.Value)
			if err != nil {
				return nil, err
			}
			result[string(k)] = v
		}
		resultSet = append(resultSet, result)
	}

	return resultSet, nil
}
