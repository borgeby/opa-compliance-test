package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/types"
	"github.com/open-policy-agent/opa/util"

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
			// if tc.Note != "withkeyword/with not stack (data)" {
			// 	continue
			// }

			modules := map[string]string{}
			for i, mod := range tc.Modules {
				modules[fmt.Sprintf("mod_%d", i)] = mod
			}
			modFiles := getModuleFiles(modules, false)

			if len(modFiles) == 0 {
				fmt.Printf("Skipping %s: No modules\n", tc.Note)
				continue
			}

			var packageNames []string
			var entryPoints []string
			for _, modFile := range modFiles {
				var pkg = modFile.Parsed.Package.Path.String()
				if len(modFile.Parsed.Rules) == 0 {
					fmt.Printf("Skipping %s in %s: No rules\n", pkg, tc.Note)
					continue
				}
				packageNames = append(packageNames, pkg)
				entryPoints = append(entryPoints, strings.ReplaceAll(strings.TrimPrefix(pkg, "data."), ".", "/"))
			}
			tc.EntryPoints = entryPoints

			b := bundle.Bundle{Modules: modFiles}

			compiler := compile.New().
				WithTarget("plan").
				WithPruneUnused(true).
				WithEntrypoints(entryPoints...).
				WithBundle(&b)
			if err := compiler.Build(context.Background()); err != nil {
				fmt.Printf("compile/Skipping %s: %v\n", tc.Note, err)
				failureCount++
				continue
			}

			if len(b.PlanModules) != 1 {
				fmt.Printf("Unexpected plan count %d for %s\n", len(b.PlanModules), tc.Note)
				failureCount++
				continue
			}

			if tc.WantError == nil && tc.WantErrorCode == nil {
				expectedResultSet, err := eval(packageNames, tc)
				if err != nil {
					fmt.Printf("eval/Skipping %s: %v\n", tc.Note, err)
					failureCount++
					continue
				}

				if len(expectedResultSet) != 1 {
					fmt.Printf("Unexpected result count %d for %s\n", len(expectedResultSet), tc.Note)
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
			} else if plan == nil {
				fmt.Printf("Failed to unmarshal plan: nil\n")
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

		if strings.HasSuffix(path, "test-functions-1006.yaml") {
			fmt.Printf("break\n")
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

func createQuery(packageNames []string) ast.Body {
	q := ast.Body{}
	for _, pkg := range packageNames {
		expr := ast.MustParseExpr(fmt.Sprintf("%s = %s", strings.ReplaceAll(pkg, ".", "_"), pkg))
		q = append(q, expr)
	}

	return q
}

func eval(packageNames []string, tc *ExtendedTestCase) ([]ResultMap, error) {
	// log.Printf("\nE: %v", packageNames)
	ctx := context.Background()

	q := createQuery(packageNames)

	modules := map[string]string{}
	for i, module := range tc.Modules {
		modules[fmt.Sprintf("test-%d.rego", i)] = module
	}

	compiler := ast.MustCompileModules(modules)
	// log.Printf("\nQ: %v", q)
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

func init() {
	// Used by the 'time/time caching' test
	ast.RegisterBuiltin(&ast.Builtin{
		Name: "test.sleep",
		Decl: types.NewFunction(
			types.Args(types.S),
			types.NewNull(),
		),
	})

	topdown.RegisterBuiltinFunc("test.sleep", func(_ topdown.BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
		d, _ := time.ParseDuration(string(operands[0].Value.(ast.String)))
		time.Sleep(d)
		return iter(ast.NullTerm())
	})
}
