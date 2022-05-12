package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

func main() {
	fmt.Println("Generating compliance tests")

	successCount, failureCount := 0, 0

	for _, tc := range cases.MustLoad("opa/test/cases/testdata").Sorted().Cases {
		//fmt.Printf("%s - %s\n", tc.Filename, tc.Note)

		folderPath, err := createFolder(tc)
		if err != nil {
			panic(err)
		}

		modules := map[string]string{}
		for i, mod := range tc.Modules {
			modules[fmt.Sprintf("mod_%d", i)] = mod
		}
		//fmt.Printf("modules: %v\n", modules)
		modFiles := getModuleFiles(modules, false)

		var entryPoints []string
		for _, modFile := range modFiles {
			entryPoints = append(entryPoints, strings.TrimPrefix(strings.ReplaceAll(modFile.Parsed.Package.Path.String(), ".", "/"), "data/"))
		}

		//fmt.Printf("entrypoints: %v\n", entryPoints)

		b := bundle.Bundle{Modules: modFiles}

		compiler := compile.New().
			WithTarget("plan").
			WithEntrypoints(entryPoints...).
			WithBundle(&b)
		if err := compiler.Build(context.Background()); err != nil {
			fmt.Printf("Skipping %s: %v\n", tc.Note, err)
			//log.Fatal(err)
			failureCount++
			continue
		}

		if len(b.PlanModules) != 1 {
			fmt.Printf("Unexpected plan count: %d\n", len(b.PlanModules))
			failureCount++
			continue
		}

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

		planData, err := indent(b.PlanModules[0].Raw)
		if err != nil {
			fmt.Printf("Failed to marshal plan: %s\n", err.Error())
			failureCount++
			continue
		}
		if err := writeWile(folderPath, "plan.json", planData); err != nil { // We know there is only one plan
			fmt.Printf("Failed to write plan: %s\n", err.Error())
			failureCount++
			continue
		}

		if tc.Input != nil {
			input, err := json.MarshalIndent(tc.Input, "", "\t")
			if err != nil {
				fmt.Printf("Failed to marshal input: %s\n", err.Error())
				failureCount++
				continue
			}
			if err := writeWile(folderPath, "input.json", input); err != nil { // We know there is only one plan
				fmt.Printf("Failed to write input: %s\n", err.Error())
				failureCount++
				continue
			}
		}

		if tc.Data != nil {
			data, err := json.MarshalIndent(tc.Data, "", "\t")
			if err != nil {
				fmt.Printf("Failed to marshal data: %s\n", err.Error())
				failureCount++
				continue
			}
			if err := writeWile(folderPath, "data.json", data); err != nil { // We know there is only one plan
				fmt.Printf("Failed to write data: %s\n", err.Error())
				failureCount++
				continue
			}
		}

		for entryPoint, expectedResult := range expectedResultSet[0] { // We know there is only one result
			fileName := fmt.Sprintf("expected_%s.json", entryPoint)
			data, err := json.MarshalIndent(expectedResult, "", "\t")
			if err != nil {
				fmt.Printf("Failed to marshal expected result: %s\n", err.Error())
				failureCount++
				continue
			}
			if err := writeWile(folderPath, fileName, data); err != nil { // We know there is only one plan
				fmt.Printf("Failed to write expected result: %s\n", err.Error())
				failureCount++
				continue
			}
		}

		successCount++
	}

	fmt.Printf("Tests generated: %d; successes: %d; failures: %d\n", successCount+failureCount, successCount, failureCount)
}

func indent(raw []byte) ([]byte, error) {
	var d interface{}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	return json.MarshalIndent(d, "", "\t")
}

func writeWile(folderPath string, name string, data []byte) error {
	return os.WriteFile(fmt.Sprintf("%s/%s", folderPath, name), data, 0644)
}

func createFolder(tc cases.TestCase) (string, error) {
	parts := strings.SplitN(tc.Note, "/", 2)

	var group, name string

	switch len(parts) {
	case 1:
		fileParts := strings.Split(tc.Filename, "/")
		l := len(fileParts)
		if l < 2 {
			return "", fmt.Errorf("test case file path could not be split into group: %s", tc.Filename)
		}
		group = fileParts[l-2 : l-1][0]
		name = parts[0]
	case 2:
		group = parts[0]
		name = parts[1]
	default:
		return "", fmt.Errorf("test case note could not be split into group and name: %s", tc.Note)
	}

	name = strings.ReplaceAll(name, " ", "_")

	path := fmt.Sprintf("tmp/%s/%s", group, name)
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", err
	}

	return path, nil
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

func eval(entryPoints []string, tc cases.TestCase) ([]ResultMap, error) {
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

	if err != nil {
		return nil, err
	}

	//if tc.WantError != nil {
	//	testAssertErrorText(t, *tc.WantError, err)
	//}

	//if tc.WantErrorCode != nil {
	//	testAssertErrorCode(t, *tc.WantErrorCode, err)
	//}

	//if err != nil && tc.WantErrorCode == nil && tc.WantError == nil {
	//	t.Fatalf("unexpected error: %v", err)
	//}

	//if tc.WantResult != nil {
	//	testAssertResultSet(t, *tc.WantResult, rs, tc.SortBindings)
	//}

	//if tc.WantResult == nil && tc.WantErrorCode == nil && tc.WantError == nil {
	//	t.Fatal("expected one of: 'want_result', 'want_error_code', or 'want_error'")
	//}

	//if testing.Verbose() {
	//	PrettyTrace(os.Stderr, *buf)
	//}

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
