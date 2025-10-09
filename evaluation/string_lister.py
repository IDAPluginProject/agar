#!/usr/bin/env python3
import sys
import json
import subprocess
import tempfile
import os

# Go code to parse the Go file
go_code = '''
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
)

type Result struct {
	File     string `json:"file"`
	Package  string `json:"package"`
	Function string `json:"function"`
	String   string `json:"string"`
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}
	filename := os.Args[1]

	src, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		panic(err)
	}

	packageName := file.Name.Name

	var results []Result

	ast.Inspect(file, func(n ast.Node) bool {
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			funcName := funcDecl.Name.Name
			if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
				// method
				recvType := ""
				if star, ok := funcDecl.Recv.List[0].Type.(*ast.StarExpr); ok {
					if ident, ok := star.X.(*ast.Ident); ok {
						recvType = "_ptr_" + ident.Name
					}
				} else if ident, ok := funcDecl.Recv.List[0].Type.(*ast.Ident); ok {
					recvType = ident.Name
				}
				funcName = recvType + "." + funcName
			}
			fullFuncName := funcName

			// find strings in body
			if funcDecl.Body != nil {
				funcCounter := 0
				innerFuncEnds := []token.Pos{}
				innerFuncIds := map[int]int{}
				ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
					innerFuncCount := len(innerFuncEnds)
					for n != nil && innerFuncCount > 0 && innerFuncEnds[len(innerFuncEnds)-1] < n.Pos() {
						innerFuncIds[innerFuncCount] = 0
						innerFuncEnds = innerFuncEnds[:innerFuncCount-1]
						innerFuncCount -= 1
					}
					if funct, ok := n.(*ast.FuncLit); ok {
						funcCounter += 1
						currentFuncId := innerFuncIds[len(innerFuncEnds)]
						innerFuncIds[len(innerFuncEnds)] = currentFuncId + 1
						innerFuncEnds = append(innerFuncEnds, funct.End())
						return true
					}
					if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						str := lit.Value
						// remove quotes
						if len(str) >= 2 && str[0] == '"' && str[len(str)-1] == '"' {
							str = str[1 : len(str)-1]
						} else if len(str) >= 2 && str[0] == '`' && str[len(str)-1] == '`' {
							str = str[1 : len(str)-1]
						}
						if str != "" {
							if str != "" {
								funcName := fullFuncName
								if len(innerFuncEnds) > 0 {
									funcName = fmt.Sprintf("%s.func%d", funcName, innerFuncIds[0])
									for i := range len(innerFuncEnds) - 1 {
										funcName = fmt.Sprintf("%s.%d", funcName, innerFuncIds[i+1])
									}
								}
								results = append(results, Result{File: filename, Package: packageName, Function: funcName, String: str})
							}
						}
					}
					return true
				})
			}
		}
		return true
	})

	json.NewEncoder(os.Stdout).Encode(results)
}
'''

def find_go_files(directory):
    go_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.go'):
                go_files.append(os.path.join(root, file))
    return go_files

def main():
    if len(sys.argv) < 2:
        print("Usage: python string_lister.py <go_file_or_directory> [prefix]")
        sys.exit(1)

    path = sys.argv[1]
    prefix = sys.argv[2] if len(sys.argv) > 2 else ""

    if os.path.isfile(path):
        # Single file
        go_files = [path]
        output_file = path.rsplit('.', 1)[0] + '_strings.json'
    elif os.path.isdir(path):
        # Directory
        go_files = find_go_files(path)
        output_file = os.path.join(path, os.path.basename(path) + '_strings.json')
    else:
        print("Path does not exist")
        sys.exit(1)

    all_data = []

    # Create temporary Go file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False) as f:
        f.write(go_code)
        temp_go_file = f.name

    # Build the Go program
    temp_exe = temp_go_file + '.exe'
    build_result = subprocess.run(['go', 'build', '-o', temp_exe, temp_go_file], capture_output=True, text=True)
    if build_result.returncode != 0:
        print("Error building Go parser:", build_result.stderr)
        os.unlink(temp_go_file)
        sys.exit(1)

    try:
        directory_package_mappings = {}
        for go_file in go_files:
            # Run the executable
            result = subprocess.run([temp_exe, go_file], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error running Go parser on {go_file}:", result.stderr)
                continue

            # Parse the JSON output
            if result.stdout.strip() in ["", "null"]:
                continue
            data = json.loads(result.stdout)
            all_data.extend(data)
        directories = sorted(set((os.path.dirname(item["file"]), item["package"]) for item in all_data), key=lambda x: len(x[0]))
        for dir_path, package in directories:
            parent = os.path.dirname(dir_path)
            if parent in directory_package_mappings:
                directory_package_mappings[dir_path] = directory_package_mappings[parent] + "_" + package
            else:
                directory_package_mappings[dir_path] = package

        for item in all_data:
            dir_path = os.path.dirname(item["file"])
            package = directory_package_mappings[dir_path]
            item["function"] = prefix + package + "." + item["function"]
            del item["package"]

        # Save to JSON file
        with open(output_file, 'w') as f:
            json.dump(all_data, f, indent=2)

        print(f"Results saved to {output_file}")

    finally:
        # Clean up temp files
        os.unlink(temp_go_file)
        os.unlink(temp_exe)

if __name__ == "__main__":
    main()