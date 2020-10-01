/*
Copyright 2016 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package program

import (
	"fmt"

	"github.com/google/go-jsonnet/ast"
	"github.com/google/go-jsonnet/internal/errors"
)

type analysisState struct {
	err      error
	freeVars ast.IdentifierSet
}

func visitNext(a ast.Node, inObject bool, vars ast.IdentifierSet, state *analysisState) {
	if state.err != nil {
		return
	}
	state.err = analyzeVisit(a, inObject, vars)
	state.freeVars.AddIdentifiers(a.FreeVariables())
}

func enterLocal(binds ast.LocalBinds, vars ast.IdentifierSet, inObject bool, s *analysisState) ast.IdentifierSet {
	newVars := vars.Clone()
	for _, bind := range binds {
		newVars.Add(bind.Variable)
	}
	// Binds in local can be mutually or even self recursive
	for _, bind := range binds {
		visitNext(bind.Body, inObject, newVars, s)
	}
	return newVars
}

func analyzeVisit(a ast.Node, inObject bool, vars ast.IdentifierSet) error {
	s := &analysisState{freeVars: ast.NewIdentifierSet()}

	// TODO(sbarzowski) Test somehow that we're visiting all the nodes
	switch a := a.(type) {
	case *ast.Apply:
		visitNext(a.Target, inObject, vars, s)
		for _, arg := range a.Arguments.Positional {
			visitNext(arg.Expr, inObject, vars, s)
		}
		for _, arg := range a.Arguments.Named {
			visitNext(arg.Arg, inObject, vars, s)
		}
	case *ast.Array:
		for _, elem := range a.Elements {
			visitNext(elem.Expr, inObject, vars, s)
		}
	case *ast.Binary:
		visitNext(a.Left, inObject, vars, s)
		visitNext(a.Right, inObject, vars, s)
	case *ast.Conditional:
		visitNext(a.Cond, inObject, vars, s)
		visitNext(a.BranchTrue, inObject, vars, s)
		visitNext(a.BranchFalse, inObject, vars, s)
	case *ast.Error:
		visitNext(a.Expr, inObject, vars, s)
	case *ast.Function:
		newVars := vars.Clone()
		for _, param := range a.Parameters {
			newVars.Add(param.Name)
		}
		for _, param := range a.Parameters {
			if param.DefaultArg != nil {
				visitNext(param.DefaultArg, inObject, newVars, s)
			}
		}
		visitNext(a.Body, inObject, newVars, s)
		// Parameters are free inside the body, but not visible here or outside
		for _, param := range a.Parameters {
			s.freeVars.Remove(param.Name)
		}
	case *ast.Import:
		//nothing to do here
	case *ast.ImportStr:
		//nothing to do here
	case *ast.InSuper:
		if !inObject {
			return errors.MakeStaticError("Can't use super outside of an object.", *a.Loc())
		}
		visitNext(a.Index, inObject, vars, s)
	case *ast.SuperIndex:
		if !inObject {
			return errors.MakeStaticError("Can't use super outside of an object.", *a.Loc())
		}
		visitNext(a.Index, inObject, vars, s)
	case *ast.Index:
		visitNext(a.Target, inObject, vars, s)
		visitNext(a.Index, inObject, vars, s)
	case *ast.Local:
		newVars := enterLocal(a.Binds, vars, inObject, s)
		visitNext(a.Body, inObject, newVars, s)

		// Any usage of newly created variables inside are considered free
		// but they are not here or outside
		for _, bind := range a.Binds {
			s.freeVars.Remove(bind.Variable)
		}
	case *ast.LiteralBoolean:
		//nothing to do here
	case *ast.LiteralNull:
		//nothing to do here
	case *ast.LiteralNumber:
		//nothing to do here
	case *ast.LiteralString:
		//nothing to do here
	case *ast.DesugaredObject:
		newVars := enterLocal(a.Locals, vars, true, s)
		for _, field := range a.Fields {
			visitNext(field.Body, true, newVars, s)
		}
		for _, assert := range a.Asserts {
			visitNext(assert, true, newVars, s)
		}

		// Object local vars are not free outside of object
		for _, bind := range a.Locals {
			s.freeVars.Remove(bind.Variable)
		}

		// Field names are calculated *outside* of the object
		for _, field := range a.Fields {
			visitNext(field.Name, inObject, vars, s)
		}

	case *ast.Self:
		if !inObject {
			return errors.MakeStaticError("Can't use self outside of an object.", *a.Loc())
		}
	case *ast.Unary:
		visitNext(a.Expr, inObject, vars, s)
	case *ast.Var:
		if !vars.Contains(a.Id) {
			return errors.MakeStaticError(fmt.Sprintf("Unknown variable: %v", a.Id), *a.Loc())
		}
		s.freeVars.Add(a.Id)
	default:
		panic(fmt.Sprintf("Unexpected node %#v", a))
	}
	a.SetFreeVariables(s.freeVars.ToOrderedSlice())
	return s.err
}

// analyze checks variable references (these could be checked statically in Jsonnet).
// It enriches the AST with additional information about free variables in every node,
// so it is necessary to always run it before executing the AST.
func analyze(node ast.Node) error {
	return analyzeVisit(node, false, ast.NewIdentifierSet("std"))
}
