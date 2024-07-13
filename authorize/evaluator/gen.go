package evaluator

//go:generate codecgen -o=evaluator_codecgen.go -st=mapstructure,codec -nx -j=false -d=1 -r=^(evaluatorOptions)|(ClientCertConstraints)$ config.go functions.go
