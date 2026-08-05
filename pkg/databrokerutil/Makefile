# Usage:
#   make bench STORAGE=mem TESTCASE=concurrent_conflicting [CONC=4] [BENCHTIME=10x] [EXTRA=synchronous_commit]
#
# STORAGE:  mem | file | postgres
# TESTCASE: concurrent_maybe_conflicting | concurrent_conflicting | concurrent_non-conflicting | all
# CONC:     concurrency suffix (conc-N) | all | empty for a single combined run
# BENCHTIME: passed to -benchtime
# EXTRA:    optional annotation inserted in output file names

STORAGE ?= mem
TESTCASE ?= concurrent_conflicting
CONC ?=
BENCHTIME ?= 30s
EXTRA ?=

TESTCASES := concurrent_maybe_conflicting concurrent_conflicting concurrent_non-conflicting
CONCS := 2 4 8

NAME := $(STORAGE)$(if $(EXTRA),_$(EXTRA),)_$(TESTCASE)$(if $(CONC),_conc-$(CONC),)
BENCH := ^BenchmarkSingleFlight$$/^$(STORAGE)$$/^conc-$(if $(CONC),$(CONC),[0-9]+)$$/^$(TESTCASE)$$

.PHONY: bench
ifeq ($(TESTCASE),all)
bench:
	@for tc in $(TESTCASES); do \
		$(MAKE) --no-print-directory bench TESTCASE=$$tc CONC=$(CONC) EXTRA=$(EXTRA) || exit 1; \
	done
else ifeq ($(CONC),all)
bench:
	@for c in $(CONCS); do \
		$(MAKE) --no-print-directory bench TESTCASE=$(TESTCASE) CONC=$$c EXTRA=$(EXTRA) || exit 1; \
	done
else
bench:
	go test -run '^$$' -bench '$(BENCH)' -benchtime=$(BENCHTIME) -benchmem \
		-cpuprofile=$(NAME).cpu.out \
		-memprofile=$(NAME).mem.out \
		-trace=$(NAME).trace.out \
		-o $(NAME).test \
		. | tee $(NAME).out
endif

.PHONY: clean
clean:
	rm -f *.cpu.out *.mem.out *.trace.out *.test *.out
