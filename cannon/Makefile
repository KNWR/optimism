fuzz:
	go test -run NOTAREALTEST -v -fuzztime 10s -fuzz=FuzzStateSyscallBrk ./mipsevm
	go test -run NOTAREALTEST -v -fuzztime 10s -fuzz=FuzzStateSyscallClone ./mipsevm
	go test -run NOTAREALTEST -v -fuzztime 10s -fuzz=FuzzStateSyscallMmap ./mipsevm
	go test -run NOTAREALTEST -v -fuzztime 10s -fuzz=FuzzStateSyscallExitGroup ./mipsevm
	go test -run NOTAREALTEST -v -fuzztime 10s -fuzz=FuzzStateSyscallFnctl ./mipsevm
	go test -run NOTAREALTEST -v -fuzztime 10s -fuzz=FuzzStateHintRead ./mipsevm
	go test -run NOTAREALTEST -v -fuzztime 10s -fuzz=FuzzStateHintWrite ./mipsevm
	go test -run NOTAREALTEST -v -fuzztime 20s -fuzz=FuzzStatePreimageRead ./mipsevm
	go test -run NOTAREALTEST -v -fuzztime 20s -fuzz=FuzzStatePreimageWrite ./mipsevm

.PHONY: fuzz
