module github.com/chrisfenner/tpmdirect

go 1.16

require (
	github.com/chrisfenner/go-tpm-sim v0.0.0-20211022232009-8a050aba42b1
	github.com/google/go-cmp v0.5.6
	golang.org/x/crypto v0.0.0-00010101000000-000000000000
)

replace golang.org/x/crypto => github.com/chrisfenner/crypto v0.0.0-20211212191354-612393ddde2b
