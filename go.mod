module github.com/chrisfenner/tpmdirect

go 1.16

require (
	github.com/chrisfenner/crypto v0.0.0-20211212022239-a128b7749a60
	github.com/chrisfenner/go-tpm-sim v0.0.0-20211022232009-8a050aba42b1
	github.com/google/go-cmp v0.5.6
)

replace golang.org/x/crypto => github.com/chrisfenner/crypto v0.0.0-20211212023216-a475de873b7a
