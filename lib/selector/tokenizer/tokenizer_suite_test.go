package tokenizer_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestTokenizer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Tokenizer Suite")
}
