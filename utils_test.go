package gomsf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContains(t *testing.T) {
	assert.Equal(t, true, contains([]string{"aaa", "bbb", "ccc"}, "aaa"))
	assert.Equal(t, false, contains([]string{"aaa", "bbb", "ccc"}, "xxx"))
}
