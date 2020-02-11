package testflight_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("tracking active users", func() {
	It("shows that you have done some stuff", func() {
		activeUsers := fly("active-users")
		Expect(string(activeUsers.Out.Contents())).To(ContainSubstring(`username  connector  last login`))
		Expect(string(activeUsers.Out.Contents())).To(ContainSubstring(`test      local      2020-02-10`))
	})
})
