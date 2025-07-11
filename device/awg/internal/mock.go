package internal

type mockGenerator struct {
	size int
}

func NewMockGenerator(size int) mockGenerator {
	return mockGenerator{size: size}
}

func (m mockGenerator) Generate() []byte {
	return make([]byte, m.size)
}

func (m mockGenerator) Size() int {
	return m.size
}

func (m mockGenerator) Name() string {
	return "mock"
}

type mockByteGenerator struct {
	data []byte
}

func NewMockByteGenerator(data []byte) mockByteGenerator {
	return mockByteGenerator{data: data}
}

func (bg mockByteGenerator) Generate() []byte {
	return bg.data
}

func (bg mockByteGenerator) Size() int {
	return len(bg.data)
}
