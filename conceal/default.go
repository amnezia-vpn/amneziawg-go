package conceal

func DefaultSizedPayloadObfs() Obfs {
	return Obfs{
		&dataSizeObf{length: 4},
		&dataObf{},
	}
}
