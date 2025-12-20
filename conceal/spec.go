package conceal

import (
	"fmt"
	"strings"
)

func (o Obfs) Spec() string {
	var builder strings.Builder
	for _, obf := range o {
		builder.WriteString(obf.Spec())
	}
	return builder.String()
}

func (o *timestampObf) Spec() string {
	return "<t>"
}

func (o *randDigitObf) Spec() string {
	return fmt.Sprintf("<rd %d>", o.length)
}

func (o *randCharObf) Spec() string {
	return fmt.Sprintf("<rc %d>", o.length)
}

func (o *randObf) Spec() string {
	return fmt.Sprintf("<r %d>", o.length)
}

func (o *dataSizeObf) Spec() string {
	return fmt.Sprintf("<dz %d>", o.length)
}

func (o *dataObf) Spec() string {
	return "<d>"
}

func (o *dataStringObf) Spec() string {
	return "<dz>"
}

func (o *bytesObf) Spec() string {
	return fmt.Sprintf("<b 0x%x>", o.data)
}
