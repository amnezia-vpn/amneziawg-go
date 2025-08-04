package awg

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewBytesGenerator(t *testing.T) {
	t.Parallel()

	type args struct {
		param string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr error
	}{
		{
			name: "empty",
			args: args{
				param: "",
			},
			wantErr: fmt.Errorf("not correct hex"),
		},
		{
			name: "wrong start",
			args: args{
				param: "123456",
			},
			wantErr: fmt.Errorf("not correct hex"),
		},
		{
			name: "not only hex value with X",
			args: args{
				param: "0X12345q",
			},
			wantErr: fmt.Errorf("not correct hex"),
		},
		{
			name: "not only hex value with x",
			args: args{
				param: "0x12345q",
			},
			wantErr: fmt.Errorf("not correct hex"),
		},
		{
			name: "valid hex",
			args: args{
				param: "0xf6ab3267fa",
			},
			want: []byte{0xf6, 0xab, 0x32, 0x67, 0xfa},
		},
		{
			name: "valid hex with odd length",
			args: args{
				param: "0xfab3267fa",
			},
			want: []byte{0xf, 0xab, 0x32, 0x67, 0xfa},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := newBytesGenerator(tt.args.param)

			if tt.wantErr != nil {
				require.ErrorAs(t, err, &tt.wantErr)
				require.Nil(t, got)
				return
			}

			require.Nil(t, err)
			require.NotNil(t, got)

			gotValues := got.Generate()
			require.Equal(t, tt.want, gotValues)
		})
	}
}

func TestNewRandomBytesGenerator(t *testing.T) {
	t.Parallel()

	type args struct {
		param string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "empty",
			args: args{
				param: "",
			},
			wantErr: fmt.Errorf("parse int"),
		},
		{
			name: "not an int",
			args: args{
				param: "x",
			},
			wantErr: fmt.Errorf("parse int"),
		},
		{
			name: "too large",
			args: args{
				param: "1001",
			},
			wantErr: fmt.Errorf("random packet size must be less than 1000"),
		},
		{
			name: "valid",
			args: args{
				param: "12",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := newRandomBytesGenerator(tt.args.param)
			if tt.wantErr != nil {
				require.ErrorAs(t, err, &tt.wantErr)
				require.Nil(t, got)
				return
			}

			require.Nil(t, err)
			require.NotNil(t, got)
			first := got.Generate()

			second := got.Generate()
			require.NotEqual(t, first, second)
		})
	}
}

func TestNewRandomASCIIGenerator(t *testing.T) {
	t.Parallel()

	type args struct {
		param string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "empty",
			args: args{
				param: "",
			},
			wantErr: fmt.Errorf("parse int"),
		},
		{
			name: "not an int",
			args: args{
				param: "x",
			},
			wantErr: fmt.Errorf("parse int"),
		},
		{
			name: "too large",
			args: args{
				param: "1001",
			},
			wantErr: fmt.Errorf("random packet size must be less than 1000"),
		},
		{
			name: "valid",
			args: args{
				param: "12",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := newRandomASCIIGenerator(tt.args.param)
			if tt.wantErr != nil {
				require.ErrorAs(t, err, &tt.wantErr)
				require.Nil(t, got)
				return
			}

			require.Nil(t, err)
			require.NotNil(t, got)
			first := got.Generate()

			second := got.Generate()
			require.NotEqual(t, first, second)
		})
	}
}

func TestNewRandomDigitGenerator(t *testing.T) {
	t.Parallel()

	type args struct {
		param string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "empty",
			args: args{
				param: "",
			},
			wantErr: fmt.Errorf("parse int"),
		},
		{
			name: "not an int",
			args: args{
				param: "x",
			},
			wantErr: fmt.Errorf("parse int"),
		},
		{
			name: "too large",
			args: args{
				param: "1001",
			},
			wantErr: fmt.Errorf("random packet size must be less than 1000"),
		},
		{
			name: "valid",
			args: args{
				param: "12",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := newRandomDigitGenerator(tt.args.param)
			if tt.wantErr != nil {
				require.ErrorAs(t, err, &tt.wantErr)
				require.Nil(t, got)
				return
			}

			require.Nil(t, err)
			require.NotNil(t, got)
			first := got.Generate()

			second := got.Generate()
			require.NotEqual(t, first, second)
		})
	}
}

func TestPacketCounterGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		param   string
		wantErr bool
	}{
		{
			name:    "Valid empty param",
			param:   "",
			wantErr: false,
		},
		{
			name:    "Invalid non-empty param",
			param:   "anything",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gen, err := newPacketCounterGenerator(tc.param)
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, 8, gen.Size())

			// Reset counter to known value for test
			initialCount := uint64(42)
			PacketCounter.Store(initialCount)

			output := gen.Generate()
			require.Equal(t, 8, len(output))

			// Verify counter value in output
			counterValue := binary.BigEndian.Uint64(output)
			require.Equal(t, initialCount, counterValue)

			// Increment counter and verify change
			PacketCounter.Add(1)
			output = gen.Generate()
			counterValue = binary.BigEndian.Uint64(output)
			require.Equal(t, initialCount+1, counterValue)
		})
	}
}
