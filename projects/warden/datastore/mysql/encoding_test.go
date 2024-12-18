package datastore

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncLenInt(t *testing.T) {
	tests := []struct {
		value   uint64
		encoded []byte
	}{
		{0x00, []byte{0x00}},
		{0x0a, []byte{0x0a}},
		{0xfa, []byte{0xfa}},
		{0xfb, []byte{0xfc, 0xfb, 0x00}},
		{0xfc, []byte{0xfc, 0xfc, 0x00}},
		{0xfd, []byte{0xfc, 0xfd, 0x00}},
		{0xfe, []byte{0xfc, 0xfe, 0x00}},
		{0xff, []byte{0xfc, 0xff, 0x00}},
		{0x0100, []byte{0xfc, 0x00, 0x01}},
		{0x876a, []byte{0xfc, 0x6a, 0x87}},
		{0xffff, []byte{0xfc, 0xff, 0xff}},
		{0x010000, []byte{0xfd, 0x00, 0x00, 0x01}},
		{0xabcdef, []byte{0xfd, 0xef, 0xcd, 0xab}},
		{0xffffff, []byte{0xfd, 0xff, 0xff, 0xff}},
		{0x01000000, []byte{0xfe, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}},
		{0xa0a1a2a3a4a5a6a7, []byte{0xfe, 0xa7, 0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1, 0xa0}},
	}
	for _, test := range tests {
		// Check lenEncIntSize first.
		if got := lenEncIntSize(test.value); got != len(test.encoded) {
			t.Errorf("lenEncIntSize returned %v but expected %v for %x", got, len(test.encoded), test.value)
		}

		// Check successful encoding.
		data := make([]byte, len(test.encoded))
		pos := writeLenEncInt(data, 0, test.value)
		assert.Equal(t, len(test.encoded), pos, "unexpected pos %v after writeLenEncInt(%x), expected %v", pos, test.value, len(test.encoded))
		assert.True(t, bytes.Equal(data, test.encoded), "unexpected encoded value for %x, got %v expected %v", test.value, data, test.encoded)

		// Check successful encoding with offset.
		data = make([]byte, len(test.encoded)+1)
		pos = writeLenEncInt(data, 1, test.value)
		assert.Equal(t, len(test.encoded)+1, pos, "unexpected pos %v after writeLenEncInt(%x, 1), expected %v", pos, test.value, len(test.encoded)+1)
		assert.True(t, bytes.Equal(data[1:], test.encoded), "unexpected encoded value for %x, got %v expected %v", test.value, data, test.encoded)

		// Check successful decoding.
		got, pos, ok := readLenEncInt(test.encoded, 0)
		if !ok || got != test.value || pos != len(test.encoded) {
			t.Errorf("readLenEncInt returned %x/%v/%v but expected %x/%v/%v", got, pos, ok, test.value, len(test.encoded), true)
		}

		// Check failed decoding.
		_, _, ok = readLenEncInt(test.encoded[:len(test.encoded)-1], 0)
		assert.False(t, ok, "readLenEncInt returned ok=true for shorter value %x", test.value)
	}
}

func TestEncUint16(t *testing.T) {
	data := make([]byte, 10)

	val16 := uint16(0xabcd)

	if got := writeUint16(data, 2, val16); got != 4 {
		t.Errorf("writeUint16 returned %v but expected 4", got)
	}

	if data[2] != 0xcd || data[3] != 0xab {
		t.Errorf("writeUint16 returned bad result: %v", data)
	}

	got16, pos, ok := readUint16(data, 2)
	if !ok || got16 != val16 || pos != 4 {
		t.Errorf("readUint16 returned %v/%v/%v but expected %v/%v/%v", got16, pos, ok, val16, 4, true)
	}

	_, _, ok = readUint16(data, 9)
	assert.False(t, ok, "readUint16 returned ok=true for shorter value")
}

func TestEncBytes(t *testing.T) {
	data := make([]byte, 10)

	if got := writeByte(data, 5, 0xab); got != 6 || data[5] != 0xab {
		t.Errorf("writeByte returned bad result: %v %v", got, data[5])
	}

	got, pos, ok := readByte(data, 5)
	if !ok || got != 0xab || pos != 6 {
		t.Errorf("readByte returned %v/%v/%v but expected %v/%v/%v", got, pos, ok, 0xab, 6, true)
	}

	_, _, ok = readByte(data, 10)
	assert.False(t, ok, "readByte returned ok=true for shorter value")

	b, pos, ok := readBytes(data, 5, 2)
	expected := []byte{0xab, 0x00}
	if !ok || !bytes.Equal(b, expected) || pos != 7 {
		t.Errorf("readBytes returned %v/%v/%v but expected %v/%v/%v", b, pos, ok, expected, 7, true)
	}

	_, _, ok = readBytes(data, 9, 2)
	assert.False(t, ok, "readBytes returned ok=true for shorter value")
}

func TestEncUint32(t *testing.T) {
	data := make([]byte, 10)

	val32 := uint32(0xabcdef10)

	if got := writeUint32(data, 2, val32); got != 6 {
		t.Errorf("writeUint32 returned %v but expected 6", got)
	}

	if data[2] != 0x10 || data[3] != 0xef || data[4] != 0xcd || data[5] != 0xab {
		t.Errorf("writeUint32 returned bad result: %v", data)
	}

	got32, pos, ok := readUint32(data, 2)
	if !ok || got32 != val32 || pos != 6 {
		t.Errorf("readUint32 returned %v/%v/%v but expected %v/%v/%v", got32, pos, ok, val32, 6, true)
	}

	_, _, ok = readUint32(data, 7)
	assert.False(t, ok, "readUint32 returned ok=true for shorter value")
}

func TestEncUint64(t *testing.T) {
	data := make([]byte, 10)

	val64 := uint64(0xabcdef1011121314)

	if got := writeUint64(data, 1, val64); got != 9 {
		t.Errorf("writeUint64 returned %v but expected 9", got)
	}

	if data[1] != 0x14 || data[2] != 0x13 || data[3] != 0x12 || data[4] != 0x11 ||
		data[5] != 0x10 || data[6] != 0xef || data[7] != 0xcd || data[8] != 0xab {
		t.Errorf("writeUint64 returned bad result: %v", data)
	}

	got64, pos, ok := readUint64(data, 1)
	if !ok || got64 != val64 || pos != 9 {
		t.Errorf("readUint64 returned %v/%v/%v but expected %v/%v/%v", got64, pos, ok, val64, 6, true)
	}

	_, _, ok = readUint64(data, 7)
	assert.False(t, ok, "readUint64 returned ok=true for shorter value")
}

func TestEncString(t *testing.T) {
	tests := []struct {
		value       string
		lenEncoded  []byte
		nullEncoded []byte
		eofEncoded  []byte
	}{
		{
			"",
			[]byte{0x00},
			[]byte{0x00},
			[]byte{},
		},
		{
			"a",
			[]byte{0x01, 'a'},
			[]byte{'a', 0x00},
			[]byte{'a'},
		},
		{
			"0123456789",
			[]byte{0x0a, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'},
			[]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 0x00},
			[]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'},
		},
	}
	for _, test := range tests {
		// len encoded tests.

		// Check lenEncStringSize first.
		if got := lenEncStringSize(test.value); got != len(test.lenEncoded) {
			t.Errorf("lenEncStringSize returned %v but expected %v for %v", got, len(test.lenEncoded), test.value)
		}

		// Check lenNullString
		if got := lenNullString(test.value); got != len(test.nullEncoded) {
			t.Errorf("lenNullString returned %v but expected %v for %v", got, len(test.nullEncoded), test.value)
		}

		// Check lenEOFString
		if got := lenEOFString(test.value); got != len(test.eofEncoded) {
			t.Errorf("lenNullString returned %v but expected %v for %v", got, len(test.eofEncoded), test.value)
		}

		// Check successful encoding.
		data := make([]byte, len(test.lenEncoded))
		pos := writeLenEncString(data, 0, test.value)
		assert.Equal(t, len(test.lenEncoded), pos, "unexpected pos %v after writeLenEncString(%v), expected %v", pos, test.value, len(test.lenEncoded))
		assert.True(t, bytes.Equal(data, test.lenEncoded), "unexpected lenEncoded value for %v, got %v expected %v", test.value, data, test.lenEncoded)

		// Check successful encoding with offset.
		data = make([]byte, len(test.lenEncoded)+1)
		pos = writeLenEncString(data, 1, test.value)
		assert.Equal(t, len(test.lenEncoded)+1, pos, "unexpected pos %v after writeLenEncString(%v, 1), expected %v", pos, test.value, len(test.lenEncoded)+1)
		assert.True(t, bytes.Equal(data[1:], test.lenEncoded), "unexpected lenEncoded value for %v, got %v expected %v", test.value, data[1:], test.lenEncoded)

		// Check successful decoding as string.
		got, pos, ok := readLenEncString(test.lenEncoded, 0)
		if !ok || got != test.value || pos != len(test.lenEncoded) {
			t.Errorf("readLenEncString returned %v/%v/%v but expected %v/%v/%v", got, pos, ok, test.value, len(test.lenEncoded), true)
		}

		// Check failed decoding with shorter data.
		_, _, ok = readLenEncString(test.lenEncoded[:len(test.lenEncoded)-1], 0)
		assert.False(t, ok, "readLenEncString returned ok=true for shorter value %v", test.value)

		// Check failed decoding with no data.
		_, _, ok = readLenEncString([]byte{}, 0)
		assert.False(t, ok, "readLenEncString returned ok=true for empty value %v", test.value)

		// Check successful skipping as string.
		pos, ok = skipLenEncString(test.lenEncoded, 0)
		if !ok || pos != len(test.lenEncoded) {
			t.Errorf("skipLenEncString returned %v/%v but expected %v/%v", pos, ok, len(test.lenEncoded), true)
		}

		// Check failed skipping with shorter data.
		_, ok = skipLenEncString(test.lenEncoded[:len(test.lenEncoded)-1], 0)
		assert.False(t, ok, "skipLenEncString returned ok=true for shorter value %v", test.value)

		// Check failed skipping with no data.
		_, ok = skipLenEncString([]byte{}, 0)
		assert.False(t, ok, "skipLenEncString returned ok=true for empty value %v", test.value)

		// Check successful decoding as bytes.
		gotb, pos, ok := readLenEncStringAsBytes(test.lenEncoded, 0)
		if !ok || string(gotb) != test.value || pos != len(test.lenEncoded) {
			t.Errorf("readLenEncString returned %v/%v/%v but expected %v/%v/%v", gotb, pos, ok, test.value, len(test.lenEncoded), true)
		}

		// Check failed decoding as bytes with shorter data.
		_, _, ok = readLenEncStringAsBytes(test.lenEncoded[:len(test.lenEncoded)-1], 0)
		assert.False(t, ok, "readLenEncStringAsBytes returned ok=true for shorter value %v", test.value)

		// Check failed decoding as bytes with no data.
		_, _, ok = readLenEncStringAsBytes([]byte{}, 0)
		assert.False(t, ok, "readLenEncStringAsBytes returned ok=true for empty value %v", test.value)

		// Check successful decoding as bytes.
		gotbcopy, posCopy, ok := readLenEncStringAsBytesCopy(test.lenEncoded, 0)
		if !ok || string(gotb) != test.value || pos != len(test.lenEncoded) {
			t.Errorf("readLenEncString returned %v/%v/%v but expected %v/%v/%v", gotbcopy, posCopy, ok, test.value, len(test.lenEncoded), true)
		}

		// Check failed decoding as bytes with shorter data.
		_, _, ok = readLenEncStringAsBytesCopy(test.lenEncoded[:len(test.lenEncoded)-1], 0)
		assert.False(t, ok, "readLenEncStringAsBytes returned ok=true for shorter value %v", test.value)

		// Check failed decoding as bytes with no data.
		_, _, ok = readLenEncStringAsBytesCopy([]byte{}, 0)
		assert.False(t, ok, "readLenEncStringAsBytes returned ok=true for empty value %v", test.value)

		// null encoded tests.

		// Check successful encoding.
		data = make([]byte, len(test.nullEncoded))
		pos = writeNullString(data, 0, test.value)
		assert.Equal(t, len(test.nullEncoded), pos, "unexpected pos %v after writeNullString(%v), expected %v", pos, test.value, len(test.nullEncoded))
		assert.True(t, bytes.Equal(data, test.nullEncoded), "unexpected nullEncoded value for %v, got %v expected %v", test.value, data, test.nullEncoded)

		// Check successful decoding.
		got, pos, ok = readNullString(test.nullEncoded, 0)
		if !ok || got != test.value || pos != len(test.nullEncoded) {
			t.Errorf("readNullString returned %v/%v/%v but expected %v/%v/%v", got, pos, ok, test.value, len(test.nullEncoded), true)
		}

		// Check failed decoding with shorter data.
		_, _, ok = readNullString(test.nullEncoded[:len(test.nullEncoded)-1], 0)
		assert.False(t, ok, "readNullString returned ok=true for shorter value %v", test.value)

		// EOF encoded tests.

		// Check successful encoding.
		data = make([]byte, len(test.eofEncoded))
		pos = writeEOFString(data, 0, test.value)
		assert.Equal(t, len(test.eofEncoded), pos, "unexpected pos %v after writeEOFString(%v), expected %v", pos, test.value, len(test.eofEncoded))
		assert.True(t, bytes.Equal(data, test.eofEncoded[:len(test.eofEncoded)]), "unexpected eofEncoded value for %v, got %v expected %v", test.value, data, test.eofEncoded)

		// Check successful decoding.
		got, pos, ok = readEOFString(test.eofEncoded, 0)
		if !ok || got != test.value || pos != len(test.eofEncoded) {
			t.Errorf("readEOFString returned %v/%v/%v but expected %v/%v/%v", got, pos, ok, test.value, len(test.eofEncoded), true)
		}
	}
}

func TestWriteZeroes(t *testing.T) {
	buf := make([]byte, 32)
	resetBuf := func() {
		t.Helper()
		for i := range len(buf) {
			buf[i] = 'f'
		}
	}

	allMatch := func(b []byte, c byte) bool {
		for i := range b {
			if b[i] != c {
				return false
			}
		}
		return true
	}

	t.Run("0-offset", func(t *testing.T) {
		for _, size := range []int{4, 10, 23, 24, 25, 26, 27} {
			resetBuf()
			pos := writeZeroes(buf, 0, size)
			assert.Equal(t, size, pos, "expected to advance pos to %d, got %d", size, pos)
			assert.True(t, allMatch(buf[:pos], 0), "buffer should be zeroes, %v", buf[:pos])
			assert.True(t, allMatch(buf[pos:], 'f'), "buffer should be dirty, %v", buf[pos:])
		}
	})

	t.Run("3-offset", func(t *testing.T) {
		offset := 3
		for _, size := range []int{4, 10, 23, 24, 25, 26, 27} {
			resetBuf()
			pos := writeZeroes(buf, offset, size)
			assert.Equal(t, offset+size, pos, "expected to advance pos to %d, got %d", offset+size, pos)
			assert.True(t, allMatch(buf[:offset], 'f'), "buffer should be dirty, %v", buf[offset:pos])
			assert.True(t, allMatch(buf[offset:pos], 0), "buffer should be zeroes, %v", buf[:pos])
			assert.True(t, allMatch(buf[pos:], 'f'), "buffer should be dirty, %v", buf[pos:])
		}
	})
}

func TestEncGtidData(t *testing.T) {
	tests := []struct {
		data   string
		header []byte
	}{
		{"", []byte{0x04, 0x03, 0x02, 0x00, 0x00}},
		{"xxx", []byte{0x07, 0x03, 0x05, 0x00, 0x03}},
		{strings.Repeat("x", 256), []byte{
			/* 264 */ 0xfc, 0x08, 0x01,
			/* constant */ 0x03,
			/* 260 */ 0xfc, 0x04, 0x01,
			/* constant */ 0x00,
			/* 256 */ 0xfc, 0x00, 0x01,
		}},
	}
	for _, test := range tests {
		got := encGtidData(test.data)
		assert.Equal(t, append(test.header, test.data...), got)
	}
}

func BenchmarkEncWriteInt(b *testing.B) {
	buf := make([]byte, 16)

	b.Run("16-bit", func(b *testing.B) {
		value := uint16(0x0100)
		for range b.N {
			_ = writeUint16(buf, 0, value)
		}
	})

	b.Run("16-bit-lenencoded", func(b *testing.B) {
		value := uint64(0x0100)
		for range b.N {
			_ = writeLenEncInt(buf, 0, value)
		}
	})

	b.Run("24-bit-lenencoded", func(b *testing.B) {
		value := uint64(0xabcdef)
		for range b.N {
			_ = writeLenEncInt(buf, 0, value)
		}
	})

	b.Run("32-bit", func(b *testing.B) {
		value := uint32(0xabcdef)
		for range b.N {
			_ = writeUint32(buf, 0, value)
		}
	})

	b.Run("64-bit", func(b *testing.B) {
		value := uint64(0xa0a1a2a3a4a5a6a7)
		for range b.N {
			_ = writeUint64(buf, 0, value)
		}
	})

	b.Run("64-bit-lenencoded", func(b *testing.B) {
		value := uint64(0xa0a1a2a3a4a5a6a7)
		for range b.N {
			_ = writeLenEncInt(buf, 0, value)
		}
	})
}

func BenchmarkEncWriteZeroes(b *testing.B) {
	buf := make([]byte, 128)

	b.Run("4-bytes", func(b *testing.B) {
		for range b.N {
			_ = writeZeroes(buf, 16, 4)
		}
	})

	b.Run("10-bytes", func(b *testing.B) {
		for range b.N {
			_ = writeZeroes(buf, 16, 10)
		}
	})

	b.Run("23-bytes", func(b *testing.B) {
		for range b.N {
			_ = writeZeroes(buf, 16, 23)
		}
	})

	b.Run("55-bytes", func(b *testing.B) {
		for range b.N {
			_ = writeZeroes(buf, 16, 55)
		}
	})
}

func BenchmarkEncReadInt(b *testing.B) {
	b.Run("16-bit", func(b *testing.B) {
		data := []byte{0xfc, 0xfb, 0x00}
		for range b.N {
			_, _, _ = readLenEncInt(data, 0)
		}
	})

	b.Run("24-bit", func(b *testing.B) {
		data := []byte{0xfd, 0x00, 0x00, 0x01}
		for range b.N {
			_, _, _ = readLenEncInt(data, 0)
		}
	})

	b.Run("64-bit", func(b *testing.B) {
		data := []byte{0xfe, 0xa7, 0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1, 0xa0}
		for range b.N {
			_, _, _ = readLenEncInt(data, 0)
		}
	})
}

func BenchmarkEncGtidData(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		_ = encGtidData("xxx")
	}
}
