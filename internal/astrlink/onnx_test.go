package astrlink

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func pbVarint(v uint64) []byte {
	var b [10]byte
	n := binary.PutUvarint(b[:], v)
	return append([]byte(nil), b[:n]...)
}

func pbKey(field, wire int) []byte {
	return pbVarint(uint64(field<<3 | wire))
}

func pbUint(field int, v uint64) []byte {
	return append(pbKey(field, 0), pbVarint(v)...)
}

func pbBytes(field int, data []byte) []byte {
	out := pbKey(field, 2)
	out = append(out, pbVarint(uint64(len(data)))...)
	return append(out, data...)
}

func tensorMsg(name string, dims []int64, dtype int, raw []byte) []byte {
	var b []byte
	for _, d := range dims {
		b = append(b, pbUint(1, uint64(d))...)
	}
	b = append(b, pbUint(2, uint64(dtype))...)
	b = append(b, pbBytes(8, []byte(name))...)
	b = append(b, pbBytes(9, raw)...)
	return b
}

func floatTensorMsg(name string, values []float32) []byte {
	raw := make([]byte, 4*len(values))
	for i, v := range values {
		binary.LittleEndian.PutUint32(raw[4*i:], math.Float32bits(v))
	}
	var b []byte
	b = append(b, pbUint(1, uint64(len(values)))...)
	b = append(b, pbUint(2, tFloat)...)
	b = append(b, pbBytes(4, raw)...) // packed float_data
	b = append(b, pbBytes(8, []byte(name))...)
	return b
}

func externalTensorMsg(name string, dims []int64, dtype, length int, location string) []byte {
	var entry []byte
	entry = append(entry, pbBytes(1, []byte("location"))...)
	entry = append(entry, pbBytes(2, []byte(location))...)
	var lengthEntry []byte
	lengthEntry = append(lengthEntry, pbBytes(1, []byte("length"))...)
	lengthEntry = append(lengthEntry, pbBytes(2, []byte(itoa(length)))...)
	var offsetEntry []byte
	offsetEntry = append(offsetEntry, pbBytes(1, []byte("offset"))...)
	offsetEntry = append(offsetEntry, pbBytes(2, []byte("1"))...)

	var b []byte
	for _, d := range dims {
		b = append(b, pbUint(1, uint64(d))...)
	}
	b = append(b, pbUint(2, uint64(dtype))...)
	b = append(b, pbBytes(8, []byte(name))...)
	b = append(b, pbBytes(13, entry)...)
	b = append(b, pbBytes(13, offsetEntry)...)
	b = append(b, pbBytes(13, lengthEntry)...)
	b = append(b, pbUint(14, 1)...) // data_location = external
	return b
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

func modelProto(tensors ...[]byte) []byte {
	var graph []byte
	for _, t := range tensors {
		graph = append(graph, pbBytes(5, t)...)
	}
	return pbBytes(7, graph)
}

func TestReadONNXInitializers(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), []byte("xabcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	model := modelProto(
		tensorMsg("w_int8", []int64{2, 2}, tInt8, []byte{1, 2, 0xff, 4}),
		externalTensorMsg("ext", []int64{2}, tInt8, 2, "data.bin"),
		floatTensorMsg("floats", []float32{1.5, -2.25}),
	)
	path := filepath.Join(dir, "model_int8.onnx")
	if err := os.WriteFile(path, model, 0o600); err != nil {
		t.Fatal(err)
	}
	ts, err := readONNX(path)
	if err != nil {
		t.Fatal(err)
	}
	w := ts["w_int8"]
	if w == nil {
		t.Fatal("w_int8 missing")
	}
	if w.dtype != tInt8 || len(w.dims) != 2 || w.dims[0] != 2 || w.dims[1] != 2 {
		t.Fatalf("w_int8 meta = %d %v", w.dtype, w.dims)
	}
	if got := w.raw; len(got) != 4 || got[0] != 1 || got[2] != 0xff {
		t.Fatalf("w_int8 raw = %v", got)
	}
	ext := ts["ext"]
	if ext == nil {
		t.Fatal("ext missing")
	}
	if string(ext.raw) != "ab" {
		t.Fatalf("ext raw = %q, want ab (offset 1, length 2)", ext.raw)
	}
	f := ts["floats"]
	if f == nil {
		t.Fatal("floats missing")
	}
	got := f.floats()
	if len(got) != 2 || got[0] != 1.5 || got[1] != -2.25 {
		t.Fatalf("floats = %v", got)
	}
}

func TestReadONNXNoGraph(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.onnx")
	if err := os.WriteFile(path, pbUint(1, 3), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readONNX(path); err == nil {
		t.Fatal("readONNX accepted a model without a graph")
	}
}

func TestReadONNXBadWireType(t *testing.T) {
	// field 7, wire type 3 (start group) is not supported.
	path := filepath.Join(t.TempDir(), "bad.onnx")
	if err := os.WriteFile(path, pbKey(7, 3), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readONNX(path); err == nil {
		t.Fatal("readONNX accepted a bad wire type")
	}
}
