package qcow2

import (
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

// Use more than 64 clusters to test L2 table reloading.
// With 512-byte clusters, L2 table contains 64 entries.
const rawSize = 65 * 512

func makeQcow2(t *testing.T, name string, data []byte) {
	require.NoError(t, os.WriteFile("testdata/"+name+".tmp", data, 0o644))
	require.NoError(t, exec.Command("qemu-img", "convert", "-c", "-f", "raw", "-O", "qcow2", "-o", "cluster_size=512",
		"testdata/"+name+".tmp", "testdata/"+name+".qcow2").Run())
	require.NoError(t, os.Remove("testdata/"+name+".tmp"))
}

// https://github.com/dominikh/go-tools/issues/633
var skip = func(t *testing.T) {
	t.SkipNow()
}

func TestCreateTestFile(t *testing.T) {
	// This test was used to create test file for TestParse().
	// Do not reenable unless really needed, as it requires qemu-img.
	skip(t)

	buf := make([]byte, rawSize)
	for i := 0; i < len(buf)/2; i++ {
		// Pattern is aligned on cluster boundaries, so we can test
		// reused clusters
		buf[2*i] = byte(i / 256)
		buf[2*i+1] = byte(i % 256)
	}
	makeQcow2(t, "small", buf)
}

func TestParse(t *testing.T) {
	fh, err := os.Open("testdata/small.qcow2")
	require.NoError(t, err)
	defer fh.Close()

	qcow2Reader, err := NewReader(fh)
	require.NoError(t, err)

	buf, err := io.ReadAll(qcow2Reader)
	require.NoError(t, err)

	require.Equal(t, rawSize, len(buf))
	for i := 0; i < len(buf)/2; i++ {
		require.Equal(t, byte(i/256), buf[2*i])
		require.Equal(t, byte(i%256), buf[2*i+1])
	}
}

func TestCreateEmptyFile(t *testing.T) {
	// This test was used to create test file for TestParseEmpty()
	// Do not reenable unless really needed, as it requires qemu-img.
	skip(t)

	makeQcow2(t, "empty", make([]byte, 1024*1024))
}

// Test L1 entries with zero offset ("No L2 table, all clusters are zero")
func TestParseEmpty(t *testing.T) {
	fh, err := os.Open("testdata/empty.qcow2")
	require.NoError(t, err)
	defer fh.Close()

	qcow2Reader, err := NewReader(fh)
	require.NoError(t, err)

	buf, err := io.ReadAll(qcow2Reader)
	require.NoError(t, err)

	require.Equal(t, 1024*1024, len(buf))
	for i := 0; i < len(buf); i++ {
		require.Equal(t, byte(0), buf[i])
	}
}
