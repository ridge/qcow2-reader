package qcow2

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// QCOW2 reader
//
// Missing features:
// - extended L2 entries
// - zstd decompression
//
// Missing features that probably are not going to be implemented ever:
// - reading dirty/corrupted images
// - reading encrypted images
// - reading images with backing files
// - reading images with external data files
//
// QCOW2 spec: https://gitlab.com/qemu-project/qemu/-/blob/master/docs/interop/qcow2.txt
//
// File structure:
//
// QCOW2 header points to L1 table.
//
// L1 table consists of entries that contain pointers to L2 tables.
//
// L2 table consists of entries that contain pointers to cluster data
// and flags "cluster is all zeroes" and "compressed".
//
// Implementation notes:
//
// This reader reads and parses L1 table at the beginning. L2 tables are read
// and parsed on demand.

type qcow2Config struct {
	// size of one cluster of data
	clusterSize int

	// total amount of clusters in image
	nClusters int

	// L1 table contains pointers to L2 tables that contain pointers
	// to compressed clusters.
	l1Table []int64

	// Number of clusters in L2 table (size of L2 table in bytes / 8 (size of L2 entry))
	l2TableSize int

	// See Compressed Clusters Descriptor in qcow2.txt
	l2CompressedEntryHostClusterOffsetMask uint64
}

type qcow2Reader struct {
	image io.ReadSeeker

	qcow2Config

	// cluster currently being read
	currentCluster int

	// L2 table that corresponds to currentCluster
	currentL2Table []l2Entry

	// current cluster data, clusterSize-sized
	currentData []byte
	// read offset in current cluster data
	currentOffset int
}

const l1EntryOffsetMask = 0xfffffffffffe00 // bits 9-55

func parseL1Table(image io.ReadSeeker, offset int64, size int) ([]int64, error) {
	if _, err := image.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}

	buf := make([]byte, size*8, size*8)
	if _, err := io.ReadFull(image, buf); err != nil {
		return nil, err
	}

	var out []int64
	for i := 0; i < size; i++ {
		out = append(out, int64(binary.BigEndian.Uint64(buf[i*8:])&l1EntryOffsetMask))
	}
	return out, nil
}

const (
	incFeatDirtyBit             = 1 << 0
	incFeatCorruptBit           = 1 << 1
	incFeatExternalDataFileBit  = 1 << 2
	incFeatCompressionTypeBit   = 1 << 3
	incFeatExtendedL2EntriesBit = 1 << 4
	incFeatUnknownBits          = ^uint64(0b11111)

	compressionTypeZlib = 0
)

func parseHeaderAndL1(image io.ReadSeeker) (qcow2Config, error) {
	header := make([]byte, 72)
	if _, err := io.ReadFull(image, header); err != nil {
		return qcow2Config{}, err
	}

	if !bytes.Equal(header[0:4], []byte{'Q', 'F', 'I', 0xfb}) {
		return qcow2Config{}, errors.New("not a qcow2 file, wrong magic")
	}

	ver := binary.BigEndian.Uint32(header[4:8])
	if ver != 2 && ver != 3 {
		return qcow2Config{}, fmt.Errorf("version %d is not supported", ver)
	}

	backingFileNameOffset := binary.BigEndian.Uint64(header[8:16])
	if backingFileNameOffset != 0 {
		return qcow2Config{}, errors.New("backing file is not supported")
	}

	// skip backing file name size

	clusterBits := binary.BigEndian.Uint32(header[20:24])
	if clusterBits < 9 || clusterBits > 21 {
		return qcow2Config{}, fmt.Errorf("cluster size %d is not supported", 1<<clusterBits)
	}
	clusterSize := 1 << clusterBits

	virtualDiskSize := binary.BigEndian.Uint64(header[24:32])

	encryptionMethod := binary.BigEndian.Uint32(header[32:36])
	if encryptionMethod != 0 {
		return qcow2Config{}, errors.New("encryption is not supported")
	}

	l1TableSize := int(binary.BigEndian.Uint32(header[36:40]))
	l1TableOffset := int64(binary.BigEndian.Uint64(header[40:48]))

	// skip refcount table offset
	// skip refcount table clusters
	// skip num snapshots
	// skip snapshots offset

	if ver == 3 {
		v3Header := make([]byte, 32)
		if _, err := io.ReadFull(image, v3Header); err != nil {
			return qcow2Config{}, err
		}

		incompatibleFeatures := binary.BigEndian.Uint64(v3Header[0:8])
		if incompatibleFeatures&incFeatDirtyBit != 0 {
			return qcow2Config{}, errors.New("dirty bit set is not supported")
		}

		if incompatibleFeatures&incFeatCorruptBit != 0 {
			return qcow2Config{}, errors.New("corrupt bit set is not supported")
		}

		if incompatibleFeatures&incFeatExternalDataFileBit != 0 {
			return qcow2Config{}, errors.New("external data file is not supported")
		}

		hasNonDefaultCompression := incompatibleFeatures&incFeatCompressionTypeBit != 0

		if incompatibleFeatures&incFeatExtendedL2EntriesBit != 0 {
			return qcow2Config{}, errors.New("extended L2 entries are not supported")
		}

		if incompatibleFeatures&incFeatUnknownBits != 0 {
			return qcow2Config{}, fmt.Errorf("unknown incompatible features are not supported, got 0x%x", incompatibleFeatures&incFeatUnknownBits)
		}

		// skip compatible features
		// skip autoclear features
		// skip refcount entry order

		headerLength := binary.BigEndian.Uint32(v3Header[28:32])
		if headerLength%8 != 0 {
			return qcow2Config{}, errors.New("header length not aligned to 8 bytes is not supported")
		}

		// Protect the next make() from negative or huge sizes
		if headerLength < 104 {
			return qcow2Config{}, errors.New("header length must be at least 104 bytes")
		}
		if headerLength > 1000 {
			return qcow2Config{}, errors.New("header length > 1000 bytes is likely corrupted")
		}

		additionalFields := make([]byte, headerLength-104)
		if _, err := io.ReadFull(image, additionalFields); err != nil {
			return qcow2Config{}, err
		}

		if hasNonDefaultCompression {
			if headerLength < 108 {
				return qcow2Config{}, fmt.Errorf("too short header for non-default compression expect header length, expected >=108, got %d", headerLength)
			}

			compressionType := binary.BigEndian.Uint32(v3Header[0:4])
			if compressionType != compressionTypeZlib {
				return qcow2Config{}, fmt.Errorf("compression type %d is not supported", compressionType)
			}
		}

		// skip padding & header extensions
	}

	l1Table, err := parseL1Table(image, l1TableOffset, l1TableSize)
	if err != nil {
		return qcow2Config{}, fmt.Errorf("failed to read L1 table: %w", err)
	}

	l2TableSize := clusterSize / 8

	return qcow2Config{
		clusterSize: clusterSize,
		nClusters:   int(virtualDiskSize) / clusterSize,
		l2TableSize: l2TableSize,
		// See Compressed Clusters Descriptor in qcow2.txt
		l2CompressedEntryHostClusterOffsetMask: 1<<(70-clusterBits) - 1,

		l1Table: l1Table,
	}, nil
}

type l2Entry struct {
	offset     int64
	compressed bool
	allZeroes  bool
}

const (
	l2EntryCompressedBit = 1 << 62

	l2EntryNoncompressedAllZeroesBit = 1 << 0
	l2EntryNoncompressedOffsetMask   = 0xfffffffffffe00 // bits 9-55
)

func parseL2Table(r *qcow2Reader, l2TableIdx int) error {
	if r.l1Table[l2TableIdx] == 0 {
		for i := 0; i < r.l2TableSize; i++ {
			r.currentL2Table[i] = l2Entry{allZeroes: true}
		}
		return nil
	}

	if _, err := r.image.Seek(r.l1Table[l2TableIdx], io.SeekStart); err != nil {
		return err
	}

	// last L2 table may be shorter than l2TableSize
	l2Entries := min(r.l2TableSize, r.nClusters-r.currentCluster)

	buf := make([]byte, 8*l2Entries, 8*l2Entries)
	if _, err := io.ReadFull(r.image, buf); err != nil {
		return err
	}

	for i := 0; i < l2Entries; i++ {
		entry := binary.BigEndian.Uint64(buf[i*8:])

		if entry&l2EntryCompressedBit != 0 {
			offset := int64(entry & r.l2CompressedEntryHostClusterOffsetMask)
			r.currentL2Table[i] = l2Entry{offset: offset, compressed: true}
		} else {
			if entry&l2EntryNoncompressedAllZeroesBit != 0 {
				r.currentL2Table[i] = l2Entry{allZeroes: true}
			} else {
				r.currentL2Table[i] = l2Entry{offset: int64(entry & l2EntryNoncompressedOffsetMask)}
			}
		}
	}

	return nil
}

func fillNextCluster(r *qcow2Reader) error {
	r.currentCluster++
	if r.currentCluster == r.nClusters {
		return io.EOF
	}

	// If reader has moved from one L2 table to another, parse the new table
	if r.currentCluster%r.l2TableSize == 0 {
		if err := parseL2Table(r, r.currentCluster/r.l2TableSize); err != nil {
			return err
		}
	}

	entry := r.currentL2Table[r.currentCluster%r.l2TableSize]
	switch {
	case entry.allZeroes:
		for i := 0; i < r.clusterSize; i++ {
			r.currentData[i] = 0
		}
	case entry.compressed:
		if _, err := r.image.Seek(entry.offset, io.SeekStart); err != nil {
			return err
		}
		flateReader := flate.NewReader(r.image)
		defer flateReader.Close()

		if _, err := io.ReadFull(flateReader, r.currentData); err != nil {
			return err
		}
	default:
		if _, err := r.image.Seek(entry.offset, io.SeekStart); err != nil {
			return err
		}
		if _, err := io.ReadFull(r.image, r.currentData); err != nil {
			return err
		}
	}

	r.currentOffset = 0
	return nil
}

func (r *qcow2Reader) Read(p []byte) (retN int, retErr error) {
	if r.currentOffset >= r.clusterSize {
		if err := fillNextCluster(r); err != nil {
			return 0, err
		}
	}

	// Some data is available. We use the convention that Read()
	// can return less data than requested to simplify implementation:
	// data from only one cluster is returned from one Read() call.

	n := min(r.clusterSize-r.currentOffset, len(p))
	copy(p, r.currentData[r.currentOffset:r.currentOffset+n])
	r.currentOffset += n
	return n, nil
}

// NewReader takes a QCOW2 image and produces reader with raw data.
func NewReader(image io.ReadSeeker) (io.Reader, error) {
	config, err := parseHeaderAndL1(image)
	if err != nil {
		return nil, err
	}

	return &qcow2Reader{
		image:       image,
		qcow2Config: config,
		// Allocate buffers
		currentData:    make([]byte, config.clusterSize, config.clusterSize),
		currentL2Table: make([]l2Entry, config.l2TableSize, config.l2TableSize),

		// Prepare state to read first L2 table and first cluster on Read()
		currentCluster: -1,
		currentOffset:  config.clusterSize,
	}, nil
}
