package output

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"time"
)

type BundleItem struct {
	Path string
	Name string // name inside tar
}

func WriteBundleTGZ(outPath string, items []BundleItem) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, it := range items {
		if it.Path == "" {
			continue
		}
		if it.Name == "" {
			it.Name = filepath.Base(it.Path)
		}
		if err := addFile(tw, it.Path, it.Name); err != nil {
			return err
		}
	}
	return nil
}

func addFile(tw *tar.Writer, path string, name string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}

	h := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    st.Size(),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(tw, f)
	return err
}
