package main

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime"
	"testing"

	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	orasOci "oras.land/oras-go/v2/content/oci"
)

const (
	testIndexRef  = "multi"
	testOtherArch = "testarch"
)

type testPlatformImage struct {
	manifest ocispec.Descriptor
	layer    ocispec.Descriptor
}

func newTestStore(t *testing.T) *orasOci.Store {
	t.Helper()
	store, err := orasOci.New(t.TempDir())
	require.NoError(t, err)
	return store
}

func pushTestBlob(t *testing.T, store *memory.Store, mediaType string, data []byte) ocispec.Descriptor {
	t.Helper()
	desc := content.NewDescriptorFromBytes(mediaType, data)
	require.NoError(t, store.Push(context.Background(), desc, bytes.NewReader(data)))
	return desc
}

func pushTestImage(t *testing.T, store *memory.Store, arch string) testPlatformImage {
	t.Helper()

	configData, err := json.Marshal(ocispec.Image{
		Platform: ocispec.Platform{OS: "linux", Architecture: arch},
	})
	require.NoError(t, err)
	config := pushTestBlob(t, store, ocispec.MediaTypeImageConfig, configData)
	layer := pushTestBlob(t, store, ocispec.MediaTypeImageLayerGzip, []byte("layer-"+arch))

	manifestData, err := json.Marshal(ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    config,
		Layers:    []ocispec.Descriptor{layer},
	})
	require.NoError(t, err)
	manifest := pushTestBlob(t, store, ocispec.MediaTypeImageManifest, manifestData)
	manifest.Platform = &ocispec.Platform{OS: "linux", Architecture: arch}

	return testPlatformImage{manifest: manifest, layer: layer}
}

func pushTestIndex(t *testing.T, store *memory.Store, images ...testPlatformImage) {
	t.Helper()

	descriptors := make([]ocispec.Descriptor, 0, len(images))
	for _, image := range images {
		descriptors = append(descriptors, image.manifest)
	}
	indexData, err := json.Marshal(ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: descriptors,
	})
	require.NoError(t, err)

	index := pushTestBlob(t, store, ocispec.MediaTypeImageIndex, indexData)
	require.NoError(t, store.Tag(context.Background(), index, testIndexRef))
}

func TestCopyImageCopiesOnlyRunningPlatform(t *testing.T) {
	ctx := context.Background()
	src := memory.New()
	running := pushTestImage(t, src, runtime.GOARCH)
	other := pushTestImage(t, src, testOtherArch)
	pushTestIndex(t, src, running, other)

	dst := newTestStore(t)
	require.NoError(t, copyImage(ctx, src, dst, testIndexRef))

	desc, err := dst.Resolve(ctx, testIndexRef)
	require.NoError(t, err)
	assert.Equal(t, running.manifest.Digest, desc.Digest, "the stored root must be the running platform's manifest")

	for _, blob := range []ocispec.Descriptor{running.manifest, running.layer} {
		exists, err := dst.Exists(ctx, blob)
		require.NoError(t, err)
		assert.True(t, exists, "%s (%s) must be copied", blob.Digest, blob.MediaType)
	}

	for _, blob := range []ocispec.Descriptor{other.manifest, other.layer} {
		exists, err := dst.Exists(ctx, blob)
		require.NoError(t, err)
		assert.False(t, exists, "%s (%s) must not be copied", blob.Digest, blob.MediaType)
	}
}

func TestCopyImageFallsBackToAllPlatforms(t *testing.T) {
	ctx := context.Background()
	src := memory.New()
	other := pushTestImage(t, src, testOtherArch)
	pushTestIndex(t, src, other)

	dst := newTestStore(t)
	require.NoError(t, copyImage(ctx, src, dst, testIndexRef))

	for _, blob := range []ocispec.Descriptor{other.manifest, other.layer} {
		exists, err := dst.Exists(ctx, blob)
		require.NoError(t, err)
		assert.True(t, exists, "%s (%s) must be copied by the fallback", blob.Digest, blob.MediaType)
	}
}
