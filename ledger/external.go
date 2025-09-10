package ledger

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-codec/codec"
)

// EncodedBlockCert defines how GetBlockBytes encodes a block and its certificate
type EncodedBlockCert struct {
	_struct struct{} `codec:""`

	Block       bookkeeping.Block     `codec:"block"`
	Certificate agreement.Certificate `codec:"cert"`
}

// externalArchivalSettings indicates whether archive mode is enabled.
//
// In case of being enabled, the URL of the external archive is returned.
// When disabled, this URL is set to "".
func externalArchiveSettings() (url string, enabled bool) {
	url = os.Getenv("EXTERNAL_ARCHIVE_URL")
	return url, url != ""
}

func downloadBlockBytesFromExternalArchive(rnd basics.Round, baseUrl string) (blk []byte, cert []byte, err error) {

	// Download block from external archive
	encodedBlockCert, err := downloadBlockFromExternalArchive(rnd, baseUrl)
	if err != nil {
		return nil, nil, err
	}

	// Encode block bytes to msgpack
	{
		codecHandle := makeCodecHandle()

		var buf bytes.Buffer
		enc := codec.NewEncoder(&buf, codecHandle)
		err = enc.Encode(encodedBlockCert.Block)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encode EncodedBlockCert.Block to msgpack: %w", err)
		}
		blk = buf.Bytes()
	}

	// Encode certificate bytes to msgpack
	{
		codecHandle := makeCodecHandle()

		var buf bytes.Buffer
		enc := codec.NewEncoder(&buf, codecHandle)
		err = enc.Encode(encodedBlockCert.Certificate)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encode EncodedBlockCert.Certificate to msgpack: %w", err)
		}
		cert = buf.Bytes()
	}

	return blk, cert, nil
}

func downloadBlockFromExternalArchive(rnd basics.Round, baseUrl string) (blk EncodedBlockCert, err error) {

	// Set up the HTTP client
	const ExternalArchiveTimeout = 10 * time.Second
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: ExternalArchiveTimeout, // Connection timeout
			}).DialContext,
			ResponseHeaderTimeout: ExternalArchiveTimeout, // Read timeout for headers
		},
		Timeout: ExternalArchiveTimeout, // Overall request timeout
	}

	// Get block bytes
	url := baseUrl + fmt.Sprint(rnd)
	resp, err := client.Get(url)
	if err != nil {
		return EncodedBlockCert{}, fmt.Errorf("failed to download block from external archive: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	encodedBlockCertBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return EncodedBlockCert{}, fmt.Errorf("failed to read HTTP response body from external archive: %w", err)
	}

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return EncodedBlockCert{}, fmt.Errorf("failed to download block from external archive: HTTP status code %d", resp.StatusCode)
	}

	// Decode block bytes from msgpack
	{
		codecHandle := makeCodecHandle()

		dec := codec.NewDecoderBytes(encodedBlockCertBytes, codecHandle)
		err = dec.Decode(&blk)
		if err != nil {
			return EncodedBlockCert{}, fmt.Errorf("failed to decode EncodedBlockCert from msgpack: %w", err)
		}
	}

	return blk, nil
}

func makeCodecHandle() *codec.MsgpackHandle {

	codecHandle := new(codec.MsgpackHandle)

	codecHandle.ErrorIfNoField = true
	codecHandle.ErrorIfNoArrayExpand = true
	codecHandle.Canonical = true
	codecHandle.RecursiveEmptyCheck = true
	codecHandle.WriteExt = true
	codecHandle.PositiveIntUnsigned = true

	return codecHandle
}
