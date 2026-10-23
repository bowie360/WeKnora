package wechat

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Tencent/WeKnora/internal/im"
	"github.com/Tencent/WeKnora/internal/logger"
)

// uploadedMedia is the CDN reference of a media file uploaded to the iLink
// CDN, ready to be embedded in a sendmessage payload.
type uploadedMedia struct {
	// EncryptQueryParam identifies the uploaded file on the WeChat CDN.
	EncryptQueryParam string
	// AESKeyHex is the hex form (32 chars) of the AES-128 key used to
	// encrypt the uploaded bytes.
	AESKeyHex string
	// CipherSize is the byte length of the encrypted payload.
	CipherSize int
}

// ilinkCall POSTs a JSON payload to an iLink API path and returns the raw
// response body, unlike ilinkPost which discards it.
func (a *Adapter) ilinkCall(ctx context.Context, path string, payload interface{}) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ilinkBaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	a.setAuthHeaders(req, body)

	resp, err := ilinkHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ilink request %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ilink api %s returned status %d: %s", path, resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// uploadImage encrypts an image and uploads it to the WeChat CDN via the
// iLink getuploadurl flow (media_type=1, no thumbnail). The flow follows the
// official iLink client behaviour:
//
//  1. Generate a random AES-128 key and file key.
//  2. Encrypt the image with AES-128-ECB (PKCS#7 padding).
//  3. POST /ilink/bot/getuploadurl with the hex AES key and sizes/MD5.
//  4. POST the ciphertext to upload_full_url (fall back to PUT).
//  5. The download reference is the x-encrypted-param response header,
//     or the encrypted_query_param embedded in the upload URL.
func (a *Adapter) uploadImage(ctx context.Context, toUserID string, data []byte) (*uploadedMedia, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("image data is empty")
	}
	if toUserID == "" {
		return nil, fmt.Errorf("no recipient user ID")
	}

	aesKey := make([]byte, 16)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("generate aes key: %w", err)
	}
	aesKeyHex := hex.EncodeToString(aesKey)

	encrypted, err := encryptAES128ECB(data, aesKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt image: %w", err)
	}

	fileKeyBytes := make([]byte, 16)
	if _, err := rand.Read(fileKeyBytes); err != nil {
		return nil, fmt.Errorf("generate file key: %w", err)
	}
	fileKey := hex.EncodeToString(fileKeyBytes)

	rawMD5 := md5.Sum(data)

	respBody, err := a.ilinkCall(ctx, "/ilink/bot/getuploadurl", map[string]interface{}{
		"filekey":       fileKey,
		"media_type":    1, // IMAGE
		"to_user_id":    toUserID,
		"rawsize":       len(data),
		"rawfilemd5":    hex.EncodeToString(rawMD5[:]),
		"filesize":      len(encrypted),
		"aeskey":        aesKeyHex,
		"no_need_thumb": true,
		"base_info":     newBaseInfo(),
	})
	if err != nil {
		return nil, fmt.Errorf("getuploadurl: %w", err)
	}

	var up struct {
		UploadParam   string `json:"upload_param"`
		UploadFullURL string `json:"upload_full_url"`
	}
	if err := json.Unmarshal(respBody, &up); err != nil {
		return nil, fmt.Errorf("unmarshal getuploadurl response: %w", err)
	}

	uploadURL := up.UploadFullURL
	if uploadURL == "" && up.UploadParam != "" {
		uploadURL = cdnBaseURL + "/upload?encrypted_query_param=" +
			url.QueryEscape(up.UploadParam) + "&filekey=" + url.QueryEscape(fileKey)
	}
	if uploadURL == "" {
		return nil, fmt.Errorf("getuploadurl returned no upload URL: %s", string(respBody))
	}

	encryptParam, err := a.putToCDN(ctx, uploadURL, encrypted)
	if err != nil {
		return nil, err
	}

	logger.Infof(ctx, "[WeChat] Image uploaded: raw=%d cipher=%d", len(data), len(encrypted))
	return &uploadedMedia{
		EncryptQueryParam: encryptParam,
		AESKeyHex:         aesKeyHex,
		CipherSize:        len(encrypted),
	}, nil
}

// putToCDN uploads the encrypted bytes to the CDN upload URL and returns the
// download reference (encrypt_query_param). POST is the method the official
// client uses; PUT is tried as a fallback. Success requires HTTP 200 plus a
// non-empty x-encrypted-param header, or an encrypted_query_param already
// present in the upload URL.
func (a *Adapter) putToCDN(ctx context.Context, uploadURL string, encrypted []byte) (string, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	var lastErr error
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		req, err := http.NewRequestWithContext(ctx, method, uploadURL, bytes.NewReader(encrypted))
		if err != nil {
			return "", fmt.Errorf("create CDN request: %w", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("CDN %s: %w", method, err)
			continue
		}
		headerParam := resp.Header.Get("x-encrypted-param")
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("CDN %s returned %d: %s", method, resp.StatusCode, string(respBody))
			continue
		}
		if headerParam != "" {
			return headerParam, nil
		}
		if u, perr := url.Parse(uploadURL); perr == nil {
			if p := u.Query().Get("encrypted_query_param"); p != "" {
				return p, nil
			}
		}
		return "", fmt.Errorf("CDN %s succeeded but returned no encrypted param", method)
	}
	return "", lastErr
}

// sendImageMessage delivers one uploaded image as a native WeChat image
// message (item type 2) in the conversation identified by the incoming
// message's context token. The media reference follows the official client:
// aes_key is the base64 encoding of the hex key string, and image_item also
// carries the hex key itself plus the cipher size as mid_size.
func (a *Adapter) sendImageMessage(ctx context.Context, incoming *im.IncomingMessage, media *uploadedMedia) error {
	contextToken := ""
	if incoming.Extra != nil {
		contextToken = incoming.Extra["context_token"]
	}

	payload := map[string]interface{}{
		"msg": map[string]interface{}{
			"from_user_id":  "",
			"to_user_id":    incoming.UserID,
			"client_id":     fmt.Sprintf("weknora_%d", time.Now().UnixNano()),
			"message_type":  2, // BOT
			"message_state": 2, // FINISH
			"item_list": []map[string]interface{}{
				{
					"type": 2, // IMAGE
					"image_item": map[string]interface{}{
						"media": map[string]interface{}{
							"encrypt_query_param": media.EncryptQueryParam,
							"aes_key":             base64.StdEncoding.EncodeToString([]byte(media.AESKeyHex)),
							"encrypt_type":        1,
						},
						"aeskey":   media.AESKeyHex,
						"mid_size": media.CipherSize,
					},
				},
			},
			"context_token": contextToken,
		},
		"base_info": newBaseInfo(),
	}

	return a.ilinkPost(ctx, "/ilink/bot/sendmessage", payload)
}

// SupportsReplyImages reports that the WeChat adapter delivers images
// attached to a reply as native image messages.
func (a *Adapter) SupportsReplyImages() bool { return true }

// sendReplyImages uploads and sends each image attached to a reply, in
// order. Individual failures are logged and skipped so one bad image never
// blocks the remaining images or fails the whole reply.
func (a *Adapter) sendReplyImages(ctx context.Context, incoming *im.IncomingMessage, reply *im.ReplyMessage) {
	for _, f := range reply.Files {
		if len(f.FileData) == 0 {
			continue
		}
		media, err := a.uploadImage(ctx, incoming.UserID, f.FileData)
		if err != nil {
			logger.Warnf(ctx, "[WeChat] Upload image %s failed: %v", f.FileName, err)
			continue
		}
		if err := a.sendImageMessage(ctx, incoming, media); err != nil {
			logger.Warnf(ctx, "[WeChat] Send image %s failed: %v", f.FileName, err)
		}
	}
}
