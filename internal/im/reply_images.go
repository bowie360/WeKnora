package im

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/Tencent/WeKnora/internal/logger"
	"github.com/Tencent/WeKnora/internal/storageurl"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
)

// imMarkdownImageRe matches Markdown image syntax and captures the alt text
// and the image reference.
var imMarkdownImageRe = regexp.MustCompile(`!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)

// imMultiBlankLineRe collapses the blank lines left behind when image
// Markdown is stripped from an answer.
var imMultiBlankLineRe = regexp.MustCompile(`\n{3,}`)

const (
	// maxIMReplyImages bounds how many images one reply delivers natively.
	maxIMReplyImages = 3
	// maxIMReplyImageBytes bounds the size of one natively delivered image.
	maxIMReplyImageBytes = 10 << 20 // 10 MiB
)

// extractIMReplyImages resolves internal storage images referenced by
// Markdown image syntax in a formatted IM answer and returns them as reply
// attachments together with the answer text stripped of the extracted image
// Markdown. It is used by channels whose adapter implements ImageReplyAdapter
// so images can be delivered as native media instead of unrenderable
// internal references (for example resource:// handles on WeChat).
//
// Images that cannot be resolved or fetched are left untouched in the text,
// which degrades to the previous behaviour for those images. When no image
// could be extracted the original content is returned unchanged.
func extractIMReplyImages(
	ctx context.Context,
	content string,
	tenant *types.Tenant,
	defaultSvc interfaces.FileService,
	storageResolvers ...interfaces.StorageBackendResolver,
) ([]ReplyFile, string) {
	if content == "" || !strings.Contains(content, "![") {
		return nil, content
	}

	resolver := newIMFileServiceResolver(tenant, defaultSvc, storageResolvers...).WithContext(ctx)

	seen := make(map[string]bool)
	extracted := make(map[string]bool)
	var files []ReplyFile

	for _, m := range imMarkdownImageRe.FindAllStringSubmatch(content, -1) {
		full, alt, ref := m[0], m[1], m[2]
		if seen[ref] || len(files) >= maxIMReplyImages {
			continue
		}
		seen[ref] = true
		if storageurl.IsHTTPURL(ref) || !storageurl.Pattern.MatchString(ref) {
			continue
		}

		svc := resolver.ResolveFileService(ref)
		if svc == nil {
			continue
		}
		rc, err := svc.GetFile(ctx, ref)
		if err != nil {
			logger.Warnf(ctx, "[IM] reply image fetch failed: ref=%s err=%v", ref, err)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxIMReplyImageBytes+1))
		rc.Close()
		if err != nil || len(data) == 0 || len(data) > maxIMReplyImageBytes {
			if err != nil {
				logger.Warnf(ctx, "[IM] reply image read failed: ref=%s err=%v", ref, err)
			}
			continue
		}
		ext, ok := detectImageExt(data)
		if !ok {
			continue
		}

		files = append(files, ReplyFile{
			FileName: replyImageFileName(alt, ext, len(files)),
			FileData: data,
		})
		extracted[full] = true
	}

	if len(files) == 0 {
		return nil, content
	}

	cleaned := content
	for full := range extracted {
		cleaned = strings.ReplaceAll(cleaned, full, "")
	}
	cleaned = imMultiBlankLineRe.ReplaceAllString(cleaned, "\n\n")
	return files, strings.TrimSpace(cleaned)
}

// detectImageExt returns the file extension for common image formats based
// on their magic bytes.
func detectImageExt(data []byte) (string, bool) {
	switch {
	case len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF:
		return ".jpg", true
	case len(data) >= 4 && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47:
		return ".png", true
	case len(data) >= 4 && data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x38:
		return ".gif", true
	case len(data) >= 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return ".webp", true
	}
	return "", false
}

// replyImageFileName derives a safe display name from the image alt text,
// falling back to a positional name. The extension always matches the
// detected image type.
func replyImageFileName(alt, ext string, idx int) string {
	name := strings.TrimSpace(alt)
	name = strings.NewReplacer("/", "_", "\\", "_", "\n", " ", "\r", " ", "\t", " ").Replace(name)
	if dot := strings.LastIndex(name, "."); dot > 0 {
		name = name[:dot]
	}
	name = strings.TrimSpace(name)
	if len([]rune(name)) > 60 {
		name = string([]rune(name)[:60])
	}
	if name == "" {
		return fmt.Sprintf("image-%d%s", idx+1, ext)
	}
	return name + ext
}
