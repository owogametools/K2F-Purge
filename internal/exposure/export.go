package exposure

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owogametools/k2f-purge/internal/model"
)

var categoryTitle = map[string]string{
	"ssh":           "SSH / 遠端連線",
	"gpg":           "GPG / 金鑰",
	"ai-tools":      "AI 工具",
	"cloud":         "雲端帳號",
	"dev-tools":     "開發工具",
	"shell-history": "Shell 歷史",
	"browsers":      "瀏覽器",
	"wallets":       "加密錢包",
	"projects":      "專案資料夾",
	"nikke":         "NIKKE",
	"system":        "系統",
}

// ExportMarkdown renders a rotation checklist grouped by category.
// It lists paths and existence only; it never includes file contents.
func ExportMarkdown(r *model.ExposureResult) string {
	if r == nil {
		return "# 曝險輪替清單\n\n（無資料）\n"
	}
	var b strings.Builder
	b.WriteString("# 曝險輪替清單\n\n")
	b.WriteString("本清單只記錄路徑是否存在。K2F PURGE 沒有讀取任何檔案內容，也不是防毒軟體。\n\n")
	if !r.StartedAt.IsZero() || !r.FinishedAt.IsZero() {
		fmt.Fprintf(&b, "掃描時間：%s → %s\n\n", fmtTime(r.StartedAt), fmtTime(r.FinishedAt))
	}

	cats := r.Categories
	if len(cats) == 0 {
		cats = summarize(r.Items)
	}
	present := 0
	for _, c := range cats {
		present += c.Present
		title := categoryTitle[c.Name]
		if title == "" {
			title = c.Name
		}
		fmt.Fprintf(&b, "- %s：存在 %d / %d\n", title, c.Present, c.Total)
	}
	fmt.Fprintf(&b, "\n合計存在 %d 項。\n", present)

	grouped := map[string][]model.ExposureItem{}
	var extra []string
	inOrder := map[string]struct{}{}
	for _, n := range categoryOrder {
		inOrder[n] = struct{}{}
	}
	for _, it := range r.Items {
		grouped[it.Category] = append(grouped[it.Category], it)
		if _, ok := inOrder[it.Category]; !ok && it.Category != "" {
			extra = append(extra, it.Category)
		}
	}
	sort.Strings(extra)
	order := append([]string{}, categoryOrder...)
	order = append(order, extra...)

	for _, cat := range order {
		items := grouped[cat]
		if len(items) == 0 {
			continue
		}
		title := categoryTitle[cat]
		if title == "" {
			title = cat
		}
		fmt.Fprintf(&b, "\n## %s\n\n", title)
		for _, it := range items {
			mark := "- [ ]"
			if it.Exists {
				mark = "- [x]"
			}
			label := it.Label
			if label == "" {
				label = it.ID
			}
			fmt.Fprintf(&b, "%s %s — `%s`", mark, label, it.Path)
			if it.Exists {
				fmt.Fprintf(&b, "（存在，%d bytes", it.Size)
				if !it.MTime.IsZero() {
					fmt.Fprintf(&b, "，mtime %s", it.MTime.UTC().Format(time.RFC3339))
				}
				b.WriteString("）")
			} else if it.Note != "" {
				fmt.Fprintf(&b, "（未存在：%s）", it.Note)
			} else {
				b.WriteString("（未存在）")
			}
			if it.Action != "" {
				fmt.Fprintf(&b, "\n  建議：%s", it.Action)
			}
			b.WriteByte('\n')
		}
	}

	if len(r.Limitations) > 0 {
		b.WriteString("\n## 限制\n\n")
		for _, lim := range r.Limitations {
			fmt.Fprintf(&b, "- %s\n", lim)
		}
	}
	return b.String()
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format(time.RFC3339)
}
