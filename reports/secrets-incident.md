# Secrets Incident Report — Lab 24

## 1. Công cụ quét

- **Scanner:** Gitleaks v8.30.1
- **Config:** `.gitleaks.toml` (custom rule `lab24-synthetic-token`)
- **Lệnh quét lịch sử:**
  ```
  gitleaks git --config .gitleaks.toml --redact --verbose .
  ```
- **Lệnh quét file hiện tại:**
  ```
  gitleaks dir --config .gitleaks.toml .
  ```

---

## 2. Finding — Token giả trong lịch sử Git

| Trường | Giá trị |
|--------|---------|
| Commit | `1bdd849922156c868a5ee9293d68f5b72e242d2c` |
| File | `lab-fake-secret.txt` |
| Rule ID | `lab24-synthetic-token` |
| Pattern khớp | `LAB24_FAKE_TOKEN=LAB24-DEMO-[REDACTED]` |
| Tác giả commit | VinUni AI20k Lab |
| Thời điểm | 2026-10-09 23:22:06 +0700 |

**Quét lịch sử (`gitleaks git`):** báo **1 finding** tại commit `1bdd849` — đúng như dự kiến của bài lab.

**Quét file hiện tại (`gitleaks dir`):** **sạch** — file `lab-fake-secret.txt` đã bị xoá khỏi HEAD ở commit sau.

---

## 3. Phân tích

File `lab-fake-secret.txt` đã bị xoá khỏi working tree tại một commit sau `1bdd849`, nhưng token vẫn còn **nguyên trong lịch sử Git**. Bất kỳ ai có quyền clone repo đều đọc được token này qua `git show 1bdd849:lab-fake-secret.txt` hoặc `git log -p`.

**Xoá file ở commit mới KHÔNG làm token cũ tự vô hiệu.** Token vẫn tồn tại vĩnh viễn trong object store của Git cho đến khi toàn bộ lịch sử bị rewrite (git-filter-repo) **và** mọi bản sao (clone, fork, backup) được đồng bộ lại.

---

## 4. Quy trình xử lý nếu đây là secret thật

1. **Thu hồi / rotate ngay lập tức** tại dịch vụ đã cấp token — đây là bước quan trọng nhất và phải làm trước mọi bước khác. Xoá file khỏi repo không thay thế được bước này.

2. **Kiểm tra sử dụng sai (audit access log):** tra log của dịch vụ xem token đã được dùng bởi IP/client nào ngoài hệ thống chủ động, trong khoảng thời gian từ commit `1bdd849` đến thời điểm rotate.

3. **Xử lý các bản sao:**
   - Thông báo cho tất cả người đã clone/fork repo trước khi phát hiện.
   - Rewrite lịch sử bằng `git filter-repo --path lab-fake-secret.txt --invert-paths` để loại file khỏi toàn bộ lịch sử.
   - Force-push tất cả branch; yêu cầu collaborator re-clone.
   - Kiểm tra GitHub/GitLab cached views, CI artifact, backup server — xoá hoặc xác nhận token đã hết hiệu lực.

4. **Ghi incident:** ghi thời điểm phát hiện, thời điểm rotate, phạm vi có thể bị lộ, người xử lý.

---

## 5. Ghi chú về bài lab này

Token `LAB24-DEMO-7K2Q9M4R6T8V1X3Z` là **token giả, vô hiệu** được tạo chủ ý để minh hoạ quy trình. Không có rủi ro bảo mật thực tế. Finding từ `gitleaks git` là kết quả dự kiến; finding từ `gitleaks dir` (file hiện tại) phải sạch.

**Kết luận kỹ thuật:** pin dependency (`requirements.lock --generate-hashes`) và pre-commit hook (`gitleaks-system`) giúp phát hiện sớm secret lộ trong quá trình phát triển, nhưng **không thay thế** bước rotate khi secret đã commit vào lịch sử — vì lịch sử Git là bất biến và được phân tán trên nhiều bản sao.
