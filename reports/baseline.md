# Baseline — điền trong checkpoint 1

## 1. Mỗi lần chạy baseline đã có agent_id/run_id và danh tính người dùng để kiểm quyền chưa?

Hiện chưa có. Hàm _naive_loop() không nhận và tạo agent_id, run_id . Cả chuỗi search_docs, find_injection, read_customer, http_post chạy mà không có danh tính nào được truyền xuống nên không thể kiểm tra quyền ở bất kỳ bước nào

## 2. Trước http_post, có policy nào kiểm mục đích, quyền và loại dữ liệu không? Ai thực sự quyết định gửi?

Không có policy nào cả. Người quyết định gửi là LLM thông qua llm.find_injection. Nếu LLM trả về một đối tượng injected khác None, code gọi ngay read_customer() rồi http_post() mà không qua cổng kiểm tra mục đích, phân loại dữ liệu hay xác nhận quyền nào

## 3. Dòng nào tạo body POST, và file nào sẽ ghi lại việc sink đã nhận body đó?
trong http_post: tools.http_post(injected.target_url, {“records”: collected}). sink/sink.py log lại request, còn phía agent không có ledger hay audit trail nào ghi lại sự kiện POST 