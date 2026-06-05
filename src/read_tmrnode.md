# TMR Node (Triple Modular Redundancy)

基於 UDP 廣播與 C++ 多執行緒實作的分散式多數決節點程式。本系統支援多任務並發處理、AES 加密運算、錯誤注入測試，以及基於 3000ms 超時機制的 3TMR / 2MR 容錯降級投票。

## 1. 系統架構與全域狀態

本程式以多執行緒架構運行，主要分為三個核心執行緒：

* **Main Thread**: 負責讀取使用者輸入、發起任務 (`TASK`) 與切換錯誤注入狀態 (`fault`)。
* **Listener Thread**: 背景監聽 UDP Port `8888`，處理收到的 `TASK` 與 `RESULT` 封包。
* **Worker Thread (`process_task`)**: 每個任務獨立開啟的執行緒，負責 AES 加密、等待同步與執行投票。

### 核心資料結構

系統使用全域 `std::map<string, TaskState> tasks` 來管理多個並發任務。

```cpp
struct TaskState {
    string plaintext;                  // 原始測資
    string my_result;                  // 本機運算出的 AES Cipher
    map<string, string> peer_results;  // 儲存其他節點回傳的結果 (Key: 節點ID, Value: Cipher)
    bool finished = false;             // 任務結算標記
    condition_variable cv;             // 用於觸發/等待該任務結果的條件變數
};
```

所有對 `tasks` 的讀寫操作皆受全域互斥鎖 `std::mutex mtx` 保護。

---

## 2. 核心運作流程

### 任務發起 (Task Initiation)
1. 使用者在終端機輸入字串。
2. 呼叫 `gen_task_id()` 透過系統時間戳生成唯一 Task ID。
3. 鎖定 `mtx`，在 `tasks` 中初始化該 Task ID 的狀態，並寫入 `plaintext`。
4. 呼叫 `broadcast()` 透過 UDP 發送 `TASK:<task_id>:<plaintext>` 給 `peer_ips` 列表中的節點。
5. 建立並分離 (`detach`) 一個新的 `process_task` 執行緒處理該任務。

### 任務處理與同步 (Processing & Synchronization)
`process_task` 函式的具體執行步驟：

1. **錯誤注入與運算**：檢查 `inject_fault` (`atomic bool`) 狀態。若為 `true`，在**加密前**將明文串接 `_WRONG` 字串，藉此模擬節點本身的「運算錯誤（Fault）」，並確保其仍會產生對應錯誤密文的合法 HMAC 驗證碼。接著呼叫 `compute_aes` 進行 AES 加密並附加 HMAC-SHA256 驗證碼。
2. **儲存與廣播**：鎖定 `mtx`，將結果存入 `tasks[task_id].my_result`，接著廣播 `RESULT:<task_id>:<my_id>:<cipher>`。
3. **阻塞等待 (Timeout Mechanism)**：使用 `unique_lock` 配合 `cv.wait_for`。執行緒會在此休眠，直到以下兩種情況之一發生：
    * **條件滿足**：`peer_results.size() >= peer_ips.size()`（收齊其他所有節點的結果）。
    * **超時觸發**：達到設定的 3000ms 上限。
4. **解鎖與投票**：等待結束後，釋放 `unique_lock`（避免與 `vote` 內的鎖死結），然後呼叫 `vote(task_id)`。
5. **結案**：標記 `finished = true`。

### 網路監聽與喚醒 (Listener & Notification)
`listener_thread` 負責解析 UDP 封包：

* **收到 TASK**：解析出 `task_id` 與 `text`，鎖定 `mtx` 建立任務狀態，並啟動 `process_task` 執行緒。
* **收到 RESULT**：解析出 `task_id`、`node_id` 與 `cipher`。鎖定 `mtx` 將結果寫入 `tasks[task_id].peer_results[node_id]`。寫入完成後，呼叫 `tasks[task_id].cv.notify_one()` 喚醒正在等待該任務的 `process_task` 執行緒。

---

## 3. 投票與資安容錯分流機制 (Voting & Security Logic)

`vote()` 函式會精確計算「網路缺失數（missing_count）」與「密文竄改數（tampered_count，即 HMAC 驗證失敗者）」，並針對預期 3 節點的叢集進行 **5 大情境完全分流處理**：

* **【情況一】完美無瑕 (無斷線、無竄改)**
  * 所有節點皆於 3000ms 內回報且 HMAC 安全驗證通過。實行標準 3TMR 多數決，只要多數（>=2 票）一致即成功通過。此情境能完美容忍單一節點的運算錯誤（Fault）。
* **【情況二】單純節點缺失 (1 台斷線/逾時，無人被竄改)**
  * 系統自動降級為 **2MR 模式**。剩餘的 2 個誠實節點運算結果必須完全一致（2/2）方能成功通過，否則宣告降級失敗。
* **【情況三】遭到惡意竄改 (1 台回報但 HMAC 驗證失敗)**
  * 觸發資安防禦！系統精準識別出異常節點並**強制剔除惡意選票**。排除威脅後，將其餘 2 個合法節點強制啟動 **2MR 安全審查**，兩者一致則防禦成功並採信結果。
* **【情況四】多重竄改 (>=2 台同時遭到變更/竄改)**
  * 判定叢集遭受大規模惡意攻擊（超過系統容錯上限），系統為保護數據安全，**拒絕降級並直接終止本次投票**。
* **【情況五】 1台斷線，同時有其他台遭竄改**
  * 網路缺失與資安攻擊同時發生，導致剩餘合法票數僅剩本機自己，資料不足以進行交叉驗證，宣告投票失敗。

* **備用 DMR 邏輯 (當系統預期節點數一開始就設定為 2 時)**：
  * 扣除竄改票後，剩餘的 2 個節點必須完全一致（max_count == 2）才算成功，否則失敗。

---

## 4. 執行與操作

本程式需要傳入節點 ID 以進行身分識別並載入對應的叢集 IP 配置。

### 環境變數設定（首次執行）

三台節點需使用相同的 AES Master Key。由其中一人產生後分發給所有組員：

```bash
# 產生隨機 key（只需做一次，三台用同一把）
openssl rand -hex 32
```
將輸出的 64 個字元設定為環境變數：
```bash
# 寫入 ~/.bashrc 生效
echo 'export AES_MASTER_KEY="你的64個hex字元"' >> ~/.bashrc
source ~/.bashrc

# 確認設定成功
echo $AES_MASTER_KEY
```

### 啟動節點

在終端機執行編譯後的程式，並傳入節點編號 (A, B 或 C)：

```bash
./TMR-Pi A
```

### 操作指令

* **輸入 `fault`**：切換錯誤注入模式 (ON/OFF)。
* **輸入任意字串**：發起一般加密與投票任務。