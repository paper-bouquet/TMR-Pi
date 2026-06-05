#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <map>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <atomic>
#include <random>
#include <cstdlib>
#include <fstream>
#include "aes.h"

#define PORT 8888

// ================= 全域 =================
std::ofstream log_file;
std::mutex log_mtx; // 專為 Log 與 cout 設計的互斥鎖，避免多執行緒寫入撕裂
std::string my_id;
std::vector<std::string> peer_ips;
std::atomic<bool> inject_fault(false);
unsigned char master_key[32] = {0};

struct TaskState {
    std::string plaintext;
    std::string my_result;
    std::map<std::string, std::string> peer_results;
    bool finished = false;
    std::condition_variable cv;
};

std::map<std::string, TaskState> tasks;
std::mutex mtx;

// ================= 安全日誌輸出 =================
void safe_log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mtx);
    std::cout << msg;
    if (log_file.is_open()) {
        log_file << msg;
        log_file.flush();
    }
}

// Heartbeat 專用變數與全域叢集配置
std::map<std::string, std::string> cluster_ips = {
    {"A", "192.168.50.41"},
    {"B", "192.168.50.14"},
    {"C", "192.168.50.62"}
};
std::map<std::string, std::chrono::steady_clock::time_point> last_seen;
std::mutex hb_mtx;

// task id 
std::string gen_task_id() {
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();

    static std::mt19937_64 rng(std::random_device{}());
    uint64_t r = rng();

    return my_id + "_" + std::to_string(now) + "_" + std::to_string(r);
}

// ================= UDP =================
void broadcast(const std::string& msg) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);

    for (auto &ip : peer_ips) {
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        sendto(sockfd, msg.c_str(), msg.length(), 0,
               (struct sockaddr*)&addr, sizeof(addr));
    }

    close(sockfd);
}

// ================= Vote =================
void vote(const std::string& task_id) {
    // 實作安全日誌輸出的 Lambda 函式
    auto log = [&](const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mtx); // 確保多個 task 的 vote 不會互相踩踏輸出
        std::cout << msg;
        if (log_file.is_open()) {
            log_file << msg;
            log_file.flush(); // 強制落碟，防止節點崩潰時丟失最新日誌
        }
    };

    std::lock_guard<std::mutex> lock(mtx);
    auto &task = tasks[task_id];

    std::map<std::string, int> counter;
    
    // 1. 先投自己一票
    counter[task.my_result]++;

    // 2. 計算缺失數與竄改數
    int missing_count = peer_ips.size() - task.peer_results.size(); //逾時缺失
    int tampered_count = 0;                                         //遭到竄改

    // 3. 檢查其他節點傳來的選票
    for (auto &p : task.peer_results) {
        std::string node_id = p.first;
        std::string full_cipher = p.second;

        // 呼叫驗證函式檢查封包是否遭到竄改
        if (verify_aes_hmac(full_cipher, master_key)) {
            // 驗證成功：合法的選票
            counter[full_cipher]++;
        } else {
            // 驗證失敗：HMAC 對不上，代表資料遭變更
            tampered_count++;
            log("偵測到來自節點 " + node_id + " 的封包遭到竄改！已強制剔除該票。\n");
        }
    }

    // 4. 找出最高票
    std::string winner;
    int max_count = 0;
    for (auto &c : counter) {
        if (c.second > max_count) {
            max_count = c.second;
            winner = c.first;
        }
    }

    int expected_nodes = 1 + peer_ips.size(); // 預期要有 3 台

    log("\n=== Task " + task_id + " 投票結果 ===\n");

    if (expected_nodes == 3) {
        
        // 【情況一】：無斷線、無竄改
        if (missing_count == 0 && tampered_count == 0) {
            if (max_count >= 2)
                log("[成功] 3TMR 多數決成功 (" + std::to_string(max_count) + "/3)\n");
            else
                log("[失敗] 3TMR 投票分歧，無法達成一致\n");
        }
        
        // 【情況二】：單純的節點缺失 (1 台斷線/逾時，但沒人被竄改) -> 正常降級 2MR
        else if (missing_count == 1 && tampered_count == 0) {
            if (max_count == 2)
                log("[降級成功] 2MR 一致 (因「節點缺失/網路斷線」啟動降級機制)\n");
            else
                log("[降級失敗] 2MR 分歧 (因「節點缺失/網路斷線」啟動降級機制)\n");
        }
        
        // 【情況三】：遭到惡意竄改 (只有 1 台被竄改)
        else if (missing_count == 0 && tampered_count == 1) {
            log("[資安防禦] 警告：偵測到 1 個節點遭受竄改攻擊！排除惡意資料，強制啟動 2MR 安全審查...\n");
            if (max_count == 2)
                log("[防禦成功] 排除被竄改資料後，其餘 2 個合法節點資料完全一致，安全通過！\n");
            else
                log("[防禦失敗] 排除被竄改資料後，其餘 2 個合法節點資料分歧，拒絕採信！\n");
        }
        
        // 【情況四】：多個節點遭到變更/竄改
        else if (tampered_count >= 2) {
            log("[嚴重攻擊中止] 偵測到多個節點(" + std::to_string(tampered_count) + "個)同時遭到竄改！系統遭受威脅，拒絕降級，終止本次投票！\n");
        }
        
        // 【修正新增：情況五】：兩台節點斷線 (孤島模式)
        else if (missing_count >= 2) {
            log("[嚴重失敗] 網路孤島狀態：失去與多數節點的連線 (缺失 " + std::to_string(missing_count) + " 台)，無法進行任何多數決！\n");
        }
        
        // 【情況六】：1台斷線，同時又有1台被竄改
        else {
            log("[嚴重錯誤] 剩餘合法節點不足，無法完成交叉驗證與投票！\n");
        }
    }
    
    //  DMR 邏輯 
    else if (expected_nodes == 2) {
        int received_nodes = 1 + task.peer_results.size() - tampered_count;
        if (received_nodes == 2 && max_count == 2)
            log("[成功] 2MR 一致\n");
        else
            log("[失敗] 2MR 分歧、節點缺失或資料遭竄改\n");
    }
    else {
        log("[錯誤] 不支援的節點數\n");
    }

    log("===========================\n> ");
    fflush(stdout);
}

// ================= Task Processing =================
void process_task(const std::string& task_id, const std::string& plaintext) {
    safe_log("\n[任務啟動] ID: " + task_id + " | 內容: " + plaintext + "\n");

    std::string text_to_encrypt = plaintext;

    if (inject_fault.load()) {
        text_to_encrypt += "_WRONG"; 
        safe_log("[警告] 模擬節點運算錯誤 (Fault)\n");
    }
    std::string my_cipher = compute_aes(text_to_encrypt, master_key, task_id);

    {
        std::lock_guard<std::mutex> lock(mtx);
        tasks[task_id].my_result = my_cipher;
    }

    broadcast("RESULT:" + task_id + ":" + my_id + ":" + my_cipher);

    std::unique_lock<std::mutex> lock(mtx);
    auto &task = tasks[task_id];

    bool success = task.cv.wait_for(
        lock,
        std::chrono::milliseconds(3000),
        [&] {
            return task.peer_results.size() >= peer_ips.size();
        });

    if (!success) {
        safe_log("[逾時] 未收齊，降級投票\n");
    } else {
        safe_log("[收齊] 所有結果\n");
    }

    lock.unlock();
    vote(task_id);
    
    // 【嚴格修復 Memory Leak】任務完成後，將其從記憶體中剔除
    {
        std::lock_guard<std::mutex> g(mtx);
        tasks.erase(task_id); 
    }
}

// ================= Heartbeat =================
void heartbeat_thread() {
    while (true) {
        broadcast("PING:" + my_id);
        std::this_thread::sleep_for(std::chrono::seconds(5)); // 每 5 秒發送一次心跳
    }
}

// ================= Listener =================
void listener_thread() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in addr{}, cli{};
    socklen_t len = sizeof(cli);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        return;
    }

    char buffer[1024];

    while (true) {
        int n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0,
                         (struct sockaddr*)&cli, &len);

        if (n <= 0) continue;

        buffer[n] = '\0';
        std::string msg(buffer);

        // ===== TASK =====
        if (msg.rfind("TASK:", 0) == 0) {
            size_t p1 = msg.find(':', 5);
            if (p1 == std::string::npos) continue;

            std::string task_id = msg.substr(5, p1 - 5);
            std::string text = msg.substr(p1 + 1);

            {
                std::lock_guard<std::mutex> lock(mtx);
                if (tasks.count(task_id)) continue;
                tasks[task_id].plaintext = text;
            }

            std::thread(process_task, task_id, text).detach();
        }

        // ===== RESULT =====
        else if (msg.rfind("RESULT:", 0) == 0) {
            size_t p1 = msg.find(':', 7);
            size_t p2 = msg.find(':', p1 + 1);

            if (p1 == std::string::npos || p2 == std::string::npos) continue;

            std::string task_id = msg.substr(7, p1 - 7);
            std::string node_id = msg.substr(p1 + 1, p2 - p1 - 1);
            std::string cipher = msg.substr(p2 + 1);

            {
                std::lock_guard<std::mutex> lock(mtx);
                tasks[task_id].peer_results[node_id] = cipher;
                tasks[task_id].cv.notify_one();
            }
        }
        // ===== PING (Heartbeat 攔截) =====
        else if (msg.rfind("PING:", 0) == 0) {
            std::string source_id = msg.substr(5);
            std::lock_guard<std::mutex> lock(hb_mtx);
            last_seen[source_id] = std::chrono::steady_clock::now();
        }
    } // end of while(true)
} // end of listener_thread

int run_tmrnode(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "用法: ./TMR-Pi A/B/C\n"; 
        return 1;
    }

    my_id = argv[1]; 
    log_file.open("tmr_" + my_id + ".log", std::ios::app);

    const char* env_key = std::getenv("AES_MASTER_KEY");
    if (!env_key) {
        std::cerr << "[錯誤] 請設定環境變數 AES_MASTER_KEY（64 hex chars）\n";
        return 1;
    }

    if (strlen(env_key) != 64) {
        std::cerr << "[錯誤] AES_MASTER_KEY 必須是 64 個 hex 字元，目前長度：" << strlen(env_key) << "\n";
        return 1;
    }
    for (int i = 0; i < 32; i++) {
        if (sscanf(env_key + i * 2, "%02hhx", &master_key[i]) != 1) {
            std::cerr << "[錯誤] AES_MASTER_KEY 包含非法字元，位置：" << i * 2 << "\n";
            return 1;
        }
    }

    for (auto &n : cluster_ips) {
        if (n.first != my_id)
            peer_ips.push_back(n.second);
    }

    safe_log("啟動節點 " + my_id + "\n");

    std::thread(listener_thread).detach();
    std::thread(heartbeat_thread).detach(); //啟動背景廣播

    std::string input;

    while (true) {
        safe_log("\n> ");
        std::getline(std::cin, input);

        if (input == "fault") {
            inject_fault.store(!inject_fault.load());
            safe_log("fault: " + std::to_string(inject_fault.load()) + "\n");
        }

        else if (input == "status") {
            std::string output = "\n=== 節點狀態 ===\n";
            output += "本機 ID   : " + my_id + "\n";
            output += "Fault 模式: " + std::string(inject_fault.load() ? "ON (模擬錯誤)" : "OFF") + "\n\n";

            {
                std::lock_guard<std::mutex> hb_lock(hb_mtx);
                auto now = std::chrono::steady_clock::now();
                output += "--- 叢集連線狀態 (Heartbeat) ---\n";
                for (const auto& node : cluster_ips) {
                    if (node.first == my_id) continue;
                    
                    auto it = last_seen.find(node.first);
                    if (it != last_seen.end()) {
                        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
                        if (duration > 15) {
                            output += "[斷線] 節點 " + node.first + " (逾時 " + std::to_string(duration) + " 秒未回應)\n";
                        } else {
                            output += "[在線] 節點 " + node.first + " (上次通訊: " + std::to_string(duration) + " 秒前)\n";
                        }
                    } else {
                        output += "[未知] 節點 " + node.first + " (尚未建立連線)\n";
                    }
                }
            }

            output += "\n--- 任務佇列 ---\n";
            {
                std::lock_guard<std::mutex> lock(mtx);
                output += "任務總數  : " + std::to_string(tasks.size()) + "\n";
                for (const auto& [id, t] : tasks) {
                    output += "  " + id + " -> " + (t.finished ? "已完成" : "進行中") +
                              " | 收到回應: " + std::to_string(t.peer_results.size()) + 
                              "/" + std::to_string(peer_ips.size()) + "\n";
                }
            }
            output += "================\n";
            safe_log(output);
        }

        else if (!input.empty()) {
            std::string task_id = gen_task_id();

            {
                std::lock_guard<std::mutex> lock(mtx);
                tasks[task_id].plaintext = input;
            }

            broadcast("TASK:" + task_id + ":" + input);
            std::thread(process_task, task_id, input).detach();
        }
    }
}