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
#include "aes.h"

#define PORT 8888

// ================= 全域 =================
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
            std::cout << "偵測到來自節點 " << node_id << " 的封包遭到竄改！已強制剔除該票。\n";
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

    std::cout << "\n=== Task " << task_id << " 投票結果 ===\n";

    if (expected_nodes == 3) {
        
        // 【情況一】：無斷線、無竄改
        if (missing_count == 0 && tampered_count == 0) {
            if (max_count >= 2)
                std::cout << "[成功] 3TMR 多數決成功 (" << max_count << "/3)\n";
            else
                std::cout << "[失敗] 3TMR 投票分歧，無法達成一致\n";
        }
        
        // 【情況二】：單純的節點缺失 (1 台斷線/逾時，但沒人被竄改) -> 正常降級 2MR
        else if (missing_count == 1 && tampered_count == 0) {
            if (max_count == 2)
                std::cout << "[降級成功] 2MR 一致 (因「節點缺失/網路斷線」啟動降級機制)\n";
            else
                std::cout << "[降級失敗] 2MR 分歧 (因「節點缺失/網路斷線」啟動降級機制)\n";
        }
        
        // 【情況三】：遭到惡意竄改 (只有 1 台被竄改)
        else if (missing_count == 0 && tampered_count == 1) {
            std::cout << "[資安防禦] 警告：偵測到 1 個節點遭受竄改攻擊！排除惡意資料，強制啟動 2MR 安全審查...\n";
            if (max_count == 2)
                std::cout << "[防禦成功] 排除被竄改資料後，其餘 2 個合法節點資料完全一致，安全通過！\n";
            else
                std::cout << "[防禦失敗] 排除被竄改資料後，其餘 2 個合法節點資料分歧，拒絕採信！\n";
        }
        
        // 【情況四】：多個節點遭到變更/竄改
        else if (tampered_count >= 2) {
            std::cout << "[嚴重攻擊中止] 偵測到多個節點(" << tampered_count << "個)同時遭到竄改！系統遭受威脅，拒絕降級，終止本次投票！\n";
        }
        
        // 【情況五】：1台斷線，同時又有1台被竄改
        else {
            std::cout << "[嚴重錯誤] 同時發生「節點缺失」與「資料竄改」，剩餘合法節點不足，無法完成投票！\n";
        }
    }
    
    //  DMR 邏輯 
    else if (expected_nodes == 2) {
        int received_nodes = 1 + task.peer_results.size() - tampered_count;
        if (received_nodes == 2 && max_count == 2)
            std::cout << "[成功] 2MR 一致\n";
        else
            std::cout << "[失敗] 2MR 分歧、節點缺失或資料遭竄改\n";
    }
    else {
        std::cout << "[錯誤] 不支援的節點數\n";
    }

    std::cout << "===========================\n> ";
    fflush(stdout);
}

// ================= Task Processing =================
void process_task(const std::string& task_id, const std::string& plaintext) {
    std::cout << "\n[任務啟動] ID: " << task_id << " | 內容: " << plaintext << std::endl;

    std::string text_to_encrypt = plaintext;

    if (inject_fault.load()) {
        text_to_encrypt += "_WRONG"; 
        std::cout << "[警告] 模擬節點運算錯誤 (Fault)\n";
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

    if (!success)
        std::cout << "[逾時] 未收齊，降級投票\n";
    else
        std::cout << "[收齊] 所有結果\n";

    lock.unlock();

    vote(task_id);

    lock.lock();
    task.finished = true;
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

            TaskState* task_ptr = nullptr;

            {
                std::lock_guard<std::mutex> lock(mtx);
                auto &t = tasks[task_id];
                t.peer_results[node_id] = cipher;
                task_ptr = &t;
            }

            task_ptr->cv.notify_one();
        }
    }
}

int run_tmrnode(int argc, char* argv[]) {
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
    std::map<std::string, std::string> cluster_ips = {
        {"A", "192.168.50.41"},
        {"B", "192.168.50.14"},
        {"C", "192.168.50.62"}
    };

    if (argc < 2) {
        std::cout << "用法: ./TMR-Pi A/B/C\n";
        return 1;
    }

    my_id = argv[1];

    for (auto &n : cluster_ips) {
        if (n.first != my_id)
            peer_ips.push_back(n.second);
    }

    std::cout << "啟動節點 " << my_id << std::endl;

    std::thread(listener_thread).detach();

    std::string input;

    while (true) {
        std::cout << "\n> ";
        std::getline(std::cin, input);

        if (input == "fault") {
            inject_fault.store(!inject_fault.load());
            std::cout << "fault: " << inject_fault.load() << std::endl;
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