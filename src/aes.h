#pragma once
#include <string>

std::string compute_aes(const std::string& plaintext, const unsigned char* master_key, const std::string& task_id);
bool verify_aes_hmac(const std::string& cipher_with_hmac, const unsigned char* master_key);