#pragma once

#include <boost/asio.hpp>
#include <curl/curl.h>
#include <queue>

class EmailTask {
public:
    EmailTask(const std::string& userEmail, const std::string& pinCode)
        : userEmail_(userEmail), pinCode_(pinCode) {}

    std::string userEmail_;
    std::string pinCode_;
};

class EmailHandler {
    CURL* curl_;
    struct curl_slist* recipients_ = nullptr;
    std::istringstream email_data_stream_{  };
    std::thread emailSendingThread_;
    std::mutex mutex_;
    std::condition_variable emailQueueNotEmpty_;
    std::queue<EmailTask> emailQueue_;
    std::atomic<bool> stopProcessing_;

    static size_t readCallback(void* ptr, size_t size, size_t nmemb, void* userp);
    void processQueue();
public:
    EmailHandler();
    ~EmailHandler();
    void sendEmail(const std::string& userEmail, const std::string& pinCode);
    void sendEmailWorker(const std::string& userEmail, const std::string& pinCode);
};