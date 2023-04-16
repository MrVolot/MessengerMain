#include "EmailHandler.h"

EmailHandler::EmailHandler(): stopProcessing_(false) {
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl_ = curl_easy_init();
	recipients_ = nullptr;
	emailSendingThread_ = std::thread(&EmailHandler::processQueue, this);
}

EmailHandler::~EmailHandler() {
	stopProcessing_ = true;
	emailQueueNotEmpty_.notify_one();
	if (emailSendingThread_.joinable()) {
		emailSendingThread_.join();
	}
	if (curl_) {
		curl_easy_cleanup(curl_);
	}
	curl_global_cleanup();
}

void EmailHandler::sendEmail(const std::string& userEmail, const std::string& pinCode)
{
	{
		std::unique_lock<std::mutex> lock(mutex_);
		emailQueue_.push(EmailTask(userEmail, pinCode));
	}
	emailQueueNotEmpty_.notify_one();
}

size_t EmailHandler::readCallback(void* ptr, size_t size, size_t nmemb, void* userp) {
	EmailHandler* sender = static_cast<EmailHandler*>(userp);
	std::istringstream& email_data_stream = sender->email_data_stream_;

	email_data_stream.read(static_cast<char*>(ptr), size * nmemb);
	return static_cast<size_t>(email_data_stream.gcount());
}

void EmailHandler::sendEmailWorker(const std::string& userEmail, const std::string& pinCode) {
	std::unique_lock<std::mutex> lock(mutex_);
	if (curl_) {
		email_data_stream_.clear();
		std::string htmlContent = R"(
<html>
<head>
<style>
body {
  font-family: Arial, Helvetica, sans-serif;
  background-color: #ddd;
}

.container {
  padding: 16px;
  background-color: white;
}

h1 {
  color: #0096E6;
  text-align: center;
}

p {
  text-align: center;
  font-size: 24px;
}

.code {
  font-size: 48px;
  color: #FF0000;
  text-align: center;
}
</style>
</head>
<body>

<div class="container">
  <h1>Verification Code</h1>
  <p>Here is your verification code:</p>
  <p class="code">)" + pinCode + R"( </p>
</div>

</body>
</html>
)";
		if (recipients_ != nullptr) {
			curl_slist_free_all(recipients_);
		}
		email_data_stream_.str("To: " + userEmail + "\r\nFrom: k.volotov@gmail.com\r\nSubject: Verification code\r\nContent-Type: text/html\r\n\r\n" + htmlContent);
		recipients_ = curl_slist_append(nullptr, userEmail.c_str());

		curl_easy_setopt(curl_, CURLOPT_URL, "smtps://smtp.gmail.com:465");
		curl_easy_setopt(curl_, CURLOPT_MAIL_FROM, "k.volotov@gmail.com");
		curl_easy_setopt(curl_, CURLOPT_MAIL_RCPT, recipients_);
		curl_easy_setopt(curl_, CURLOPT_USERNAME, "k.volotov@gmail.com");
		curl_easy_setopt(curl_, CURLOPT_PASSWORD, "shvskqyrlokjwakd");
		curl_easy_setopt(curl_, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
		curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 1L);
		curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 2L);
		curl_easy_setopt(curl_, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(curl_, CURLOPT_VERBOSE, 1L);

		curl_easy_setopt(curl_, CURLOPT_READFUNCTION, &EmailHandler::readCallback);
		curl_easy_setopt(curl_, CURLOPT_READDATA, this);

		CURLcode res = curl_easy_perform(curl_);

		if (res != CURLE_OK) {
			//std::cerr << "Error sending email: " << curl_easy_strerror(res) << std::endl;
		}
		else {
			//std::cout << "Email sent successfully!" << std::endl;
		}

		//curl_slist_free_all(recipients_);
		if (recipients_ != nullptr) {
			curl_slist_free_all(recipients_);
			recipients_ = nullptr; // Reset recipients_ to NULL after freeing the list
		}
	}
	lock.unlock();
}

void EmailHandler::processQueue() {
	while (!stopProcessing_) {
		std::unique_lock<std::mutex> lock(mutex_);
		emailQueueNotEmpty_.wait(lock, [this]() { return !emailQueue_.empty() || stopProcessing_; });

		if (!emailQueue_.empty()) {
			EmailTask task = emailQueue_.front();
			emailQueue_.pop();

			lock.unlock();

			sendEmailWorker(task.userEmail_, task.pinCode_);
		}
	}
}