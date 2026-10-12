// SecGuard - 高性能安全审计引擎
// W1: 骨架 + /health
#include <cpp-httplib/httplib.h>   // third_party 是搜索根,所以带子目录名
#include <nlohmann/json.hpp>       // 系统包 libnlohmann-json3-dev

#include <iostream>

int main() {
    httplib::Server svr;

    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        nlohmann::json body = {
            {"status",  "ok"},
            {"service", "secguard"},
        };
        res.set_content(body.dump(), "application/json");
    });

    constexpr int kPort = 8080;
    std::cout << "secguard listening on http://0.0.0.0:" << kPort << std::endl;

    if (!svr.listen("0.0.0.0", kPort)) {
        std::cerr << "failed to listen on port " << kPort << std::endl;
        return 1;
    }
    return 0;
}
