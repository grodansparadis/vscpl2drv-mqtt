#include "mqttobj.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

static void require(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "%s\n", message);
        std::exit(EXIT_FAILURE);
    }
}

int main()
{
    CDriverSemaphore semaphore;
    require(semaphore.waitFor(0) == -1 && errno == ETIMEDOUT,
            "An empty semaphore must time out.");

    semaphore.post();
    semaphore.post();
    require(semaphore.waitFor(0) == 0, "The first post must be consumable.");
    require(semaphore.waitFor(0) == 0, "The second post must be consumable.");
    require(semaphore.tryWait() == -1 && errno == EAGAIN,
            "Consumed posts must not remain available.");

    const auto started = std::chrono::steady_clock::now();
    require(semaphore.waitFor(20000) == -1 && errno == ETIMEDOUT,
            "An empty semaphore must report a finite timeout.");
    require(std::chrono::steady_clock::now() - started >=
              std::chrono::milliseconds(10),
            "A relative timeout must not be treated as an expired absolute time.");

    std::thread producer([&semaphore]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        semaphore.post();
    });
    const int result = semaphore.waitFor(5000000);
    producer.join();
    require(result == 0, "Posting from another thread must wake the waiter.");
    require(semaphore.tryWait() == -1 && errno == EAGAIN,
            "The awakened waiter must consume exactly one post.");

    std::puts("Semaphore counting, timeouts and thread wakeup pass.");
    return EXIT_SUCCESS;
}
