// 无锁 MPSC 队列(Multi-Producer Single-Consumer)——趣味集第 27 讲
//
// 场景:多个工作线程写审计日志,一个后台线程批量落库。
//   M=多生产者:每个请求线程都要入队
//   S=单消费者:只有一个写库线程出队
//
// 为什么选 MPSC 而不是 MPMC:消费者唯一,出队侧就不需要 CAS,
// 少一层复杂度,也少一处出错的地方。
//
// 设计要点:
//   1. 定长环形缓冲 —— 满了按策略丢弃(审计是旁路需求,不能反压主链路)
//   2. 入队靠 CAS 抢槽位(第 16 讲:抢的是"改号"这一下,不是整张表)
//   3. head 与 tail 分处不同 cache line,避免伪共享(第 12 则)
//   4. 槽位用序号比对,规避 ABA(第 16 讲)
#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace secguard {

// Capacity 必须是 2 的幂(用位与代替取模)
template <class T, std::size_t Capacity>
class MpscQueue {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity 必须是 2 的幂");

public:
    MpscQueue() {
        for (std::size_t i = 0; i < Capacity; ++i) slots_[i].seq.store(i, std::memory_order_relaxed);
    }

    MpscQueue(const MpscQueue&) = delete;
    MpscQueue& operator=(const MpscQueue&) = delete;

    // 入队。队列满返回 false(调用方负责记一次丢弃)。
    bool push(const T& item) {
        Slot* slot = nullptr;
        std::size_t pos = head_.load(std::memory_order_relaxed);

        for (;;) {
            slot = &slots_[pos & (Capacity - 1)];
            const std::size_t seq = slot->seq.load(std::memory_order_acquire);

            // seq == pos 表示这个槽位空闲可写
            const auto diff = static_cast<std::intptr_t>(seq) - static_cast<std::intptr_t>(pos);
            if (diff == 0) {
                // 抢槽位:把 head 往前推一格
                if (head_.compare_exchange_weak(pos, pos + 1,
                                                std::memory_order_relaxed,
                                                std::memory_order_relaxed)) {
                    break;      // 抢到了
                }
                // 没抢到:CAS 已把最新 pos 写回,直接重试
            } else if (diff < 0) {
                return false;   // 队列满
            } else {
                pos = head_.load(std::memory_order_relaxed);   // 别人先走一步,重读
            }
        }

        slot->data = item;
        // 发布:告诉消费者"这个槽位写好了"。seq 变成 pos+1
        slot->seq.store(pos + 1, std::memory_order_release);
        return true;
    }

    // 出队。只能由单消费者线程调用。
    bool pop(T& out) {
        std::size_t pos = tail_.load(std::memory_order_relaxed);

        for (;;) {
            Slot* slot = &slots_[pos & (Capacity - 1)];
            const std::size_t seq = slot->seq.load(std::memory_order_acquire);

            // seq == pos+1 表示这个槽位已经写好
            const auto diff = static_cast<std::intptr_t>(seq) - static_cast<std::intptr_t>(pos + 1);
            if (diff == 0) {
                if (tail_.compare_exchange_weak(pos, pos + 1,
                                                std::memory_order_relaxed,
                                                std::memory_order_relaxed)) {
                    break;      // 抢到了
                }
            } else if (diff < 0) {
                return false;   // 队列空
            } else {
                pos = tail_.load(std::memory_order_relaxed);
            }
        }

        Slot* slot = &slots_[pos & (Capacity - 1)];
        out = std::move(slot->data);
        // 归还槽位:seq 变成 pos+Capacity,同时起到"清空"的作用
        slot->seq.store(pos + Capacity, std::memory_order_release);
        return true;
    }

    // 近似长度(仅供监控,不保证精确)
    [[nodiscard]] std::size_t size_approx() const {
        const std::size_t head = head_.load(std::memory_order_acquire);
        const std::size_t tail = tail_.load(std::memory_order_acquire);
        return head >= tail ? head - tail : 0;
    }

    [[nodiscard]] static constexpr std::size_t capacity() { return Capacity; }

private:
    struct Slot {
        std::atomic<std::size_t> seq{0};
        T data{};
    };

    // head 与 tail 各占一条 cache line:生产者改 head,消费者改 tail,
    // 若同处一条 line 就会反复失效、互相拖慢(第 12 则伪共享)
    alignas(64) std::atomic<std::size_t> head_{0};
    alignas(64) std::atomic<std::size_t> tail_{0};
    alignas(64) std::array<Slot, Capacity> slots_{};
};

}  // namespace secguard
