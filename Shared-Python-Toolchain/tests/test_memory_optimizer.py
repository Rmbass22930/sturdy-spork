from memory_optimizer.manager import MemoryManager, get_memory_stats


def test_get_memory_stats_returns_values():
    stats = get_memory_stats()
    assert stats["total_mb"] > 0
    assert stats["available_mb"] > 0


def test_memory_manager_reserve_and_release_segment():
    manager = MemoryManager(min_free_mb=0, block_size_mb=1)
    segments = manager.reserve(1, tag="unit-test")
    status = manager.status()
    assert status["segments"] == 1
    assert status["reserved_mb"] >= 1
    assert manager.release(segments[0].id)
    assert manager.status()["segments"] == 0


def test_memory_manager_release_all():
    manager = MemoryManager(min_free_mb=0, block_size_mb=1)
    manager.reserve(1)
    manager.reserve(1)
    released = manager.release_all()
    assert released >= 2
    assert manager.status()["segments"] == 0
