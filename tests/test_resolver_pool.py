"""Regression tests for resolver churn and per-loop shared default channels.

https://github.com/aio-libs/aiodns/issues/191
"""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar
from unittest.mock import patch

import pycares
import pytest

import aiodns


def test_default_resolvers_share_channel_without_sharing_handle() -> None:
    async def run() -> None:
        first = aiodns.DNSResolver()
        if not first._event_thread:
            pytest.skip('event-thread channel unavailable')
        channel = first._channel
        await first.close()
        for _ in range(50):
            client = aiodns.DNSResolver()
            assert client is not first
            assert client._channel is channel
            await client.close()

    asyncio.run(run())


def test_default_resolver_close_is_isolated_and_idle_pool_expires() -> None:
    class FakeChannel:
        instances: ClassVar[list[FakeChannel]] = []

        def __init__(self, **kwargs: Any):
            self.callbacks: list[Any] = []
            self.closed = False
            self.servers = ['127.0.0.1:53']
            self.instances.append(self)

        def query(
            self, host: str, qtype: int, *, callback: Any, **kwargs: Any
        ) -> None:
            self.callbacks.append(callback)

        def close(self) -> None:
            self.closed = True

        def cancel(self) -> None:
            raise AssertionError(
                "cancel() must not cancel another client's queries"
            )

    async def run() -> None:
        a = aiodns.DNSResolver()
        b = aiodns.DNSResolver()
        assert a is not b
        assert a._channel is b._channel
        future_a = a.query_dns('pending.local', 'A')
        future_b = b.query_dns('still-live.local', 'A')
        await a.close()
        with pytest.raises(RuntimeError, match='closed'):
            a.query_dns('after-close.local', 'A')
        with pytest.raises(aiodns.error.DNSError):
            await future_a
        assert not future_b.done()
        assert not a._channel.closed
        a._channel.callbacks[1]('answer', None)
        assert await future_b == 'answer'
        await b.close()
        assert not a._channel.closed
        await asyncio.sleep(0.04)
        assert a._channel.closed

    with patch('aiodns.pycares.Channel', FakeChannel):
        with patch('aiodns._DEFAULT_POOL_IDLE_SECONDS', 0.01, create=True):
            asyncio.run(run())
    assert len(FakeChannel.instances) == 1


def test_explicit_config_and_nameservers_are_private() -> None:
    async def run() -> None:
        a = aiodns.DNSResolver()
        b = aiodns.DNSResolver()
        if not a._event_thread:
            pytest.skip('event-thread channel unavailable')
        assert a._channel is b._channel
        original = b.nameservers
        a.nameservers = ['127.0.0.2']
        assert a._channel is not b._channel
        assert b.nameservers == original
        custom = aiodns.DNSResolver(timeout=1.0)
        assert custom._channel is not b._channel
        c = aiodns.DNSResolver()
        assert c._channel is b._channel
        await a.close()
        await b.close()
        await c.close()
        await custom.close()

    asyncio.run(run())


def test_event_loop_separation() -> None:
    loop1 = asyncio.new_event_loop()
    loop2 = asyncio.new_event_loop()
    try:
        a = aiodns.DNSResolver(loop=loop1)
        b = aiodns.DNSResolver(loop=loop2)
        assert a._channel is not b._channel
        loop1.run_until_complete(a.close())
        loop2.run_until_complete(b.close())
    finally:
        loop1.close()
        loop2.close()


def test_pool_fallback_to_private_socket_channels() -> None:
    real_channel = pycares.Channel
    created: list[pycares.Channel] = []

    def patched_channel(*args: Any, **kwargs: Any) -> pycares.Channel:
        if 'sock_state_cb' not in kwargs:
            raise pycares.AresError('event threads unavailable')
        channel = real_channel(*args, **kwargs)
        created.append(channel)
        return channel

    async def run() -> None:
        a = aiodns.DNSResolver()
        b = aiodns.DNSResolver()
        assert a._channel is not b._channel
        assert not a._event_thread
        assert not b._event_thread
        await a.close()
        await b.close()

    with patch('aiodns.pycares.Channel', patched_channel):
        asyncio.run(run())
    assert len(created) == 2


def test_cancel_is_local_to_the_resolver() -> None:
    """Shared channel cancellation must not affect other clients."""

    class FakeChannel:
        def __init__(self, **kwargs: Any) -> None:
            self.callbacks: list[Any] = []
            self.servers = ['127.0.0.1:53']

        def query(
            self, host: str, qtype: int, *, callback: Any, **kwargs: Any
        ) -> None:
            self.callbacks.append(callback)

        def cancel(self) -> None:
            raise AssertionError('channel-wide cancellation is unsafe')

        def close(self) -> None:
            pass

    async def run() -> None:
        a = aiodns.DNSResolver()
        b = aiodns.DNSResolver()
        a_future = a.query_dns('a.local', 'A')
        b_future = b.query_dns('b.local', 'A')
        a.cancel()
        with pytest.raises(aiodns.error.DNSError):
            await a_future
        assert not b_future.done()
        b._channel.callbacks[1]('ok', None)
        assert await b_future == 'ok'
        await a.close()
        await b.close()

    with patch('aiodns.pycares.Channel', FakeChannel):
        asyncio.run(run())


def test_nameserver_copy_on_write_preserves_running_query() -> None:
    """Changing one client's nameservers must not kill in-flight DNS."""

    class FakeChannel:
        def __init__(self, **kwargs: Any) -> None:
            self.callbacks: list[Any] = []
            self.servers = ['127.0.0.1:53']
            self.closed = False

        def query(
            self, host: str, qtype: int, *, callback: Any, **kwargs: Any
        ) -> None:
            self.callbacks.append(callback)

        def cancel(self) -> None:
            pass

        def close(self) -> None:
            self.closed = True

    async def run() -> None:
        a = aiodns.DNSResolver()
        b = aiodns.DNSResolver()
        old_channel = a._channel
        future = a.query_dns('old-config.local', 'A')
        a.nameservers = ['127.0.0.2']
        assert a._channel is not old_channel
        assert b._channel is old_channel
        assert b.nameservers == ['127.0.0.1']
        await b.close()
        await asyncio.sleep(0.03)
        assert not old_channel.closed
        old_channel.callbacks[0]('resolved', None)
        assert await future == 'resolved'
        await a.close()
        await asyncio.sleep(0.03)
        assert old_channel.closed

    with patch('aiodns.pycares.Channel', FakeChannel):
        with patch('aiodns._DEFAULT_POOL_IDLE_SECONDS', 0.01):
            asyncio.run(run())
