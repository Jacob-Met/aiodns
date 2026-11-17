from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import socket
import sys
import warnings
import weakref
from collections.abc import Callable, Iterable, Iterator, Sequence
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal, TypeVar, overload

import pycares

from . import error
from .compat import (
    AresHostResult,
    AresQueryAAAAResult,
    AresQueryAResult,
    AresQueryCAAResult,
    AresQueryCNAMEResult,
    AresQueryMXResult,
    AresQueryNAPTRResult,
    AresQueryNSResult,
    AresQueryPTRResult,
    AresQuerySOAResult,
    AresQuerySRVResult,
    AresQueryTXTResult,
    QueryResult,
    convert_result,
)

__version__ = '4.0.4'

__all__ = (
    'DNSResolver',
    'error',
)

_T = TypeVar('_T')

WINDOWS_SELECTOR_ERR_MSG = (
    'ProactorEventLoop will not work with aiodns on Windows without event '
    'threads. See more: https://github.com/aio-libs/aiodns#note-for-windows-users'
)

_LOGGER = logging.getLogger(__name__)

query_type_map = {
    'A': pycares.QUERY_TYPE_A,
    'AAAA': pycares.QUERY_TYPE_AAAA,
    'ANY': pycares.QUERY_TYPE_ANY,
    'CAA': pycares.QUERY_TYPE_CAA,
    'CNAME': pycares.QUERY_TYPE_CNAME,
    'MX': pycares.QUERY_TYPE_MX,
    'NAPTR': pycares.QUERY_TYPE_NAPTR,
    'NS': pycares.QUERY_TYPE_NS,
    'PTR': pycares.QUERY_TYPE_PTR,
    'SOA': pycares.QUERY_TYPE_SOA,
    'SRV': pycares.QUERY_TYPE_SRV,
    'TXT': pycares.QUERY_TYPE_TXT,
}

query_class_map = {
    'IN': pycares.QUERY_CLASS_IN,
    'CHAOS': pycares.QUERY_CLASS_CHAOS,
    'HS': pycares.QUERY_CLASS_HS,
    'NONE': pycares.QUERY_CLASS_NONE,
    'ANY': pycares.QUERY_CLASS_ANY,
}


# Keep one default c-ares event-thread channel per event loop through short
# resolver lifetimes. c-ares creates inotify instances more quickly than its
# destructor thread can release them under heavy ClientSession churn.
_DEFAULT_POOL_IDLE_SECONDS = 0.5


class _DefaultChannelPool:
    def __init__(
        self, loop: asyncio.AbstractEventLoop, channel: pycares.Channel
    ) -> None:
        self.channel = channel
        self.references = 0
        self._loop_ref = weakref.ref(loop)
        self._idle_ref: weakref.ReferenceType[asyncio.TimerHandle] | None = (
            None
        )
        self._idle_deadline: float | None = None
        self._idle_generation = 0
        self._closed = False
        # The pool must not keep an event loop alive after it is closed.
        self._finalizer = weakref.finalize(loop, self._close_channel)

    def acquire(self) -> None:
        # Keep one timer armed through resolver churn instead of creating and
        # cancelling a TimerHandle and weakref finalizer for every client.
        self.references += 1
        self._idle_deadline = None

    def release(self) -> None:
        self.references -= 1
        if self.references != 0:
            return
        loop = self._loop_ref()
        if loop is None or loop.is_closed():
            self.expire()
            return
        self._idle_deadline = loop.time() + _DEFAULT_POOL_IDLE_SECONDS
        idle = self._idle_ref() if self._idle_ref is not None else None
        if idle is None:
            self._arm_idle_timer(_DEFAULT_POOL_IDLE_SECONDS, loop)

    def _arm_idle_timer(
        self, delay: float, loop: asyncio.AbstractEventLoop
    ) -> None:
        self._idle_generation += 1
        generation = self._idle_generation
        idle = loop.call_later(delay, self._idle_timeout, generation)
        self._idle_ref = weakref.ref(idle)
        # EventLoop.close() discards pending timer handles without invoking
        # callbacks. Its handle finalizer retires the otherwise stranded
        # c-ares channel even when a caller still holds the closed loop.
        weakref.finalize(idle, self._expire_discarded_timer, generation)

    def _idle_timeout(self, generation: int) -> None:
        if generation != self._idle_generation:
            return
        self._idle_ref = None
        # Invalidate the timer finalizer: a successful callback is not a
        # discarded handle, and another idle deadline may now be pending.
        self._idle_generation += 1
        if self.references or self._idle_deadline is None:
            return
        loop = self._loop_ref()
        if loop is None or loop.is_closed():
            self.expire()
            return
        remaining = self._idle_deadline - loop.time()
        if remaining > 0:
            self._arm_idle_timer(remaining, loop)
        else:
            self.expire()

    def _expire_discarded_timer(self, generation: int) -> None:
        if self._idle_generation == generation:
            self.expire()

    def expire(self) -> None:
        if self.references:
            return
        loop = self._loop_ref()
        if loop is not None and _DEFAULT_POOLS.get(loop) is self:
            del _DEFAULT_POOLS[loop]
        self._close_channel()

    def _close_channel(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._finalizer.detach()
        self.channel.close()


_DEFAULT_POOLS: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, _DefaultChannelPool
] = weakref.WeakKeyDictionary()


class DNSResolver:
    def __init__(
        self,
        nameservers: Sequence[str] | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
        **kwargs: Any,
    ) -> None:  # TODO(PY311): Use Unpack for kwargs.
        self._closed = True
        self.loop = loop or asyncio.get_event_loop()
        if TYPE_CHECKING:
            assert self.loop is not None
        # Only the unconfigured resolver is shareable. Explicit timeout,
        # nameserver, and pycares options must retain independent channels.
        use_default_pool = nameservers is None and not kwargs
        kwargs.pop('sock_state_cb', None)
        timeout = kwargs.pop('timeout', None)
        self._timeout = timeout
        self._pool: _DefaultChannelPool | None = None
        self._pending_futures: set[asyncio.Future[Any]] = set()
        pool = _DEFAULT_POOLS.get(self.loop) if use_default_pool else None
        if pool is not None:
            self._event_thread, self._channel = True, pool.channel
            self._pool = pool
            pool.acquire()
        else:
            self._event_thread, self._channel = self._make_channel(**kwargs)
            # Only event-thread channels are pooled; socket-state fallback
            # channels have callbacks and fd watchers bound to their owner.
            if use_default_pool and self._event_thread:
                pool = _DefaultChannelPool(self.loop, self._channel)
                _DEFAULT_POOLS[self.loop] = pool
                self._pool = pool
                pool.acquire()
        if nameservers:
            self.nameservers = nameservers
        self._read_fds: set[int] = set()
        self._write_fds: set[int] = set()
        self._timer: asyncio.TimerHandle | None = None
        self._closed = False

    def _make_channel(self, **kwargs: Any) -> tuple[bool, pycares.Channel]:
        # pycares 5+ uses event_thread by default when sock_state_cb
        # is not provided
        try:
            return True, pycares.Channel(timeout=self._timeout, **kwargs)
        except pycares.AresError as e:
            if sys.platform == 'linux':
                _LOGGER.warning(
                    'Failed to create DNS resolver channel with automatic '
                    'monitoring of resolver configuration changes. This '
                    'usually means the system ran out of inotify watches. '
                    'Falling back to socket state callback. Consider '
                    'increasing the system inotify watch limit: %s',
                    e,
                )
            else:
                _LOGGER.warning(
                    'Failed to create DNS resolver channel with automatic '
                    'monitoring of resolver configuration changes. '
                    'Falling back to socket state callback: %s',
                    e,
                )
        # Fall back to sock_state_cb
        # We cannot use a ProactorEventLoop because it does not
        # provide an add_reader or add_writer function to utilize.
        if sys.platform == 'win32':
            if hasattr(asyncio, 'ProactorEventLoop'):
                if isinstance(self.loop, asyncio.ProactorEventLoop):
                    raise RuntimeError(WINDOWS_SELECTOR_ERR_MSG)
        # Use weak reference for deterministic cleanup. Without it there's a
        # reference cycle (DNSResolver -> _channel -> callback -> DNSResolver).
        # Python 3.4+ can handle cycles with __del__, but weak ref ensures
        # cleanup happens immediately when last reference is dropped.
        weak_self = weakref.ref(self)

        def sock_state_cb_wrapper(
            fd: int, readable: bool, writable: bool
        ) -> None:
            this = weak_self()
            if this is not None:
                this._sock_state_cb(fd, readable, writable)

        return False, pycares.Channel(
            sock_state_cb=sock_state_cb_wrapper,
            timeout=self._timeout,
            **kwargs,
        )

    @property
    def nameservers(self) -> Sequence[str]:
        # pycares 5.x returns servers with port (e.g., '8.8.8.8:53')
        # Strip port for backward compatibility with pycares 4.x
        return [s.rsplit(':', 1)[0] for s in self._channel.servers]

    @nameservers.setter
    def nameservers(self, value: Iterable[str | bytes]) -> None:
        if self._pool is not None:
            # Copy on write: configure a new channel before detaching from
            # the shared pool. Failed updates must preserve the old channel.
            event_thread, channel = self._make_channel()
            try:
                channel.servers = value
            except BaseException:
                channel.close()
                raise
            old_pool = self._pool
            self._event_thread, self._channel = event_thread, channel
            self._pool = None
            pending = tuple(f for f in self._pending_futures if not f.done())
            if pending:
                # Preserve the old channel until already-issued queries finish.
                remaining = len(pending)

                def release_after_query(future: asyncio.Future[Any]) -> None:
                    nonlocal remaining
                    remaining -= 1
                    if remaining == 0:
                        old_pool.release()

                for future in pending:
                    future.add_done_callback(release_after_query)
            else:
                old_pool.release()
            return
        self._channel.servers = value

    def _track_future(self, future: asyncio.Future[_T]) -> asyncio.Future[_T]:
        if self._closed:
            raise RuntimeError('DNS resolver is closed')
        if self._pool is not None:
            self._pending_futures.add(future)
            future.add_done_callback(self._pending_futures.discard)
        return future

    def _cancel_pending_futures(self) -> None:
        pending = tuple(self._pending_futures)
        self._pending_futures.clear()
        for future in pending:
            if not future.done():
                future.set_exception(
                    error.DNSError(
                        error.ARES_ECANCELLED,
                        pycares.errno.strerror(error.ARES_ECANCELLED),
                    )
                )

    def _safe_call_soon_threadsafe(
        self, callback: Callable[..., None], *args: Any
    ) -> None:
        # c-ares can deliver a final callback after a pooled resolver
        # closed and the event loop was torn down. Never raise from its
        # worker thread when the result can no longer be consumed.
        loop = self.loop
        if loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(callback, *args)
        except RuntimeError:
            # Closing can race with scheduling on another thread. Preserve
            # unrelated RuntimeErrors instead of hiding actual callback bugs.
            if not loop.is_closed():
                raise

    def _callback(
        self, fut: asyncio.Future[_T], result: _T, errorno: int | None
    ) -> None:
        # The future can already be done if pycares raised synchronously
        # and _capture_ares_error set the exception before c-ares delivered
        # the same error through this callback.
        if fut.done():
            return
        if errorno is not None:
            fut.set_exception(
                error.DNSError(errorno, pycares.errno.strerror(errorno))
            )
        else:
            fut.set_result(result)

    def _get_future_callback(
        self,
    ) -> tuple[asyncio.Future[_T], Callable[[_T, int | None], None]]:
        """Return a future and a callback to set the result of the future."""
        cb: Callable[[_T, int | None], None]
        future: asyncio.Future[_T] = self._track_future(
            self.loop.create_future()
        )
        if self._event_thread:
            cb = functools.partial(
                self._safe_call_soon_threadsafe,
                self._callback,
                future,
            )
        else:
            cb = functools.partial(self._callback, future)
        return future, cb

    def _query_callback(
        self,
        fut: asyncio.Future[QueryResult],
        qtype: int,
        result: pycares.DNSResult,
        errorno: int | None,
    ) -> None:
        """Callback for query that converts results to compatible format."""
        # See _callback for why we guard on done() rather than cancelled().
        if fut.done():
            return
        if errorno is not None:
            fut.set_exception(
                error.DNSError(errorno, pycares.errno.strerror(errorno))
            )
            return
        try:
            converted = convert_result(result, qtype)
        except error.DNSError as exc:
            fut.set_exception(exc)
        else:
            fut.set_result(converted)

    def _get_query_future_callback(
        self, qtype: int
    ) -> tuple[asyncio.Future[QueryResult], Callable[..., None]]:
        """Return a future and callback for query with result conversion."""
        future: asyncio.Future[QueryResult] = self._track_future(
            self.loop.create_future()
        )
        cb: Callable[..., None]
        if self._event_thread:
            cb = functools.partial(
                self._safe_call_soon_threadsafe,
                self._query_callback,
                future,
                qtype,
            )
        else:
            cb = functools.partial(self._query_callback, future, qtype)
        return future, cb

    @contextlib.contextmanager
    def _capture_ares_error(self, fut: asyncio.Future[_T]) -> Iterator[None]:
        # When pycares raises synchronously (e.g. ARES_EBADNAME for a
        # malformed hostname), c-ares may also invoke the callback first,
        # leaving the future already done. Route the error through the
        # future so callers can rely on `await` to raise.
        try:
            yield
        except pycares.AresError as exc:
            if fut.done():
                return
            # pycares always raises (errno, message), but be defensive:
            # an args-less AresError should still resolve the future to
            # avoid an indefinite hang on `await`.
            errno = exc.args[0] if exc.args else error.ARES_EFORMERR
            fut.set_exception(
                error.DNSError(errno, pycares.errno.strerror(errno))
            )

    @overload
    def query(
        self, host: str, qtype: Literal['A'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryAResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['AAAA'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryAAAAResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['CAA'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryCAAResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['CNAME'], qclass: str | None = ...
    ) -> asyncio.Future[AresQueryCNAMEResult]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['MX'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryMXResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['NAPTR'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryNAPTRResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['NS'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryNSResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['PTR'], qclass: str | None = ...
    ) -> asyncio.Future[AresQueryPTRResult]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['SOA'], qclass: str | None = ...
    ) -> asyncio.Future[AresQuerySOAResult]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['SRV'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQuerySRVResult]]: ...
    @overload
    def query(
        self, host: str, qtype: Literal['TXT'], qclass: str | None = ...
    ) -> asyncio.Future[list[AresQueryTXTResult]]: ...

    def query(
        self, host: str, qtype: str, qclass: str | None = None
    ) -> asyncio.Future[list[Any]] | asyncio.Future[Any]:
        """Query DNS records (deprecated, use query_dns instead)."""
        warnings.warn(
            'query() is deprecated, use query_dns() instead',
            DeprecationWarning,
            stacklevel=2,
        )
        try:
            qtype_int = query_type_map[qtype]
        except KeyError as e:
            raise ValueError(f'invalid query type: {qtype}') from e
        qclass_int: int | None = None
        if qclass is not None:
            try:
                qclass_int = query_class_map[qclass]
            except KeyError as e:
                raise ValueError(f'invalid query class: {qclass}') from e

        fut, cb = self._get_query_future_callback(qtype_int)
        with self._capture_ares_error(fut):
            if qclass_int is not None:
                self._channel.query(
                    host, qtype_int, query_class=qclass_int, callback=cb
                )
            else:
                self._channel.query(host, qtype_int, callback=cb)
        return fut

    def query_dns(
        self, host: str, qtype: str, qclass: str | None = None
    ) -> asyncio.Future[pycares.DNSResult]:
        """Query DNS records, returning native pycares 5.x DNSResult."""
        try:
            qtype_int = query_type_map[qtype]
        except KeyError as e:
            raise ValueError(f'invalid query type: {qtype}') from e
        qclass_int: int | None = None
        if qclass is not None:
            try:
                qclass_int = query_class_map[qclass]
            except KeyError as e:
                raise ValueError(f'invalid query class: {qclass}') from e

        fut: asyncio.Future[pycares.DNSResult]
        fut, cb = self._get_future_callback()
        with self._capture_ares_error(fut):
            if qclass_int is not None:
                self._channel.query(
                    host, qtype_int, query_class=qclass_int, callback=cb
                )
            else:
                self._channel.query(host, qtype_int, callback=cb)
        return fut

    def _gethostbyname_callback(
        self,
        fut: asyncio.Future[AresHostResult],
        host: str,
        result: pycares.AddrInfoResult | None,
        errorno: int | None,
    ) -> None:
        """Callback for gethostbyname that converts AddrInfoResult."""
        # See _callback for why we guard on done() rather than cancelled().
        if fut.done():
            return
        if errorno is not None:
            fut.set_exception(
                error.DNSError(errorno, pycares.errno.strerror(errorno))
            )
        else:
            assert result is not None  # noqa: S101
            # node.addr is (address_bytes, port) - extract and decode
            addresses = [node.addr[0].decode() for node in result.nodes]
            # Get canonical name from cnames if available
            name = result.cnames[0].name if result.cnames else host
            fut.set_result(
                AresHostResult(name=name, aliases=[], addresses=addresses)
            )

    def gethostbyname(
        self, host: str, family: socket.AddressFamily
    ) -> asyncio.Future[AresHostResult]:
        """
        Resolve hostname to addresses.

        Deprecated: Use getaddrinfo() instead. This is implemented using
        getaddrinfo as pycares 5.x removed the gethostbyname method.
        """
        warnings.warn(
            'gethostbyname() is deprecated, use getaddrinfo() instead',
            DeprecationWarning,
            stacklevel=2,
        )
        fut: asyncio.Future[AresHostResult] = self._track_future(
            self.loop.create_future()
        )
        cb: Callable[..., None]
        if self._event_thread:
            cb = functools.partial(
                self._safe_call_soon_threadsafe,
                self._gethostbyname_callback,
                fut,
                host,
            )
        else:
            cb = functools.partial(self._gethostbyname_callback, fut, host)
        with self._capture_ares_error(fut):
            self._channel.getaddrinfo(host, None, family=family, callback=cb)
        return fut

    def getaddrinfo(
        self,
        host: str,
        family: socket.AddressFamily = socket.AF_UNSPEC,
        port: int | None = None,
        proto: int = 0,
        type: int = 0,
        flags: int = 0,
    ) -> asyncio.Future[pycares.AddrInfoResult]:
        fut: asyncio.Future[pycares.AddrInfoResult]
        fut, cb = self._get_future_callback()
        with self._capture_ares_error(fut):
            self._channel.getaddrinfo(
                host,
                port,
                family=family,
                type=type,
                proto=proto,
                flags=flags,
                callback=cb,
            )
        return fut

    def getnameinfo(
        self,
        sockaddr: tuple[str, int] | tuple[str, int, int, int],
        flags: int = 0,
    ) -> asyncio.Future[pycares.NameInfoResult]:
        fut: asyncio.Future[pycares.NameInfoResult]
        fut, cb = self._get_future_callback()
        with self._capture_ares_error(fut):
            self._channel.getnameinfo(sockaddr, flags, callback=cb)
        return fut

    def gethostbyaddr(self, name: str) -> asyncio.Future[pycares.HostResult]:
        fut: asyncio.Future[pycares.HostResult]
        fut, cb = self._get_future_callback()
        with self._capture_ares_error(fut):
            self._channel.gethostbyaddr(name, callback=cb)
        return fut

    def cancel(self) -> None:
        if self._pool is None:
            self._channel.cancel()
        # A shared channel's cancel() would also cancel unrelated clients.
        self._cancel_pending_futures()

    def _sock_state_cb(self, fd: int, readable: bool, writable: bool) -> None:
        if readable or writable:
            if readable:
                self.loop.add_reader(
                    fd, self._channel.process_fd, fd, pycares.ARES_SOCKET_BAD
                )
                self._read_fds.add(fd)
            if writable:
                self.loop.add_writer(
                    fd, self._channel.process_fd, pycares.ARES_SOCKET_BAD, fd
                )
                self._write_fds.add(fd)
            if self._timer is None:
                self._start_timer()
        else:
            # socket is now closed
            if fd in self._read_fds:
                self._read_fds.discard(fd)
                self.loop.remove_reader(fd)

            if fd in self._write_fds:
                self._write_fds.discard(fd)
                self.loop.remove_writer(fd)

            if (
                not self._read_fds
                and not self._write_fds
                and self._timer is not None
            ):
                self._timer.cancel()
                self._timer = None

    def _timer_cb(self) -> None:
        if self._read_fds or self._write_fds:
            self._channel.process_fd(
                pycares.ARES_SOCKET_BAD, pycares.ARES_SOCKET_BAD
            )
            self._start_timer()
        else:
            self._timer = None

    def _start_timer(self) -> None:
        timeout = self._timeout
        if timeout is None or timeout < 0 or timeout > 1:
            timeout = 1
        elif timeout == 0:
            timeout = 0.1

        self._timer = self.loop.call_later(timeout, self._timer_cb)

    def _cleanup(self) -> None:
        """Cleanup timers and file descriptors when closing resolver."""
        if self._closed:
            return
        # Mark as closed first to prevent double cleanup
        self._closed = True
        self._cancel_pending_futures()
        if self._pool is not None:
            self._pool.release()
            self._pool = None
            return
        # Cancel timer if running
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

        # Remove all file descriptors
        for fd in self._read_fds:
            self.loop.remove_reader(fd)
        for fd in self._write_fds:
            self.loop.remove_writer(fd)

        self._read_fds.clear()
        self._write_fds.clear()
        self._channel.close()

    async def close(self) -> None:
        """
        Cleanly close the DNS resolver.

        This should be called to ensure all resources are properly released.
        After calling close(), the resolver should not be used again.
        """
        if not self._closed and self._pool is None:
            self._channel.cancel()
        self._cleanup()

    async def __aenter__(self) -> DNSResolver:
        """Enter the async context manager."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the async context manager."""
        await self.close()

    def __del__(self) -> None:
        """Handle cleanup when the resolver is garbage collected."""
        # Check if we have a channel to clean up
        # This can happen if an exception occurs during __init__ before
        # _channel is created (e.g., RuntimeError on Windows
        # without proper loop)
        if hasattr(self, '_channel'):
            self._cleanup()
