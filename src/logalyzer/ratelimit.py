import logging
from dataclasses import dataclass
from datetime import datetime

# --------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# rate limiter / token bucket


class TokensExhausted(Exception):
    pass


class TokenBucket:
    def __init__(self, capacity: float, refill_rate: float, last_refill: float = 0):
        #: total allowed tokens
        self.capacity = capacity
        #: number of tokens left in current window
        self.tokens = capacity
        #: how many tokens we refill (in tokens per second)
        self.refill_rate = refill_rate
        #: timestamp (UNIX) from last refill
        self.last_refill: float = 0

    @staticmethod
    def when(at: float | datetime | None = None):
        if at is None:
            at = datetime.now()
        if isinstance(at, datetime):
            at = at.timestamp()
        return at

    def refill(self, at: float | datetime | None = None):
        at = self.when(at)

        # compute elapsed time between last refill and current (at) time
        elapsed = at - self.last_refill
        # how many new tokens to fill in bucket
        new_tokens = elapsed * self.refill_rate

        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_refill = at

    def consume(
        self,
        tokens: float = 1,
        at: float | datetime | None = None,
        raise_exc: bool = True,
    ):
        at = self.when(at)
        self.refill(at=at)

        tokens_left = self.tokens - tokens
        self.tokens = max(0, tokens_left)  # can we overdraw?

        if tokens_left < 0:
            if raise_exc:
                raise TokensExhausted()
            return False
        return True

    def can_consume(self, tokens: float = 1, at: float | datetime | None = None):
        self.refill(at=at)

        tokens_left = self.tokens - tokens

        return tokens_left >= 0

    def __repr__(self):
        return (
            self.__class__.__qualname__
            + f"(capacity={self.capacity!r}, tokens={self.tokens!r}, refill_rate={self.refill_rate!r}, last_refill={self.last_refill!r})"
        )


@dataclass
class ExceedStreakInformation:
    # UNIX timestamps (convertable to `datetime`)
    start: float
    end: float | None = None
    start_exceed: float | None = None
    end_exceed: float | None = None
    count: int = 0
    count_exceed: int = 0

    @property
    def has_exceeded(self):
        return self.count_exceed > 0

    def update(self, when: float, exceeded: bool):
        # update last known end of any information
        self.end = when
        # increment all
        self.count += 1

        if exceeded:
            # if we do not yet have a start, set the start of exceeding
            if self.start_exceed is None:
                self.start_exceed = when
            # last known timestamp of exceeding
            self.end_exceed = when
            # increment
            self.count_exceed += 1

    def __str__(self):
        _ts = datetime.fromtimestamp
        parts = [
            f"{_ts(self.start)} -- {_ts(self.end)}",
            f" [{self.count}x]",
        ]
        if self.start_exceed is not None:
            parts.extend(
                [
                    f", exceeded: {_ts(self.start_exceed)} -- {_ts(self.end_exceed)}",
                    f" [{self.count_exceed}x]",
                ]
            )
        return "".join(parts)


class TokenBucketWithStreakInfo(TokenBucket):
    def __init__(self, capacity: float, refill_rate: float, last_refill: float = 0):
        super().__init__(capacity, refill_rate, last_refill)
        self.streak: ExceedStreakInformation | None = None

    def refill(self, at: float | datetime | None = None):
        # refill bucket
        super().refill(at)

        # check if bucket if full
        bucket_full = self.tokens == self.capacity
        # bucket is full, previous streak can be discarded, start (possible) new streak
        if bucket_full:
            # if self.streak is not None and self.streak.start_exceed is not None:
            #     LOGGER.debug(f"Streak: {self.streak}")
            at = self.when(at)
            self.streak = ExceedStreakInformation(start=at)

    def consume(
        self,
        tokens: float = 1,
        at: float | datetime | None = None,
        raise_exc: bool = True,
    ):
        at = self.when(at)
        # True if tokens left, False if tokens exhausted/request limit exceeded
        tokens_left = True
        try:
            tokens_left = super().consume(tokens, at=at, raise_exc=raise_exc)
        except TokensExhausted as ex:
            tokens_left = False
            raise ex
        finally:
            # if first request
            if self.streak is None:
                self.streak = ExceedStreakInformation(start=at)

            # update streak "end" times
            self.streak.update(at, exceeded=not tokens_left)
            # NOTE: excessive requests may reduce for a time and later increase again
            # will all be in the same streak if token bucket has no change to fully recover

        return tokens_left

    def __repr__(self):
        return (
            self.__class__.__qualname__
            + f"(capacity={self.capacity!r}, tokens={self.tokens!r}, refill_rate={self.refill_rate!r}, last_refill={self.last_refill!r}, streak={self.streak!r})"
        )


# --------------------------------------------------------------------------

