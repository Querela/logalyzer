import logging
from dataclasses import InitVar, dataclass, field
from datetime import datetime
from typing import List

# --------------------------------------------------------------------------

LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# rate limiter / token bucket


class TokensExhausted(Exception):
    pass


class TokenBucket:
    def __init__(
        self,
        capacity: float,
        refill_rate: float,
        last_refill: float = 0.0,
        overdraw_recover: bool = True,
    ):
        #: total allowed tokens
        self.capacity = capacity
        #: number of tokens left in current window
        self.tokens = capacity
        #: how many tokens we refill (in tokens per second)
        self.refill_rate = refill_rate
        #: timestamp (UNIX) from last refill
        self.last_refill: float = last_refill
        #: whether consumption tracks excess (to negative capacity) which slows recovery for excess consumption
        self.overdraw_recover = overdraw_recover

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
        # NOTE: if timestamps out of order prevent negative durations!
        elapsed = max(0, elapsed)
        # how many new tokens to fill in bucket
        new_tokens = elapsed * self.refill_rate
        # LOGGER.debug(f"refill: {elapsed=} {self.refill_rate=} {new_tokens=} --> new tokens={min(self.capacity, self.tokens + new_tokens)!r}")

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
        # LOGGER.debug(f"consume: {self.tokens=} {tokens=} {tokens_left=} {max(0, tokens_left)=}")

        # can we overdraw?
        if self.overdraw_recover:
            # overdraw to negative capacity (so refill takes a bit longer to normalize)
            self.tokens = max(-self.capacity, tokens_left)

        else:
            self.tokens = max(0, tokens_left)

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


# --------------------------------------------------------------------------
# extended with streak information to track exhaustion/usage excess


@dataclass
class Streak:
    # UNIX timestamps (convertable to `datetime`)
    start: float
    end: float | None = None
    count: int = 0

    def update(self, when: float):
        # increment all
        self.count += 1
        # update last known end of any information
        self.end = when

    def __str__(self):
        _ts = datetime.fromtimestamp
        return f"{_ts(self.start)} -- {_ts(self.end)}  [{self.count}x]"


@dataclass
class ExceedStreaks:
    normal: Streak = field(init=False)
    exceeded: List[Streak] = field(init=False, default_factory=list)
    is_exceeding: bool = field(init=False, default=False)

    start_end: InitVar[float]

    def __post_init__(self, start_end: float):
        self.normal = Streak(start=start_end, end=start_end, count=1)

    @property
    def has_exceeded(self):
        return len(self.exceeded) > 0

    @property
    def start(self):
        return self.normal.start

    @property
    def end(self):
        return self.normal.end

    @property
    def count(self):
        return self.normal.count

    @property
    def exceed_start(self):
        if self.exceeded:
            return self.exceeded[0].start
        return None

    @property
    def exceed_end(self):
        if self.exceeded:
            return self.exceeded[-1].end
        return None

    @property
    def exceed_count(self):
        if self.exceeded:
            return sum(e.count for e in self.exceeded)
        return 0

    @property
    def exceed_streaks_count(self):
        return len(self.exceeded)

    def update(self, when: float, exceeded: bool):
        # update normal streak info
        self.normal.update(when)

        if exceeded:
            if self.is_exceeding:
                assert self.exceeded, "we should already have a exceeded streak item"
                self.exceeded[-1].update(when)

            else:
                # start exceeding new streak
                self.is_exceeding = True
                self.exceeded.append(Streak(start=when, end=when, count=1))

        else:
            # recover
            self.is_exceeding = False

    def __str__(self):
        _ts = datetime.fromtimestamp
        parts = [f"{self.normal!s}"]
        if self.exceeded:
            parts.extend(
                [
                    f", exceeded: {_ts(self.exceed_start)} -- {_ts(self.exceed_end)}",
                    f" [{self.exceed_count}x] {{{self.exceed_streaks_count}x}}",
                ]
            )
        return "".join(parts)


class TokenBucketWithStreakInfo(TokenBucket):
    def __init__(
        self,
        capacity: float,
        refill_rate: float,
        last_refill: float = 0.0,
        overdraw_recover: bool = True,
    ):
        super().__init__(
            capacity=capacity,
            refill_rate=refill_rate,
            last_refill=last_refill,
            overdraw_recover=overdraw_recover,
        )
        self.streak: ExceedStreaks | None = None

    def refill(self, at: float | datetime | None = None):
        # refill bucket
        super().refill(at)

        # check if bucket if full
        bucket_full = self.tokens == self.capacity
        # bucket is full, previous streak can be discarded, start (possible) new streak
        # LOGGER.debug(f"Streak: {self.streak} id={str(id(self.streak))[-4:]}")
        if bucket_full:
            # if self.streak is not None and self.streak.start_exceed is not None:
            # LOGGER.debug(f"Discard old Streak: {self.streak} id={str(id(self.streak))[-4:]}")
            at = self.when(at)
            self.streak = ExceedStreaks(at)
            # LOGGER.debug(f"Start new Streak: {self.streak} id={str(id(self.streak))[-4:]}")

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
                self.streak = ExceedStreaks(at)

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
