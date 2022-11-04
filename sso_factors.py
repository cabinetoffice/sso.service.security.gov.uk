import numbers
import json

from enum import Enum, EnumMeta
from math import ceil
from functools import total_ordering


def _get_int(obj, check_class: bool = True) -> int:
    try:
        if obj.__class__ == str:
            potential_num = obj.strip().split(".")[0]
            if potential_num in _factorQuality:
                return _factorQuality[potential_num]
            if potential_num.isnumeric():
                return int(potential_num)

        if check_class and obj in FactorQuality:
            return FactorQuality.get(obj).value

        if isinstance(obj, numbers.Real):
            return int(obj)
    except:
        pass
    return None


class FactorQualityMeta(EnumMeta):
    def __contains__(self, other):
        try:
            self(other)
        except ValueError:
            if other.__class__ == str:
                if other.lower() in self.list():
                    return True
            return False
        else:
            return True


_factorQuality = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "veryhigh": 4,
    "highest": 5,
}


@total_ordering
class FactorQuality(str, Enum, metaclass=FactorQualityMeta):
    none: str = "none"
    low: str = "low"
    medium: str = "medium"
    high: str = "high"
    veryhigh: str = "veryhigh"
    highest: str = "highest"

    def __eq__(self, other):
        i = _get_int(other)
        if i or i == 0:
            return _factorQuality[self.value] == i
        return NotImplemented

    def __lt__(self, other):
        i = _get_int(other)
        if i is None:
            return False
        if i or i == 0:
            return _factorQuality[self.value] < i
        return NotImplemented

    def __gt__(self, other):
        i = _get_int(other)
        if i is None:
            return False
        if i or i == 0:
            return _factorQuality[self.value] > i
        return NotImplemented

    def __le__(self, other):
        i = _get_int(other)
        if i is None:
            return False
        if i or i == 0:
            return _factorQuality[self.value] <= i
        return NotImplemented

    def __ge__(self, other):
        i = _get_int(other)
        if i is None:
            return False
        if i or i == 0:
            return _factorQuality[self.value] >= i
        return NotImplemented

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"<FactorQuality('{self.name}')>"

    def __json__(self):
        return str(self)

    @classmethod
    def list(cls):
        return [x.name for x in cls]

    @classmethod
    def get(cls, value=None):
        try:
            if value:
                valstr = str(value).lower()
                for member in cls:
                    if member.name == valstr:
                        return member
                if type(value) == int or _get_int(value, check_class=False) is not None:
                    vint = _get_int(value, check_class=False)
                    for member in cls:
                        if _factorQuality[member.value] == vint:
                            return member
        except Exception:
            pass
        return cls.none


def calculate_auth_quality(pf_quality: str = None, mfa_quality: str = None) -> str:
    pfq = FactorQuality.get(pf_quality)
    mfq = FactorQuality.get(mfa_quality)

    # if no multifactor multifactor, then use the primary factor value
    if pfq == "none" and mfq == "none":
        return pfq

    if pfq >= "high" and mfq >= "veryhigh":
        return FactorQuality.highest

    if pfq >= "high" and mfq >= "high":
        return FactorQuality.veryhigh

    if pfq >= "medium" and mfq >= "highest":
        return FactorQuality.veryhigh

    if pfq >= "high":
        return FactorQuality.high

    if pfq >= "medium" and mfq >= "high":
        return FactorQuality.high

    if pfq >= "medium":
        return FactorQuality.medium

    # if no multifactor multifactor, then use the primary factor value
    if pfq != "none" and mfq == "none":
        return pfq

    return FactorQuality.low
