# -*- coding: utf-8 -*-

from schematics.models import Model
from schematics.types import IntType, StringType


from .constants import POLICY_DEPLOYMENT_ACTIONS


class PolicyInvokationInfo(Model):
    action = StringType(
        choices=POLICY_DEPLOYMENT_ACTIONS._asdict().values(),
        required=True,
    )
    policy_id = IntType(
        required=True,
    )

    @classmethod
    def from_dict(cls, d):
        info = cls.from_flat(d)
        info.validate()
        return info
