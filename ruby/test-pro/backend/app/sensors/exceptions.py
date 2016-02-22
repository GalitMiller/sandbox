# -*- coding: utf-8 -*-


class TakeControlOverSensorError(Exception):
    pass


class SensorIsAlreadyUnderControl(TakeControlOverSensorError):
    pass
