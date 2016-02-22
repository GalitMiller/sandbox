# -*- coding: utf-8 -*-

from functools import partial

from ..constants import DIRECTIONS

from .objects import RuleOptionList, RuleReferenceInfoList


class RuleParsedDataPreprocessor(object):

    def __call__(self, data):
        self.data = data
        self._process_direction()
        self._process_options()
        return self.data

    def _process_direction(self):
        direction = self.data.pop('direction')
        self.data['is_bidirectional'] = (direction == DIRECTIONS.BIDIRECTIONAL)

    def _process_options(self):
        options = RuleOptionList.from_string(self.data.pop('options'))

        for option in options[:]:
            for extractor in self._attribute_extractors:
                if extractor(self, option):
                    options.remove(option)

        flow, content, references = self._group_options(options)

        self.data['flow_control'] = flow.to_string()
        self.data['content_control'] = content.to_string()
        self.data['reference_infos'] = self._process_references(references)

    def _extract_attribute(self, option, src_key,
                           dst_key=None, converter=None):
        if option.key == src_key:
            dst_key = dst_key or src_key
            value = converter(option.value) if converter else option.value
            self.data[dst_key] = value
            return True

    _attribute_extractors = [
        partial(
            _extract_attribute,
            src_key='msg',
            dst_key='message',
            converter=lambda x: x.strip('"'),
        ),
        partial(
            _extract_attribute,
            src_key='priority',
            converter=int,
        ),
        partial(
            _extract_attribute,
            src_key='classtype',
            dst_key='class_type',
        ),
        partial(
            _extract_attribute,
            src_key='sid',
            converter=int,
        ),
        partial(
            _extract_attribute,
            src_key='gid',
            converter=int,
        ),
        partial(
            _extract_attribute,
            src_key='rev',
            dst_key='revision',
            converter=int,
        ),
    ]

    @staticmethod
    def _group_options(options):
        cls = RuleOptionList
        flow, content, references = cls(), cls(), cls()

        for option in options:
            container = (references if option.key == 'reference'
                         else flow if (option.key.startswith('flow')
                                       or option.key == 'stream_size')
                         else content)
            container.append(option)

        return flow, content, references

    @staticmethod
    def _process_references(reference_options):
        values = reference_options.itervalues()
        return RuleReferenceInfoList.from_strings(values)


preprocess_rule_parsed_data = RuleParsedDataPreprocessor()
