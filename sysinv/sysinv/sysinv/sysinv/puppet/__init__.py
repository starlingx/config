#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import yaml


class quoted_str(str):
    pass


# force strings to be single-quoted to avoid interpretation as numeric values
def quoted_presenter(dumper, data):
    return dumper.represent_scalar(u'tag:yaml.org,2002:str', data, style="'")


yaml.add_representer(quoted_str, quoted_presenter)
