# -*- coding: utf-8 -*-
"""Define and extend configuration settings for your application.
"""

import os
from imcrypt.config.routes import routes  # noqa
from imcrypt.config.dependencies import dependencies  # noqa


debug = {
    'enabled': os.environ.get('DEV_ENV', False)
}
