from prover.trace_builders import TraceBuilder, Trace, RegisterView, next_power_of_two, get_modular_inverse
from prover.trace_builders.rsa2048 import RSA2048TraceBuilder
from prover.trace_builders.sha256 import Sha256TraceBuilder
from prover.trace_builders.sha256.constants import TRACE_WIDTH as SHA_TRACE_WIDTH
from prover.trace_builders.sha256.constants import ROUND_CONSTANTS
from prover.trace_builders.utils import FIELD_MODULUS

from ast import literal_eval

from . import constants
from . import utils

from functools import partial
from collections.abc import Callable

# TODO: Combine SHA-256 with RSA2048 to get message authentication